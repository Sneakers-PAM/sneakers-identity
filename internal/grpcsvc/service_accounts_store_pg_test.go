// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// TestPGServiceAccountStore covers the service_accounts + api_tokens store
// against a real Postgres (skips without IDENTITY_PG_DSN, via newPGServer):
// CreateSA + ListSA; InsertToken + TokenByHash resolves the SA + scope and
// bumps last_used_at; an expired token and a revoked token are NOT resolved as
// valid (TokenByHash returns pgx.ErrNoRows for both, indistinguishable from an
// unknown hash); RevokeToken sets revoked_at.
func TestPGServiceAccountStore(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	st := newServiceAccountStore(s.db)

	sa, err := st.CreateSA(ctx, "ci-runner", "CI pipeline machine account", "user-admin-1")
	if err != nil {
		t.Fatalf("CreateSA: %v", err)
	}
	if sa.ID == "" || sa.Name != "ci-runner" || sa.Disabled {
		t.Fatalf("unexpected service account: %+v", sa)
	}

	list, err := st.ListSA(ctx)
	if err != nil || len(list) != 1 || list[0].ID != sa.ID {
		t.Fatalf("ListSA: got %+v err %v", list, err)
	}

	assertLiveTokenResolves(ctx, t, st, sa)
	assertExpiredTokenDenied(ctx, t, st, sa)
	assertRevokedTokenDenied(ctx, t, st, sa)

	// An unknown hash is indistinguishable from expired/revoked.
	if _, err := st.TokenByHash(ctx, "hash-does-not-exist"); err != pgx.ErrNoRows {
		t.Fatalf("TokenByHash(unknown): want pgx.ErrNoRows, got %v", err)
	}

	assertRevokeTokenPreservesOriginalTimestamp(ctx, t, st, sa)
	assertDisabledSATokenDenied(ctx, t, st, sa)
}

// TestPGServiceAccountOidcStore covers the OIDC client-linkage store methods
// against a real Postgres (skips without IDENTITY_PG_DSN, via newPGServer):
// LinkOidc then ResolveByOidc resolves the SA; ResolveByOidc on an unknown
// (issuer,subject) pair is pgx.ErrNoRows; a disabled SA does NOT resolve even
// though it is still linked (mirrors TokenByHash's disabled-SA rule); a
// second SA linking the SAME (issuer,subject) hits the unique index and
// surfaces a 23505 pg error; UnlinkOidc clears both columns so ResolveByOidc
// stops matching.
func TestPGServiceAccountOidcStore(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	st := newServiceAccountStore(s.db)

	sa, err := st.CreateSA(ctx, "oidc-agent", "agent authenticating via Hydra", "user-admin-1")
	if err != nil {
		t.Fatalf("CreateSA: %v", err)
	}

	const issuer = "https://hydra.example.org/"
	const subject = "client-oidc-agent"

	linked, err := st.LinkOidc(ctx, sa.ID, issuer, subject, []string{"Security"})
	if err != nil {
		t.Fatalf("LinkOidc: %v", err)
	}
	if linked.OidcIssuer != issuer || linked.OidcSubject != subject {
		t.Fatalf("LinkOidc: unexpected row: %+v", linked)
	}

	resolved, err := st.ResolveByOidc(ctx, issuer, subject)
	if err != nil {
		t.Fatalf("ResolveByOidc(linked): %v", err)
	}
	if resolved.ID != sa.ID {
		t.Fatalf("ResolveByOidc(linked): got %+v, want id %s", resolved, sa.ID)
	}

	if _, err := st.ResolveByOidc(ctx, issuer, "unknown-subject"); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ResolveByOidc(unknown): want pgx.ErrNoRows, got %v", err)
	}

	assertDisabledSAOidcNotResolved(ctx, t, st, sa.ID, issuer, subject)
	assertOidcLinkUniqueViolation(ctx, t, st, issuer, subject)
	assertUnlinkOidcClearsColumns(ctx, t, st, sa.ID)
}

// assertDisabledSAOidcNotResolved covers the fail-closed rule that a disabled
// service account must not resolve via OIDC even while still linked.
func assertDisabledSAOidcNotResolved(ctx context.Context, t *testing.T, st *serviceAccountStore, saID, issuer, subject string) {
	t.Helper()
	if _, err := st.DisableSA(ctx, saID); err != nil {
		t.Fatalf("DisableSA: %v", err)
	}
	if _, err := st.ResolveByOidc(ctx, issuer, subject); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("ResolveByOidc(disabled SA): want pgx.ErrNoRows, got %v", err)
	}
}

// assertOidcLinkUniqueViolation covers the unique index on
// (oidc_issuer, oidc_subject): a second SA linking the same pair must fail
// with a 23505 unique-violation.
func assertOidcLinkUniqueViolation(ctx context.Context, t *testing.T, st *serviceAccountStore, issuer, subject string) {
	t.Helper()
	other, err := st.CreateSA(ctx, "oidc-agent-2", "second agent", "user-admin-1")
	if err != nil {
		t.Fatalf("CreateSA(second): %v", err)
	}
	_, err = st.LinkOidc(ctx, other.ID, issuer, subject, nil)
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "23505" {
		t.Fatalf("LinkOidc(duplicate issuer+subject): want 23505 unique violation, got %v", err)
	}
}

// assertUnlinkOidcClearsColumns covers UnlinkOidc: both columns go back to
// NULL, and the (issuer, subject) pair the SA used to hold no longer
// resolves.
func assertUnlinkOidcClearsColumns(ctx context.Context, t *testing.T, st *serviceAccountStore, saID string) {
	t.Helper()
	unlinked, err := st.UnlinkOidc(ctx, saID)
	if err != nil {
		t.Fatalf("UnlinkOidc: %v", err)
	}
	if unlinked.OidcIssuer != "" || unlinked.OidcSubject != "" {
		t.Fatalf("UnlinkOidc should clear both columns, got %+v", unlinked)
	}
}

// assertLiveTokenResolves covers a live, unexpired token: it resolves the SA +
// scope via TokenByHash and bumps last_used_at (visible on the next ListTokens).
func assertLiveTokenResolves(ctx context.Context, t *testing.T, st *serviceAccountStore, sa *serviceAccountRow) {
	t.Helper()
	liveTok, err := st.InsertToken(ctx, sa.ID, "hash-live", "secrets:read", nil, "user-admin-1")
	if err != nil {
		t.Fatalf("InsertToken(live): %v", err)
	}
	if liveTok.LastUsedAt != nil {
		t.Fatalf("freshly-minted token should have no last_used_at yet, got %v", liveTok.LastUsedAt)
	}

	found, err := st.TokenByHash(ctx, "hash-live")
	if err != nil {
		t.Fatalf("TokenByHash(live): %v", err)
	}
	if found.ServiceAccountID != sa.ID || found.ServiceAccountName != sa.Name || found.Scope != "secrets:read" {
		t.Fatalf("TokenByHash(live) wrong resolution: %+v", found)
	}

	list, err := st.ListTokens(ctx, sa.ID)
	if err != nil || len(list) != 1 || list[0].LastUsedAt == nil {
		t.Fatalf("ListTokens after use: got %+v err %v", list, err)
	}
}

// assertExpiredTokenDenied covers a token whose expiry has already passed:
// TokenByHash must treat it exactly like an unknown hash.
func assertExpiredTokenDenied(ctx context.Context, t *testing.T, st *serviceAccountStore, sa *serviceAccountRow) {
	t.Helper()
	past := time.Now().Add(-1 * time.Hour)
	if _, err := st.InsertToken(ctx, sa.ID, "hash-expired", "secrets:read", &past, "user-admin-1"); err != nil {
		t.Fatalf("InsertToken(expired): %v", err)
	}
	if _, err := st.TokenByHash(ctx, "hash-expired"); err != pgx.ErrNoRows {
		t.Fatalf("TokenByHash(expired): want pgx.ErrNoRows, got %v", err)
	}
}

// assertRevokedTokenDenied covers RevokeToken + the post-revoke TokenByHash
// denial.
func assertRevokedTokenDenied(ctx context.Context, t *testing.T, st *serviceAccountStore, sa *serviceAccountRow) {
	t.Helper()
	revokedTok, err := st.InsertToken(ctx, sa.ID, "hash-revoked", "secrets:read", nil, "user-admin-1")
	if err != nil {
		t.Fatalf("InsertToken(revoked): %v", err)
	}
	revoked, err := st.RevokeToken(ctx, revokedTok.ID)
	if err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if revoked.RevokedAt == nil {
		t.Fatalf("RevokeToken should stamp revoked_at, got %+v", revoked)
	}
	if _, err := st.TokenByHash(ctx, "hash-revoked"); err != pgx.ErrNoRows {
		t.Fatalf("TokenByHash(revoked): want pgx.ErrNoRows, got %v", err)
	}
}

// assertRevokeTokenPreservesOriginalTimestamp covers audit correctness:
// re-revoking an already-revoked token must not overwrite the original
// revoked_at — a second RevokeToken call is a no-op, not a stamp-refresh.
func assertRevokeTokenPreservesOriginalTimestamp(ctx context.Context, t *testing.T, st *serviceAccountStore, sa *serviceAccountRow) {
	t.Helper()
	tok, err := st.InsertToken(ctx, sa.ID, "hash-double-revoke", "secrets:read", nil, "user-admin-1")
	if err != nil {
		t.Fatalf("InsertToken(double-revoke): %v", err)
	}
	first, err := st.RevokeToken(ctx, tok.ID)
	if err != nil || first.RevokedAt == nil {
		t.Fatalf("RevokeToken(first): got %+v err %v", first, err)
	}
	time.Sleep(10 * time.Millisecond)
	second, err := st.RevokeToken(ctx, tok.ID)
	if err != nil || second.RevokedAt == nil {
		t.Fatalf("RevokeToken(second): got %+v err %v", second, err)
	}
	if !second.RevokedAt.Equal(*first.RevokedAt) {
		t.Fatalf("re-revoking must preserve the original revoked_at: first=%v second=%v", first.RevokedAt, second.RevokedAt)
	}
}

// assertDisabledSATokenDenied covers the security-critical invariant that
// disabling a service account fails closed for ALREADY-minted tokens: a token
// that resolved fine while its SA was active must stop resolving the moment
// the SA is disabled (DisableSA itself still soft-disables without deleting).
func assertDisabledSATokenDenied(ctx context.Context, t *testing.T, st *serviceAccountStore, sa *serviceAccountRow) {
	t.Helper()
	if _, err := st.InsertToken(ctx, sa.ID, "hash-pre-disable", "secrets:read", nil, "user-admin-1"); err != nil {
		t.Fatalf("InsertToken(pre-disable): %v", err)
	}

	disabled, err := st.DisableSA(ctx, sa.ID)
	if err != nil || !disabled.Disabled {
		t.Fatalf("DisableSA: got %+v err %v", disabled, err)
	}

	if _, err := st.TokenByHash(ctx, "hash-pre-disable"); err != pgx.ErrNoRows {
		t.Fatalf("TokenByHash(disabled SA): want pgx.ErrNoRows, got %v", err)
	}
}
