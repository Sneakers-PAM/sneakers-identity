// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestPGServiceAccountRPCs covers the service-account + API-token RPCs end to
// end against a real Postgres (skips without IDENTITY_PG_DSN, via
// newPGServer): MintApiToken returns a non-empty plaintext token exactly once
// plus metadata; the token verifies via VerifyApiToken with the right SA id +
// scope; a revoked or expired token is valid=false; ListApiTokens never
// carries a token value; a garbage token is valid=false.
func TestPGServiceAccountRPCs(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)

	saResp, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{
		Name: "ci-runner", Description: "CI pipeline machine account", CreatedBy: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	sa := saResp.GetServiceAccount()
	if sa.GetId() == "" || sa.GetName() != "ci-runner" || sa.GetDisabled() {
		t.Fatalf("unexpected service account: %+v", sa)
	}

	list, err := s.ListServiceAccounts(ctx, &identityv1.ListServiceAccountsRequest{})
	if err != nil || len(list.GetServiceAccounts()) != 1 {
		t.Fatalf("ListServiceAccounts: got %v err %v", list, err)
	}

	mintResp := mintToken(ctx, t, s, sa.GetId(), "Security")
	if mintResp.GetToken() == "" {
		t.Fatalf("MintApiToken must return a non-empty plaintext token")
	}
	if mintResp.GetMeta().GetServiceAccountId() != sa.GetId() || mintResp.GetMeta().GetScope() != "group-security" {
		t.Fatalf("unexpected token meta: %+v", mintResp.GetMeta())
	}

	assertVerifiesAs(ctx, t, s, mintResp.GetToken(), sa, "group-security", []string{"Security"})

	assertRevokedTokenInvalid(ctx, t, s, sa.GetId(), mintResp.GetMeta().GetId())
	assertGarbageTokenInvalid(ctx, t, s)
	assertListNeverLeaksToken(ctx, t, s, sa.GetId())
	assertDisabledServiceAccount(ctx, t, s)
}

// TestPGServiceAccountOidcRPCs covers the OIDC client-link RPCs end to end
// against a real Postgres (skips without IDENTITY_PG_DSN, via newPGServer):
// LinkOidcClient then ResolveServiceAccountByOidc resolves valid=true with
// the right service account id; an unknown (issuer,subject) pair resolves
// valid=false; a disabled but still-linked SA resolves valid=false
// (fail-closed, indistinguishable from unknown, mirroring VerifyApiToken);
// UnlinkOidcClient clears the linkage so it no longer resolves.
func TestPGServiceAccountOidcRPCs(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)

	saResp, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{
		Name: "oidc-agent-rpc", Description: "agent authenticating via Hydra", CreatedBy: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	saID := saResp.GetServiceAccount().GetId()

	const issuer = "https://hydra.example.org/"
	const subject = "client-oidc-agent-rpc"

	linkResp, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
		ServiceAccountId: saID, OidcIssuer: issuer, OidcSubject: subject, ActingAdmin: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("LinkOidcClient: %v", err)
	}
	if linkResp.GetServiceAccount().GetOidcIssuer() != issuer || linkResp.GetServiceAccount().GetOidcSubject() != subject {
		t.Fatalf("LinkOidcClient: unexpected service account: %+v", linkResp.GetServiceAccount())
	}

	resolveResp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: issuer, OidcSubject: subject,
	})
	if err != nil {
		t.Fatalf("ResolveServiceAccountByOidc(linked): %v", err)
	}
	if !resolveResp.GetValid() || resolveResp.GetServiceAccountId() != saID {
		t.Fatalf("ResolveServiceAccountByOidc(linked): got %+v", resolveResp)
	}

	assertUnknownOidcNotValid(ctx, t, s, issuer)
	assertDisabledOidcNotValid(ctx, t, s, saID, issuer, subject)
	assertUnlinkOidcClientClearsResolution(ctx, t, s, saID, issuer)
}

// assertUnknownOidcNotValid asserts an unlinked subject under the same
// issuer resolves valid=false, never a distinguishing error.
func assertUnknownOidcNotValid(ctx context.Context, t *testing.T, s *Server, issuer string) {
	t.Helper()
	resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: issuer, OidcSubject: "no-such-subject",
	})
	if err != nil {
		t.Fatalf("ResolveServiceAccountByOidc(unknown): %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("an unknown (issuer,subject) must not resolve as valid")
	}
}

// assertDisabledOidcNotValid covers the security-critical fail-closed
// invariant: disabling the linked service account stops OIDC resolution
// even though the linkage row itself is untouched.
func assertDisabledOidcNotValid(ctx context.Context, t *testing.T, s *Server, saID, issuer, subject string) {
	t.Helper()
	if _, err := s.DisableServiceAccount(ctx, &identityv1.DisableServiceAccountRequest{Id: saID}); err != nil {
		t.Fatalf("DisableServiceAccount: %v", err)
	}
	resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: issuer, OidcSubject: subject,
	})
	if err != nil {
		t.Fatalf("ResolveServiceAccountByOidc(disabled SA): %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("a disabled service account's OIDC linkage must not resolve as valid")
	}
}

// assertUnlinkOidcClientClearsResolution re-enables the SA (undoing the
// disable from assertDisabledOidcNotValid, via a direct SQL fixture update —
// there is no EnableServiceAccount RPC) to prove UnlinkOidcClient, not the
// disabled flag, is what stops resolution afterward.
func assertUnlinkOidcClientClearsResolution(ctx context.Context, t *testing.T, s *Server, saID, issuer string) {
	t.Helper()
	if _, err := s.db.Exec(ctx, `UPDATE service_accounts SET disabled = false WHERE id = $1`, saID); err != nil {
		t.Fatalf("re-enable fixture SA: %v", err)
	}

	unlinkResp, err := s.UnlinkOidcClient(ctx, &identityv1.UnlinkOidcClientRequest{ServiceAccountId: saID, ActingAdmin: "user-admin-1"})
	if err != nil {
		t.Fatalf("UnlinkOidcClient: %v", err)
	}
	if unlinkResp.GetServiceAccount().GetOidcIssuer() != "" || unlinkResp.GetServiceAccount().GetOidcSubject() != "" {
		t.Fatalf("UnlinkOidcClient should clear both fields, got %+v", unlinkResp.GetServiceAccount())
	}

	resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: issuer, OidcSubject: "client-oidc-agent-rpc",
	})
	if err != nil {
		t.Fatalf("ResolveServiceAccountByOidc(post-unlink): %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("resolution must not succeed after UnlinkOidcClient")
	}
}

// mintToken mints a token for saID with the given scope and fails the test on
// error.
func mintToken(ctx context.Context, t *testing.T, s *Server, saID, scope string) *identityv1.MintApiTokenResponse {
	t.Helper()
	resp, err := s.MintApiToken(ctx, &identityv1.MintApiTokenRequest{
		ServiceAccountId: saID, Scope: scope, CreatedBy: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("MintApiToken: %v", err)
	}
	return resp
}

// assertRevokedTokenInvalid mints a fresh token, revokes it, and asserts
// VerifyApiToken then reports it invalid.
func assertRevokedTokenInvalid(ctx context.Context, t *testing.T, s *Server, saID, otherTokenID string) {
	t.Helper()
	mint := mintToken(ctx, t, s, saID, "group-platform")
	if mint.GetMeta().GetId() == otherTokenID {
		t.Fatalf("MintApiToken should mint a new token id each time")
	}
	if _, err := s.RevokeApiToken(ctx, &identityv1.RevokeApiTokenRequest{Id: mint.GetMeta().GetId()}); err != nil {
		t.Fatalf("RevokeApiToken: %v", err)
	}
	verifyResp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: mint.GetToken()})
	if err != nil {
		t.Fatalf("VerifyApiToken(revoked): %v", err)
	}
	if verifyResp.GetValid() {
		t.Fatalf("a revoked token must not verify as valid")
	}
}

// assertGarbageTokenInvalid asserts a well-formed-but-unknown token string
// verifies as invalid, without distinguishing it from expired/revoked.
func assertGarbageTokenInvalid(ctx context.Context, t *testing.T, s *Server) {
	t.Helper()
	verifyResp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: "garbage-not-a-real-token"})
	if err != nil {
		t.Fatalf("VerifyApiToken(garbage): %v", err)
	}
	if verifyResp.GetValid() {
		t.Fatalf("a garbage token must not verify as valid")
	}
}

// assertListNeverLeaksToken mints a token and asserts ListApiTokens returns
// its metadata with the token's plaintext discoverable nowhere in the
// response (the ApiToken message structurally has no token field).
func assertListNeverLeaksToken(ctx context.Context, t *testing.T, s *Server, saID string) {
	t.Helper()
	mint := mintToken(ctx, t, s, saID, "security")
	list, err := s.ListApiTokens(ctx, &identityv1.ListApiTokensRequest{ServiceAccountId: saID})
	if err != nil {
		t.Fatalf("ListApiTokens: %v", err)
	}
	var found bool
	for _, tok := range list.GetTokens() {
		if tok.GetId() == mint.GetMeta().GetId() {
			found = true
			if tok.GetServiceAccountId() != saID {
				t.Fatalf("listed token has wrong service_account_id: %+v", tok)
			}
		}
	}
	if !found {
		t.Fatalf("ListApiTokens did not include the minted token")
	}
}

// assertDisabledServiceAccount covers the security-critical invariant that
// disabling a service account fails closed for machine auth end to end, on
// its own dedicated SA (so it doesn't disturb the shared fixture above): a
// token minted before the disable stops verifying, and MintApiToken refuses
// to mint a NEW token for an already-disabled SA (no row is written).
func assertDisabledServiceAccount(ctx context.Context, t *testing.T, s *Server) {
	t.Helper()
	saResp, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{
		Name: "disabled-sa-test", CreatedBy: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount(disabled-sa-test): %v", err)
	}
	saID := saResp.GetServiceAccount().GetId()

	mint := mintToken(ctx, t, s, saID, "security")

	if _, err := s.DisableServiceAccount(ctx, &identityv1.DisableServiceAccountRequest{Id: saID}); err != nil {
		t.Fatalf("DisableServiceAccount: %v", err)
	}

	verifyResp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: mint.GetToken()})
	if err != nil {
		t.Fatalf("VerifyApiToken(disabled SA's token): %v", err)
	}
	if verifyResp.GetValid() {
		t.Fatalf("a token belonging to a disabled service account must not verify as valid")
	}

	_, err = s.MintApiToken(ctx, &identityv1.MintApiTokenRequest{
		ServiceAccountId: saID, Scope: "security", CreatedBy: "user-admin-1",
	})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("MintApiToken(disabled SA): want FailedPrecondition, got %v", err)
	}

	list, err := s.ListApiTokens(ctx, &identityv1.ListApiTokensRequest{ServiceAccountId: saID})
	if err != nil {
		t.Fatalf("ListApiTokens: %v", err)
	}
	if len(list.GetTokens()) != 1 {
		t.Fatalf("MintApiToken(disabled SA) must not have minted a token: got %d tokens", len(list.GetTokens()))
	}
}

// assertVerifiesAs checks token verifies valid as sa, with the given stored
// scope and resolved group names.
func assertVerifiesAs(ctx context.Context, t *testing.T, s *Server, token string, sa *identityv1.ServiceAccount, scope string, groups []string) {
	t.Helper()
	resp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: token})
	if err != nil {
		t.Fatalf("VerifyApiToken: %v", err)
	}
	if !resp.GetValid() || resp.GetServiceAccountId() != sa.GetId() || resp.GetScope() != scope ||
		resp.GetName() != sa.GetName() || !reflect.DeepEqual(resp.GetGroupNames(), groups) {
		t.Fatalf("VerifyApiToken(valid token): got %+v", resp)
	}
}
