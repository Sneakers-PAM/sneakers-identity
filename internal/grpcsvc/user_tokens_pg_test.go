// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strings"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func seedTokenUser(ctx context.Context, t *testing.T, s *Server, id string, groupIDs ...string) {
	t.Helper()
	if _, err := s.db.Exec(ctx, `INSERT INTO users (id,name,email,roles) VALUES ($1,$1,$1||'@example.org','{user}')`, id); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
	for _, g := range groupIDs {
		addMember(ctx, t, s, id, g)
	}
}

func addMember(ctx context.Context, t *testing.T, s *Server, userID, groupID string) {
	t.Helper()
	if _, err := s.db.Exec(ctx, `INSERT INTO group_membership (user_id, group_id) VALUES ($1,$2)`, userID, groupID); err != nil {
		t.Fatalf("add %s to %s: %v", userID, groupID, err)
	}
}

func mintUserToken(ctx context.Context, t *testing.T, s *Server, userID string) *identityv1.MintUserTokenResponse {
	t.Helper()
	resp, err := s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: userID, Label: "laptop", ClientName: "Example CLI"})
	if err != nil {
		t.Fatalf("MintUserToken: %v", err)
	}
	return resp
}

func verifyUserToken(ctx context.Context, t *testing.T, s *Server, token string) *identityv1.VerifyUserTokenResponse {
	t.Helper()
	resp, err := s.VerifyUserToken(ctx, &identityv1.VerifyUserTokenRequest{Token: token})
	if err != nil {
		t.Fatalf("VerifyUserToken: %v", err)
	}
	return resp
}

func TestPGUserTokenMintReturnsPlaintextOnce(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	minted := mintUserToken(ctx, t, s, "u-ada")
	if !strings.HasPrefix(minted.GetToken(), "snk_u_") || len(minted.GetToken()) != len("snk_u_")+43 {
		t.Fatalf("token = %q, want snk_u_ + 43 base64url chars", minted.GetToken())
	}
	meta := minted.GetMeta()
	if meta.GetUserId() != "u-ada" || meta.GetLabel() != "laptop" || meta.GetClientName() != "Example CLI" ||
		meta.GetCreatedAtUnix() == 0 || meta.GetExpiresAtUnix() != 0 || meta.GetRevokedAtUnix() != 0 {
		t.Fatalf("meta = %+v", meta)
	}
	var stored int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM user_tokens WHERE token_hash=$1`, minted.GetToken()).Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("plaintext token found in user_tokens.token_hash (count=%d, err=%v)", stored, err)
	}
}

func TestPGUserTokenVerifyResolvesOwnerAndGroups(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security")
	minted := mintUserToken(ctx, t, s, "u-ada")

	got := verifyUserToken(ctx, t, s, minted.GetToken())
	if !got.GetValid() || got.GetTokenId() != minted.GetMeta().GetId() || got.GetUser().GetId() != "u-ada" {
		t.Fatalf("verify = %+v", got)
	}
	if !slices.Equal(got.GetGroupNames(), []string{"Security"}) {
		t.Fatalf("groups = %v, want [Security]", got.GetGroupNames())
	}
}

func TestPGUserTokenVerifyStampsLastUsed(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	verifyUserToken(ctx, t, s, mintUserToken(ctx, t, s, "u-ada").GetToken())

	list, err := s.ListUserTokens(ctx, &identityv1.ListUserTokensRequest{UserId: "u-ada"})
	if err != nil || len(list.GetTokens()) != 1 {
		t.Fatalf("ListUserTokens = %v, %v", list, err)
	}
	if list.GetTokens()[0].GetLastUsedAtUnix() == 0 {
		t.Fatal("last_used_at not stamped by verify")
	}
}

// The token carries no permissions: the same token must see membership
// changes on the very next verify.
func TestPGUserTokenGroupsAreResolvedLive(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security")
	token := mintUserToken(ctx, t, s, "u-ada").GetToken()

	addMember(ctx, t, s, "u-ada", "group-platform")
	if got := verifyUserToken(ctx, t, s, token).GetGroupNames(); !slices.Equal(got, []string{"Platform Team", "Security"}) {
		t.Fatalf("after adding Platform Team: groups = %v", got)
	}

	if _, err := s.db.Exec(ctx, `DELETE FROM group_membership WHERE user_id='u-ada' AND group_id='group-security'`); err != nil {
		t.Fatal(err)
	}
	if got := verifyUserToken(ctx, t, s, token).GetGroupNames(); !slices.Equal(got, []string{"Platform Team"}) {
		t.Fatalf("after removing Security: groups = %v", got)
	}
}

func TestPGUserTokenRevokeIsOwnerChecked(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	seedTokenUser(ctx, t, s, "u-bob")
	minted := mintUserToken(ctx, t, s, "u-ada")

	_, err := s.RevokeUserToken(ctx, &identityv1.RevokeUserTokenRequest{Id: minted.GetMeta().GetId(), UserId: "u-bob"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("revoke by non-owner: want NotFound, got %v", err)
	}
	if !verifyUserToken(ctx, t, s, minted.GetToken()).GetValid() {
		t.Fatal("a refused revoke must leave the token valid")
	}

	rev, err := s.RevokeUserToken(ctx, &identityv1.RevokeUserTokenRequest{Id: minted.GetMeta().GetId(), UserId: "u-ada"})
	if err != nil || rev.GetMeta().GetRevokedAtUnix() == 0 {
		t.Fatalf("owner revoke = %v, %v", rev, err)
	}
	if verifyUserToken(ctx, t, s, minted.GetToken()).GetValid() {
		t.Fatal("revoked token still verifies")
	}
}

func TestPGUserTokenInvalidTokens(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	minted := mintUserToken(ctx, t, s, "u-ada")

	if _, err := s.db.Exec(ctx, `UPDATE user_tokens SET expires_at = now() - interval '1 minute' WHERE id=$1`, minted.GetMeta().GetId()); err != nil {
		t.Fatal(err)
	}
	saShaped := strings.Repeat("A", 43)
	for name, tok := range map[string]string{
		"expired":        minted.GetToken(),
		"empty":          "",
		"unknown":        "snk_u_" + strings.Repeat("A", 43),
		"sa-token shape": saShaped,
	} {
		if got := verifyUserToken(ctx, t, s, tok); got.GetValid() || got.GetUser() != nil || len(got.GetGroupNames()) != 0 {
			t.Errorf("%s token: want an empty invalid response, got %+v", name, got)
		}
	}
}

func TestPGUserTokenMintNeedsAnExistingUser(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	_, err := s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: "u-nobody", Label: "x"})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("mint for unknown user: want NotFound, got %v", err)
	}
}

func TestPGUserTokenClientKind(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	for _, tc := range []struct{ in, want string }{
		{in: "mcp", want: "mcp"},
		{in: "cli", want: "cli"},
		{in: "", want: "cli"},
	} {
		minted, err := s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: "u-ada", Label: "agent", ClientKind: tc.in})
		if err != nil {
			t.Fatalf("MintUserToken(%q): %v", tc.in, err)
		}
		if got := minted.GetMeta().GetClientKind(); got != tc.want {
			t.Fatalf("mint %q: meta client_kind = %q, want %q", tc.in, got, tc.want)
		}
		if got := verifyUserToken(ctx, t, s, minted.GetToken()).GetClientKind(); got != tc.want {
			t.Fatalf("mint %q: verify client_kind = %q, want %q", tc.in, got, tc.want)
		}
	}
	list, err := s.ListUserTokens(ctx, &identityv1.ListUserTokensRequest{UserId: "u-ada"})
	if err != nil {
		t.Fatalf("ListUserTokens: %v", err)
	}
	kinds := []string{}
	for _, tok := range list.GetTokens() {
		kinds = append(kinds, tok.GetClientKind())
	}
	slices.Sort(kinds)
	if !slices.Equal(kinds, []string{"cli", "cli", "mcp"}) {
		t.Fatalf("listed kinds = %v", kinds)
	}

	_, err = s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: "u-ada", ClientKind: "browser"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("unknown kind: err = %v, want InvalidArgument", err)
	}
}

func TestPGRevokeTokensByClientKind(t *testing.T) {
	ctx := context.Background()
	rec := &recordingAuditor{}
	s := newPGServer(t).WithAudit(rec)
	seedTokenUser(ctx, t, s, "u-ada")
	seedTokenUser(ctx, t, s, "u-bob")

	mint := func(user, kind string) string {
		t.Helper()
		resp, err := s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: user, Label: "agent", ClientKind: kind})
		if err != nil {
			t.Fatalf("MintUserToken: %v", err)
		}
		return resp.GetToken()
	}
	mcp := []string{mint("u-ada", "mcp"), mint("u-ada", "mcp"), mint("u-bob", "mcp")}
	cli := []string{mint("u-ada", "cli"), mint("u-bob", "cli")}
	revokedEarlier := mint("u-bob", "mcp")
	if _, err := s.db.Exec(ctx, `UPDATE user_tokens SET revoked_at = now() WHERE token_hash=$1`, hashToken(revokedEarlier)); err != nil {
		t.Fatalf("revoke one beforehand: %v", err)
	}
	rec.take()

	res, err := s.RevokeTokensByClientKind(ctx, &identityv1.RevokeTokensByClientKindRequest{Kind: "mcp"})
	if err != nil {
		t.Fatalf("RevokeTokensByClientKind: %v", err)
	}
	if res.GetRevoked() != 3 {
		t.Fatalf("revoked = %d, want 3", res.GetRevoked())
	}
	for _, tok := range mcp {
		if verifyUserToken(ctx, t, s, tok).GetValid() {
			t.Fatal("an mcp token still verifies after RevokeTokensByClientKind(mcp)")
		}
	}
	for _, tok := range cli {
		if !verifyUserToken(ctx, t, s, tok).GetValid() {
			t.Fatal("a cli token stopped verifying after RevokeTokensByClientKind(mcp)")
		}
	}
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionUserTokenRevokeByKind, "", "mcp", map[string]string{"client_kind": "mcp", "revoked": "3"})
	assertNoSecretIn(t, []audit.Event{ev}, append(mcp, cli...)...)

	again, err := s.RevokeTokensByClientKind(ctx, &identityv1.RevokeTokensByClientKindRequest{Kind: "mcp"})
	if err != nil || again.GetRevoked() != 0 {
		t.Fatalf("second run = %v, %v; want 0 revoked", again, err)
	}
	rec.take()

	for _, bad := range []string{"", "browser"} {
		if _, err := s.RevokeTokensByClientKind(ctx, &identityv1.RevokeTokensByClientKindRequest{Kind: bad}); status.Code(err) != codes.InvalidArgument {
			t.Fatalf("kind %q: err = %v, want InvalidArgument", bad, err)
		}
	}
	rec.none(t)
}
