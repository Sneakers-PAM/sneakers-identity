// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// A service account's group ids come back next to the names, pair for pair,
// so the vault can match a group rule by id for a machine principal too.
func TestPGVerifyApiTokenReturnsGroupIDs(t *testing.T) {
	ctx := context.Background()
	s := newScopePGServer(t)
	saID := newScopeSA(ctx, t, s, "group-ids-token")

	verify := func(token string) *identityv1.VerifyApiTokenResponse {
		t.Helper()
		resp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: token})
		if err != nil || !resp.GetValid() {
			t.Fatalf("VerifyApiToken: %+v err %v", resp, err)
		}
		return resp
	}

	got := verify(mintToken(ctx, t, s, saID, "group-infra help-desk Security").GetToken())
	if want := []string{"Infrastructure", "Help Desk", "Security"}; !slices.Equal(got.GetGroupNames(), want) {
		t.Fatalf("group_names = %v, want %v", got.GetGroupNames(), want)
	}
	if want := []string{"group-infra", "group-helpdesk", "group-security"}; !slices.Equal(got.GetGroupIds(), want) {
		t.Fatalf("group_ids = %v, want %v", got.GetGroupIds(), want)
	}

	none := verify(mintToken(ctx, t, s, saID, "").GetToken())
	if len(none.GetGroupNames()) != 0 || len(none.GetGroupIds()) != 0 {
		t.Fatalf("an unscoped token got names %v ids %v", none.GetGroupNames(), none.GetGroupIds())
	}
}

func TestPGResolveServiceAccountByOidcReturnsGroupIDs(t *testing.T) {
	ctx := context.Background()
	s := newScopePGServer(t)
	saID := newScopeSA(ctx, t, s, "group-ids-oidc")
	const issuer, subject = "https://hydra.example.org/", "client-group-ids"

	if _, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
		ServiceAccountId: saID, OidcIssuer: issuer, OidcSubject: subject,
		ActingAdmin: "user-admin-1", AllowedGroups: []string{"group-helpdesk", "group-infra"},
	}); err != nil {
		t.Fatalf("LinkOidcClient: %v", err)
	}
	resolve := func(scope string) *identityv1.ResolveServiceAccountByOidcResponse {
		t.Helper()
		resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
			OidcIssuer: issuer, OidcSubject: subject, Scope: scope,
		})
		if err != nil || !resp.GetValid() {
			t.Fatalf("ResolveServiceAccountByOidc: %+v err %v", resp, err)
		}
		return resp
	}

	got := resolve("infrastructure security help-desk")
	if want := []string{"Infrastructure", "Help Desk"}; !slices.Equal(got.GetGroupNames(), want) {
		t.Fatalf("group_names = %v, want %v", got.GetGroupNames(), want)
	}
	if want := []string{"group-infra", "group-helpdesk"}; !slices.Equal(got.GetGroupIds(), want) {
		t.Fatalf("group_ids = %v, want %v", got.GetGroupIds(), want)
	}

	for _, scope := range []string{"", "security"} {
		none := resolve(scope)
		if len(none.GetGroupNames()) != 0 || len(none.GetGroupIds()) != 0 {
			t.Fatalf("scope %q got names %v ids %v", scope, none.GetGroupNames(), none.GetGroupIds())
		}
	}
}
