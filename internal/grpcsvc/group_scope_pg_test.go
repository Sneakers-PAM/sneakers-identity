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

// newScopePGServer is newPGServer plus the groups the scope grammar tests
// need: names with spaces, a slug collision, and a non-ASCII name.
func newScopePGServer(t *testing.T) *Server {
	t.Helper()
	s := newPGServer(t)
	if _, err := s.db.Exec(context.Background(), `INSERT INTO groups (id,name) VALUES
		('group-helpdesk','Help Desk'),('group-infra','Infrastructure'),
		('group-netops-a','Net Ops'),('group-netops-b','net  ops'),('group-cafe','Café')`); err != nil {
		t.Fatalf("seed groups: %v", err)
	}
	return s
}

func newScopeSA(ctx context.Context, t *testing.T, s *Server, name string) string {
	t.Helper()
	resp, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{Name: name, CreatedBy: "user-admin-1"})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	return resp.GetServiceAccount().GetId()
}

// TestPGApiTokenScopeGrammar covers the opaque API-token path: mint-time
// validation and ID canonicalization, verify-time resolution to group names,
// legacy exact-name scopes, and fail-closed collisions.
func TestPGApiTokenScopeGrammar(t *testing.T) {
	ctx := context.Background()
	s := newScopePGServer(t)
	saID := newScopeSA(ctx, t, s, "scope-grammar-token")

	verifyNames := func(token string) []string {
		t.Helper()
		resp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{Token: token})
		if err != nil || !resp.GetValid() {
			t.Fatalf("VerifyApiToken: %+v err %v", resp, err)
		}
		return resp.GetGroupNames()
	}

	// Slug, ID, exact name and case variants all canonicalize to IDs.
	mint := mintToken(ctx, t, s, saID, " help-desk\tgroup-infra HELP-DESK Security ")
	if got := mint.GetMeta().GetScope(); got != "group-helpdesk group-infra group-security" {
		t.Fatalf("minted scope = %q, want canonical IDs", got)
	}
	if got := verifyNames(mint.GetToken()); !reflect.DeepEqual(got, []string{"Help Desk", "Infrastructure", "Security"}) {
		t.Fatalf("verify group names = %q", got)
	}

	// Non-ASCII names are mintable by ID only.
	cafe := mintToken(ctx, t, s, saID, "group-cafe")
	if got := verifyNames(cafe.GetToken()); !reflect.DeepEqual(got, []string{"Café"}) {
		t.Fatalf("verify by id of non-ascii group = %q", got)
	}

	// Empty scope is allowed and grants no groups.
	empty := mintToken(ctx, t, s, saID, "  ")
	if got := verifyNames(empty.GetToken()); len(got) != 0 {
		t.Fatalf("empty scope must grant no groups, got %q", got)
	}

	// Unknown, colliding, lookalike and non-ASCII entries reject the mint.
	for _, bad := range []string{"nope", "net-ops", "help-desk nope", "Ιnfrastructure", "café", "help_desk"} {
		_, err := s.MintApiToken(ctx, &identityv1.MintApiTokenRequest{ServiceAccountId: saID, Scope: bad, CreatedBy: "user-admin-1"})
		if status.Code(err) != codes.InvalidArgument {
			t.Errorf("MintApiToken(scope %q): want InvalidArgument, got %v", bad, err)
		}
	}

	assertLegacyTokenScope(ctx, t, s, saID, mint.GetToken(), verifyNames)
}

// assertLegacyTokenScope covers legacy tokens, renames and post-mint
// collisions on the API-token path.
func assertLegacyTokenScope(ctx context.Context, t *testing.T, s *Server, saID, canonical string, verifyNames func(string) []string) {
	t.Helper()
	// A legacy token (minted before the scope grammar, stored scope verbatim) keeps
	// working for exact names; unknown and colliding entries grant nothing.
	legacy := "legacy-plaintext-token-for-scope-grammar"
	if _, err := s.saStore().InsertToken(ctx, saID, hashToken(legacy), "Infrastructure nope net-ops Security", nil, "user-admin-1"); err != nil {
		t.Fatalf("InsertToken: %v", err)
	}
	if got := verifyNames(legacy); !reflect.DeepEqual(got, []string{"Infrastructure", "Security"}) {
		t.Fatalf("legacy verify group names = %q", got)
	}

	// A rename follows the ID: the canonical token now grants the new name.
	if _, err := s.db.Exec(ctx, `UPDATE groups SET name='Service Desk' WHERE id='group-helpdesk'`); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := verifyNames(canonical); !reflect.DeepEqual(got, []string{"Service Desk", "Infrastructure", "Security"}) {
		t.Fatalf("after rename, verify group names = %q", got)
	}

	// A collision created AFTER mint fails closed for slug-scoped legacy
	// tokens but not for ID-canonical ones. (A trailing space: the unique name index
	// forbids a pure case-variant name, but the slug still collides.)
	if _, err := s.db.Exec(ctx, `INSERT INTO groups (id,name) VALUES ('group-infra-2','Infrastructure ')`); err != nil {
		t.Fatalf("insert colliding group: %v", err)
	}
	if got := verifyNames(legacy); !reflect.DeepEqual(got, []string{"Security"}) {
		t.Fatalf("legacy verify after collision = %q, want only Security", got)
	}
	if got := verifyNames(canonical); !reflect.DeepEqual(got, []string{"Service Desk", "Infrastructure", "Security"}) {
		t.Fatalf("canonical verify after collision = %q", got)
	}
}

// TestPGOidcScopeGrammar covers the Hydra OIDC path: allowed_groups is
// validated and stored as IDs, and the JWT scope resolves by ID or slug
// INTERSECT that bound.
func TestPGOidcScopeGrammar(t *testing.T) {
	ctx := context.Background()
	s := newScopePGServer(t)
	saID := newScopeSA(ctx, t, s, "scope-grammar-oidc")
	const issuer, subject = "https://hydra.example.org/", "client-scope-grammar"

	link := func(groups []string) (*identityv1.ServiceAccount, error) {
		resp, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
			ServiceAccountId: saID, OidcIssuer: issuer, OidcSubject: subject,
			ActingAdmin: "user-admin-1", AllowedGroups: groups,
		})
		return resp.GetServiceAccount(), err
	}
	resolve := func(scope string) []string {
		t.Helper()
		resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
			OidcIssuer: issuer, OidcSubject: subject, Scope: scope,
		})
		if err != nil || !resp.GetValid() {
			t.Fatalf("ResolveServiceAccountByOidc: %+v err %v", resp, err)
		}
		return resp.GetGroupNames()
	}

	sa, err := link([]string{"Help Desk", "group-infra", "net  ops"})
	if err != nil {
		t.Fatalf("LinkOidcClient: %v", err)
	}
	if got := sa.GetOidcAllowedGroups(); !reflect.DeepEqual(got, []string{"group-helpdesk", "group-infra", "group-netops-b"}) {
		t.Fatalf("stored allowed groups = %q, want IDs", got)
	}

	cases := []struct {
		scope string
		want  []string
	}{
		{"help-desk", []string{"Help Desk"}},
		{"group-helpdesk", []string{"Help Desk"}},
		{"Infrastructure", []string{"Infrastructure"}},
		{"HELP-DESK  infrastructure", []string{"Help Desk", "Infrastructure"}},
		{"help-desk platform-team security", []string{"Help Desk"}}, // outside bound dropped
		{"net-ops", []string{}},                                     // collision fails closed
		{"group-netops-b", []string{"net  ops"}},                    // ID still works
		{"nope", []string{}},
		{"Ιnfrastructure", []string{}},
		{"", []string{}},
	}
	for _, tc := range cases {
		if got := resolve(tc.scope); !reflect.DeepEqual(nonNil(got), tc.want) {
			t.Errorf("resolve(%q) = %q, want %q", tc.scope, got, tc.want)
		}
	}

	// Unknown or colliding allowed entries reject the link, leaving the
	// previous bound untouched.
	for _, bad := range []string{"nope", "net-ops", "Ιnfrastructure"} {
		if _, err := link([]string{"Help Desk", bad}); status.Code(err) != codes.InvalidArgument {
			t.Errorf("LinkOidcClient(%q): want InvalidArgument, got %v", bad, err)
		}
	}
	if got := resolve("help-desk"); !reflect.DeepEqual(got, []string{"Help Desk"}) {
		t.Fatalf("bound changed by a rejected link: %q", got)
	}

	// Empty allowed groups grants nothing, whatever the scope.
	if _, err := link(nil); err != nil {
		t.Fatalf("LinkOidcClient(nil): %v", err)
	}
	if got := resolve("help-desk group-infra"); len(got) != 0 {
		t.Fatalf("empty bound must grant nothing, got %q", got)
	}

	// A legacy row (exact names stored) still bounds correctly.
	if _, err := s.saStore().LinkOidc(ctx, saID, issuer, subject, []string{"Infrastructure", "Help Desk"}); err != nil {
		t.Fatalf("LinkOidc(legacy): %v", err)
	}
	if got := resolve("infrastructure help-desk group-cafe"); !reflect.DeepEqual(got, []string{"Infrastructure", "Help Desk"}) {
		t.Fatalf("legacy bound resolve = %q", got)
	}
}
