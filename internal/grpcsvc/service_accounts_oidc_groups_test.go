// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"reflect"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// TestNormalizeAllowedGroups covers the admin-supplied allowed-groups bound
// normalization (the OIDC trust model): whitespace is trimmed, blanks are
// dropped, duplicates collapse (first occurrence wins, order preserved), and
// nil/empty input yields a non-nil EMPTY slice — never nil — so the
// NOT NULL text[] column always stores '{}' ("no groups", fail closed).
func TestNormalizeAllowedGroups(t *testing.T) {
	cases := []struct {
		name string
		in   []string
		want []string
	}{
		{"nil", nil, []string{}},
		{"empty", []string{}, []string{}},
		{"blanks only", []string{"", "  ", "\t"}, []string{}},
		{"trim", []string{" platform ", "security"}, []string{"platform", "security"}},
		{"dedupe keeps first order", []string{"b", "a", "b", " a"}, []string{"b", "a"}},
		{"case sensitive", []string{"Ops", "ops"}, []string{"Ops", "ops"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeAllowedGroups(tc.in)
			if got == nil {
				t.Fatalf("normalizeAllowedGroups(%q) returned nil, want non-nil empty slice", tc.in)
			}
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeAllowedGroups(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestPGServiceAccountOidcAllowedGroups covers the allowed-groups bound end to
// end against a real Postgres (skips without IDENTITY_PG_DSN): a fresh SA has
// no allowed groups; LinkOidcClient stores the normalized list; the SA proto
// and ResolveServiceAccountByOidc both return it; a re-link REPLACES it
// (including down to empty, which resolves with zero allowed groups — the
// gateway then grants nothing); UnlinkOidcClient clears it.
func TestPGServiceAccountOidcAllowedGroups(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)

	saResp, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{
		Name: "oidc-allowed-groups", CreatedBy: "user-admin-1",
	})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	if got := saResp.GetServiceAccount().GetOidcAllowedGroups(); len(got) != 0 {
		t.Fatalf("fresh SA must have no allowed groups, got %q", got)
	}
	saID := saResp.GetServiceAccount().GetId()

	const issuer = "https://hydra.example.org/"
	const subject = "client-oidc-allowed-groups"

	link := func(groups []string) *identityv1.ServiceAccount {
		t.Helper()
		resp, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
			ServiceAccountId: saID, OidcIssuer: issuer, OidcSubject: subject,
			ActingAdmin: "user-admin-1", AllowedGroups: groups,
		})
		if err != nil {
			t.Fatalf("LinkOidcClient(%q): %v", groups, err)
		}
		return resp.GetServiceAccount()
	}
	resolveGroups := func() []string {
		t.Helper()
		resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{
			OidcIssuer: issuer, OidcSubject: subject,
		})
		if err != nil || !resp.GetValid() || resp.GetServiceAccountId() != saID {
			t.Fatalf("ResolveServiceAccountByOidc: got %+v err %v", resp, err)
		}
		return resp.GetAllowedGroups()
	}

	// Entries may be exact names, slugs or IDs; all are stored as IDs.
	sa := link([]string{" Platform Team ", "Security", "security", "group-security", ""})
	want := []string{"group-platform", "group-security"}
	if !reflect.DeepEqual(sa.GetOidcAllowedGroups(), want) {
		t.Fatalf("LinkOidcClient: allowed groups %q, want %q", sa.GetOidcAllowedGroups(), want)
	}
	if got := resolveGroups(); !reflect.DeepEqual(got, want) {
		t.Fatalf("Resolve: allowed groups %q, want %q", got, want)
	}

	assertListedAllowedGroups(t, s, saID, want)

	// Re-link replaces wholesale; linking with no groups binds the client but
	// grants it nothing.
	if got := link([]string{"Security"}).GetOidcAllowedGroups(); !reflect.DeepEqual(got, []string{"group-security"}) {
		t.Fatalf("re-link: allowed groups %q, want [group-security]", got)
	}
	if got := link(nil).GetOidcAllowedGroups(); len(got) != 0 {
		t.Fatalf("re-link(nil): allowed groups %q, want none", got)
	}
	if got := resolveGroups(); len(got) != 0 {
		t.Fatalf("Resolve after re-link(nil): allowed groups %q, want none", got)
	}

	link([]string{"Security"})
	unlinked, err := s.UnlinkOidcClient(ctx, &identityv1.UnlinkOidcClientRequest{ServiceAccountId: saID, ActingAdmin: "user-admin-1"})
	if err != nil {
		t.Fatalf("UnlinkOidcClient: %v", err)
	}
	if got := unlinked.GetServiceAccount().GetOidcAllowedGroups(); len(got) != 0 {
		t.Fatalf("UnlinkOidcClient must clear allowed groups, got %q", got)
	}

	// A disabled SA resolves as invalid and leaks no allowed groups, even
	// while a non-empty bound is stored.
	link([]string{"Security"})
	if _, err := s.DisableServiceAccount(ctx, &identityv1.DisableServiceAccountRequest{Id: saID}); err != nil {
		t.Fatalf("DisableServiceAccount: %v", err)
	}
	assertResolvesInvalid(t, s, issuer, subject)
}

// assertListedAllowedGroups checks ListServiceAccounts carries saID's bound.
func assertListedAllowedGroups(t *testing.T, s *Server, saID string, want []string) {
	t.Helper()
	list, err := s.ListServiceAccounts(context.Background(), &identityv1.ListServiceAccountsRequest{})
	if err != nil {
		t.Fatalf("ListServiceAccounts: %v", err)
	}
	for _, x := range list.GetServiceAccounts() {
		if x.GetId() != saID {
			continue
		}
		if !reflect.DeepEqual(x.GetOidcAllowedGroups(), want) {
			t.Fatalf("ListServiceAccounts: allowed groups %q, want %q", x.GetOidcAllowedGroups(), want)
		}
		return
	}
	t.Fatalf("ListServiceAccounts did not include %s", saID)
}

// assertResolvesInvalid checks (issuer, subject) resolves invalid and leaks
// no allowed groups.
func assertResolvesInvalid(t *testing.T, s *Server, issuer, subject string) {
	t.Helper()
	resp, err := s.ResolveServiceAccountByOidc(context.Background(), &identityv1.ResolveServiceAccountByOidcRequest{
		OidcIssuer: issuer, OidcSubject: subject,
	})
	if err != nil {
		t.Fatalf("ResolveServiceAccountByOidc: %v", err)
	}
	if resp.GetValid() || len(resp.GetAllowedGroups()) != 0 {
		t.Fatalf("want invalid with no groups, got %+v", resp)
	}
}
