// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// orphanFixture seeds, on top of newPGServer's two groups:
//   - user-admin (site-admin) and user-ada (plain user, member of Platform Team);
//   - group-empty "Build Agents" (no members, unreferenced);
//   - group-bound "Release Bots" (no members, in sa-ci's OIDC bound and in the
//     scope of a live token; a revoked token naming it doesn't count);
//   - Security (no members, unreferenced).
func orphanFixture(t *testing.T) *Server {
	t.Helper()
	ctx := context.Background()
	s := newPGServer(t)
	for _, q := range []string{
		`INSERT INTO users (id,name,email,roles) VALUES
		   ('user-admin','Admin','admin@example.org','{site-admin}'),
		   ('user-ada','Ada','ada@example.org','{user}')`,
		`INSERT INTO groups (id,name) VALUES ('group-empty','Build Agents'),('group-bound','Release Bots')`,
		`INSERT INTO group_membership (user_id,group_id) VALUES ('user-ada','group-platform')`,
		`INSERT INTO service_accounts (id,name,created_by,oidc_allowed_groups)
		   VALUES ('sa-ci','ci-runner','user-admin','{group-bound,group-platform}')`,
		`INSERT INTO api_tokens (id,service_account_id,token_hash,scope,created_by) VALUES
		   ('tok-live','sa-ci','h1','release-bots group-platform','user-admin'),
		   ('tok-old','sa-ci','h2','group-bound','user-admin')`,
		`UPDATE api_tokens SET revoked_at=now() WHERE id='tok-old'`,
	} {
		if _, err := s.db.Exec(ctx, q); err != nil {
			t.Fatalf("seed (%s): %v", q, err)
		}
	}
	return s
}

func orphanIDs(gs []*identityv1.OrphanGroup) []string {
	var out []string
	for _, g := range gs {
		out = append(out, g.GetId())
	}
	slices.Sort(out)
	return out
}

func groupExists(t *testing.T, s *Server, id string) bool {
	t.Helper()
	var n int
	if err := s.db.QueryRow(context.Background(), `SELECT count(*) FROM groups WHERE id=$1`, id).Scan(&n); err != nil {
		t.Fatalf("count group: %v", err)
	}
	return n == 1
}

func TestPGListOrphanGroups(t *testing.T) {
	s := orphanFixture(t)
	resp, err := s.ListOrphanGroups(context.Background(), &identityv1.ListOrphanGroupsRequest{ActingUserId: "user-admin"})
	if err != nil {
		t.Fatalf("ListOrphanGroups: %v", err)
	}
	if got, want := orphanIDs(resp.GetGroups()), []string{"group-bound", "group-empty", "group-security"}; !slices.Equal(got, want) {
		t.Fatalf("orphans = %v, want %v (a group with a member is never an orphan)", got, want)
	}
	if resp.GetWarning() == "" {
		t.Error("the RACI warning is missing")
	}
	for _, g := range resp.GetGroups() {
		if g.GetId() != "group-bound" {
			if len(g.GetServiceAccounts())+len(g.GetApiTokens()) != 0 {
				t.Errorf("%s: unexpected references %v %v", g.GetId(), g.GetServiceAccounts(), g.GetApiTokens())
			}
			continue
		}
		if len(g.GetServiceAccounts()) != 1 || g.GetServiceAccounts()[0].GetId() != "sa-ci" || g.GetServiceAccounts()[0].GetName() != "ci-runner" {
			t.Errorf("bound service accounts = %v, want sa-ci", g.GetServiceAccounts())
		}
		if len(g.GetApiTokens()) != 1 || g.GetApiTokens()[0].GetId() != "tok-live" {
			t.Errorf("tokens = %v, want only the live token (by slug)", g.GetApiTokens())
		}
	}
}

func TestPGOrphanGroupsNeedASiteAdmin(t *testing.T) {
	s := orphanFixture(t)
	ctx := context.Background()
	for _, actor := range []string{"", "user-ada", "user-nobody"} {
		if _, err := s.ListOrphanGroups(ctx, &identityv1.ListOrphanGroupsRequest{ActingUserId: actor}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("ListOrphanGroups as %q: %v, want PermissionDenied", actor, err)
		}
		if _, err := s.PruneOrphanGroups(ctx, &identityv1.PruneOrphanGroupsRequest{Ids: []string{"group-empty"}, ActingUserId: actor}); status.Code(err) != codes.PermissionDenied {
			t.Errorf("PruneOrphanGroups as %q: %v, want PermissionDenied", actor, err)
		}
	}
	if !groupExists(t, s, "group-empty") {
		t.Fatal("a refused prune deleted the group")
	}
}

func TestPGPruneOrphanGroupsDeletesAnUnreferencedOrphan(t *testing.T) {
	s := orphanFixture(t)
	resp, err := s.PruneOrphanGroups(context.Background(), &identityv1.PruneOrphanGroupsRequest{
		Ids: []string{"group-empty", " group-empty "}, ActingUserId: "user-admin",
	})
	if err != nil {
		t.Fatalf("PruneOrphanGroups: %v", err)
	}
	if len(resp.GetPruned()) != 1 || resp.GetPruned()[0].GetId() != "group-empty" || resp.GetPruned()[0].GetName() != "Build Agents" {
		t.Fatalf("pruned = %v, want group-empty once", resp.GetPruned())
	}
	if groupExists(t, s, "group-empty") {
		t.Fatal("group-empty still exists")
	}
	if resp.GetWarning() == "" {
		t.Error("the RACI warning is missing")
	}
}

func TestPGPruneOrphanGroupsIsAllOrNothing(t *testing.T) {
	s := orphanFixture(t)
	ctx := context.Background()
	for name, ids := range map[string][]string{
		"unknown id":       {"group-empty", "group-missing"},
		"has a member":     {"group-empty", "group-platform"},
		"still referenced": {"group-empty", "group-bound"},
		"no ids":           {" "},
	} {
		_, err := s.PruneOrphanGroups(ctx, &identityv1.PruneOrphanGroupsRequest{Ids: ids, ActingUserId: "user-admin"})
		want := codes.FailedPrecondition
		if name == "no ids" {
			want = codes.InvalidArgument
		}
		if status.Code(err) != want {
			t.Errorf("%s: %v, want %v", name, err, want)
		}
	}
	for _, id := range []string{"group-empty", "group-platform", "group-bound"} {
		if !groupExists(t, s, id) {
			t.Errorf("%s was deleted by a refused prune", id)
		}
	}
}

func TestPGPruneOrphanGroupsForceStripsReferences(t *testing.T) {
	s := orphanFixture(t)
	ctx := context.Background()
	resp, err := s.PruneOrphanGroups(ctx, &identityv1.PruneOrphanGroupsRequest{
		Ids: []string{"group-bound"}, Force: true, ActingUserId: "user-admin",
	})
	if err != nil {
		t.Fatalf("PruneOrphanGroups force: %v", err)
	}
	p := resp.GetPruned()[0]
	if len(p.GetServiceAccountsUpdated()) != 1 || len(p.GetApiTokensUpdated()) != 1 {
		t.Fatalf("updates = %v %v, want sa-ci and tok-live", p.GetServiceAccountsUpdated(), p.GetApiTokensUpdated())
	}
	var bound []string
	if err := s.db.QueryRow(ctx, `SELECT oidc_allowed_groups FROM service_accounts WHERE id='sa-ci'`).Scan(&bound); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(bound, []string{"group-platform"}) {
		t.Errorf("sa-ci bound = %v, want [group-platform]", bound)
	}
	var live, old string
	if err := s.db.QueryRow(ctx, `SELECT scope FROM api_tokens WHERE id='tok-live'`).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow(ctx, `SELECT scope FROM api_tokens WHERE id='tok-old'`).Scan(&old); err != nil {
		t.Fatal(err)
	}
	if live != "group-platform" {
		t.Errorf("tok-live scope = %q, want %q", live, "group-platform")
	}
	if old != "group-bound" {
		t.Errorf("a revoked token's scope changed: %q", old)
	}
	if groupExists(t, s, "group-bound") {
		t.Fatal("group-bound still exists")
	}
}
