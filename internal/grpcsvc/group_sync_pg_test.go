// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/lldap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// dbGroups returns the identity groups table as id -> name.
func dbGroups(ctx context.Context, t *testing.T, s *Server) map[string]string {
	t.Helper()
	rows, err := s.db.Query(ctx, `SELECT id, name FROM groups`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			t.Fatal(err)
		}
		out[id] = name
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// staticDir is a fake lldap directory whose ListGroups returns groups.
func staticDir(groups ...lldap.Group) *fakeLldap {
	return &fakeLldap{listGroups: func(context.Context) ([]lldap.Group, error) {
		return append([]lldap.Group(nil), groups...), nil
	}}
}

func sorted(ss []string) []string {
	out := append([]string{}, ss...)
	sort.Strings(out)
	return out
}

// TestPGGroupsNameUniqueCaseInsensitive: migration 0007 forbids two groups
// whose names differ only in case, because vault RACI matches names
// case-insensitively.
func TestPGGroupsNameUniqueCaseInsensitive(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	_, err := s.db.Exec(ctx, `INSERT INTO groups (id,name) VALUES ('group-security-2','SECURITY')`)
	if err == nil {
		t.Fatal("inserting a case-variant of an existing group name must fail")
	}
}

// TestPGCreateGroupWritesGroupsTable: CreateGroup lands the lldap group in
// the identity groups table under the lldap ID, so it is immediately listable,
// joinable and grantable.
func TestPGCreateGroupWritesGroupsTable(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	s.lldap = &fakeLldap{createGroup: func(_ context.Context, name string) (lldap.Group, error) {
		return lldap.Group{ID: 42, Name: name}, nil
	}}
	resp, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "  RACI Approvers  "})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	if resp.GetGroup().GetId() != "42" || resp.GetGroup().GetName() != "RACI Approvers" {
		t.Fatalf("group = %+v", resp.GetGroup())
	}
	if got := dbGroups(ctx, t, s)["42"]; got != "RACI Approvers" {
		t.Fatalf("groups row 42 = %q, want RACI Approvers", got)
	}
	g, err := s.GetGroup(ctx, &identityv1.GetGroupRequest{Id: "42"})
	if err != nil || g.GetGroup().GetName() != "RACI Approvers" {
		t.Fatalf("GetGroup: %v %+v", err, g)
	}
	// A member can now be added (AddGroupMember requires the groups row).
	if _, err := s.db.Exec(ctx, `INSERT INTO users (id,name,email,roles) VALUES ('u1','U One','u1@example.org','{user}')`); err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddGroupMember(ctx, &identityv1.AddGroupMemberRequest{UserId: "u1", GroupId: "42"}); err != nil {
		t.Fatalf("AddGroupMember on created group: %v", err)
	}
}

// TestPGCreateGroupRejectsCaseInsensitiveDuplicate: a name that already exists
// in identity (any case) is AlreadyExists and lldap is never touched.
func TestPGCreateGroupRejectsCaseInsensitiveDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	called := false
	s.lldap = &fakeLldap{createGroup: func(context.Context, string) (lldap.Group, error) {
		called = true
		return lldap.Group{ID: 7, Name: "security"}, nil
	}}
	_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "security"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", status.Code(err))
	}
	if called {
		t.Fatal("lldap CreateGroup must not run for a known duplicate")
	}
}

// TestPGCreateGroupLldapErrors: lldap's own duplicate is AlreadyExists, any
// other lldap failure is Internal, and neither writes a groups row.
func TestPGCreateGroupLldapErrors(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	for _, tc := range []struct {
		err  error
		want codes.Code
	}{
		{errors.New("Uniqueness violation: group already exists"), codes.AlreadyExists},
		{errors.New("connection refused"), codes.Internal},
	} {
		s.lldap = &fakeLldap{createGroup: func(context.Context, string) (lldap.Group, error) {
			return lldap.Group{}, tc.err
		}}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "ops"})
		if status.Code(err) != tc.want {
			t.Fatalf("lldap err %q: code = %v, want %v", tc.err, status.Code(err), tc.want)
		}
	}
	if got := len(dbGroups(ctx, t, s)); got != 2 {
		t.Fatalf("groups rows = %d, want the 2 seeded", got)
	}
}

// TestPGCreateGroupRollsBackLldapOnDBFailure: if the groups insert fails after
// lldap created the group (here: a racing case-variant row), the lldap group
// is deleted again so the two stores do not diverge.
func TestPGCreateGroupRollsBackLldapOnDBFailure(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	var deleted []int
	s.lldap = &fakeLldap{
		createGroup: func(ctx context.Context, name string) (lldap.Group, error) {
			if _, err := s.db.Exec(ctx, `INSERT INTO groups (id,name) VALUES ('race','OPS')`); err != nil {
				t.Fatal(err)
			}
			return lldap.Group{ID: 43, Name: name}, nil
		},
		deleteGroup: func(_ context.Context, id int) error {
			deleted = append(deleted, id)
			return nil
		},
	}
	_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "ops"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", status.Code(err))
	}
	if !reflect.DeepEqual(deleted, []int{43}) {
		t.Fatalf("lldap DeleteGroup calls = %v, want [43]", deleted)
	}
	if _, ok := dbGroups(ctx, t, s)["43"]; ok {
		t.Fatal("groups row 43 must not exist")
	}
}

// TestPGSyncGroupsFromLldap: the lldap -> identity reconciliation inserts new
// groups, renames changed ones by ID, ignores lldap's built-in groups, skips
// case-insensitive name conflicts, never deletes, and flags orphans that a
// service account still references. Re-running is a no-op.
func TestPGSyncGroupsFromLldap(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	if _, err := s.db.Exec(ctx, `INSERT INTO groups (id,name) VALUES ('9','Helpdesk (old)')`); err != nil {
		t.Fatal(err)
	}
	saID := newScopeSA(ctx, t, s, "sync-orphan-ref")
	if _, err := s.db.Exec(ctx, `UPDATE service_accounts SET oidc_allowed_groups='{group-platform}' WHERE id=$1`, saID); err != nil {
		t.Fatal(err)
	}
	s.lldap = staticDir(
		lldap.Group{ID: 1, Name: "lldap_admin"},
		lldap.Group{ID: 2, Name: "lldap_password_manager"},
		lldap.Group{ID: 3, Name: "lldap_strict_readonly"},
		lldap.Group{ID: 7, Name: "RACI Approvers"},
		lldap.Group{ID: 8, Name: "SECURITY"}, // case-variant of seeded group-security
		lldap.Group{ID: 9, Name: "Help Desk"},
	)

	rep, err := s.SyncGroups(ctx)
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	checkFirstSyncReport(t, rep)
	want := map[string]string{
		"group-platform": "Platform Team", "group-security": "Security",
		"7": "RACI Approvers", "9": "Help Desk",
	}
	if got := dbGroups(ctx, t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("groups = %v, want %v", got, want)
	}

	rep, err = s.SyncGroups(ctx)
	if err != nil {
		t.Fatalf("SyncGroups #2: %v", err)
	}
	if len(rep.Inserted) != 0 || len(rep.Renamed) != 0 || rep.Unchanged != 2 {
		t.Fatalf("second run should be a no-op, got %+v", rep)
	}
	if got := dbGroups(ctx, t, s); !reflect.DeepEqual(got, want) {
		t.Fatalf("groups after re-run = %v", got)
	}
}

// TestPGSyncGroupsRenameSwap: two groups swapping names in lldap must not trip
// the case-insensitive unique index mid-transaction.
func TestPGSyncGroupsRenameSwap(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	if _, err := s.db.Exec(ctx, `INSERT INTO groups (id,name) VALUES ('10','Alpha'),('11','Beta')`); err != nil {
		t.Fatal(err)
	}
	s.lldap = staticDir(lldap.Group{ID: 10, Name: "beta"}, lldap.Group{ID: 11, Name: "alpha"})
	rep, err := s.SyncGroups(ctx)
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if got := sorted(rep.Renamed); !reflect.DeepEqual(got, []string{"10", "11"}) {
		t.Fatalf("renamed = %v", got)
	}
	g := dbGroups(ctx, t, s)
	if g["10"] != "beta" || g["11"] != "alpha" {
		t.Fatalf("groups = %v", g)
	}
}

// TestPGSyncGroupsLldapCaseVariants: two lldap groups whose names differ only
// in case are both skipped (fail closed), never one arbitrarily chosen.
func TestPGSyncGroupsLldapCaseVariants(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	s.lldap = staticDir(lldap.Group{ID: 20, Name: "Ops"}, lldap.Group{ID: 21, Name: "ops"}, lldap.Group{ID: 22, Name: "Infra"})
	rep, err := s.SyncGroups(ctx)
	if err != nil {
		t.Fatalf("SyncGroups: %v", err)
	}
	if !reflect.DeepEqual(rep.Inserted, []string{"22"}) || len(rep.Skipped) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	g := dbGroups(ctx, t, s)
	if _, ok := g["20"]; ok {
		t.Fatalf("groups = %v: case variants must not land", g)
	}
}

// TestPGSyncGroupsLldapError: a directory failure aborts the sync without
// touching the table; a missing lldap client is an error, not a silent no-op.
func TestPGSyncGroupsLldapError(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	s.lldap = &fakeLldap{listGroups: func(context.Context) ([]lldap.Group, error) {
		return nil, errors.New("lldap down")
	}}
	if _, err := s.SyncGroups(ctx); err == nil {
		t.Fatal("want an error when lldap ListGroups fails")
	}
	if got := len(dbGroups(ctx, t, s)); got != 2 {
		t.Fatalf("groups rows = %d, want the 2 seeded", got)
	}
	s.lldap = nil
	if _, err := s.SyncGroups(ctx); err == nil {
		t.Fatal("want an error when lldap is not configured")
	}
}

func checkFirstSyncReport(t *testing.T, rep GroupSyncReport) {
	t.Helper()
	if !reflect.DeepEqual(rep.Inserted, []string{"7"}) {
		t.Errorf("inserted = %v, want [7]", rep.Inserted)
	}
	if !reflect.DeepEqual(rep.Renamed, []string{"9"}) {
		t.Errorf("renamed = %v, want [9]", rep.Renamed)
	}
	if rep.IgnoredBuiltin != 3 {
		t.Errorf("ignored built-ins = %d, want 3", rep.IgnoredBuiltin)
	}
	if len(rep.Skipped) != 1 || rep.Skipped[0].ID != "8" {
		t.Errorf("skipped = %+v, want only lldap group 8", rep.Skipped)
	}
	if got := sorted(rep.Orphans); !reflect.DeepEqual(got, []string{"group-platform", "group-security"}) {
		t.Errorf("orphans = %v", got)
	}
	if !reflect.DeepEqual(rep.ReferencedOrphans, []string{"group-platform"}) {
		t.Errorf("referenced orphans = %v, want [group-platform]", rep.ReferencedOrphans)
	}
}
