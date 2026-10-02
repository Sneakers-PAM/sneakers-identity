// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"slices"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newPGServer connects to the live Postgres named by IDENTITY_PG_DSN (skips the
// test when unset), migrates, resets to a clean slate and seeds two groups.
//
//	IDENTITY_PG_DSN=postgres://identity@localhost:5432/identity?sslmode=disable \
//	  go test ./internal/grpcsvc -run TestPG -v
func newPGServer(t *testing.T) *Server {
	t.Helper()
	dsn := os.Getenv("IDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set IDENTITY_PG_DSN to run the Postgres integration test")
	}
	if err := postgres.Migrate(dsn, "../../migrations"); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)
	for _, q := range []string{
		`TRUNCATE group_membership RESTART IDENTITY CASCADE`,
		`TRUNCATE api_tokens, service_accounts CASCADE`,
		`DELETE FROM users`,
		`DELETE FROM groups`,
		`INSERT INTO groups (id,name) VALUES ('group-platform','Platform Team'),('group-security','Security')`,
	} {
		if _, err := db.Querier().Exec(ctx, q); err != nil {
			t.Fatalf("reset (%s): %v", q, err)
		}
	}
	return New(db)
}

// TestPGProvisioning covers pre-create → adopt-on-login → provision and the
// subject/idempotency guarantees of the login path.
func TestPGProvisioning(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)

	pc, err := s.PreCreateLocalUser(ctx, &identityv1.PreCreateLocalUserRequest{
		Email: "Ada.Lovelace@example.org", Name: "Ada Lovelace", Roles: []string{"user"},
	})
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	if pc.GetUser().GetSubject() != "" {
		t.Fatalf("pre-created user should have empty subject, got %q", pc.GetUser().GetSubject())
	}
	preID := pc.GetUser().GetId()

	// Adopt: email matches (case-insensitive) → subject stamped onto same row.
	ad := adopt(t, s, "sub-ada", "ada.lovelace@example.org", "Ada L.")
	if ad != preID {
		t.Fatalf("adopt should reuse pre-created row %s, got %s", preID, ad)
	}

	// Re-login resolves by subject (no new row).
	if again := adopt(t, s, "sub-ada", "ada.lovelace@example.org", "Ada L."); again != preID {
		t.Fatalf("re-login should resolve to %s, got %s", preID, again)
	}

	// Provision: unknown subject + unmatched email → fresh user.
	graceID := adopt(t, s, "sub-grace", "grace.hopper@example.org", "Grace Hopper")
	if graceID == preID {
		t.Fatal("provision should create a new user, not reuse the adopted row")
	}

	got, err := s.GetUserBySubject(ctx, &identityv1.GetUserBySubjectRequest{Subject: "sub-grace"})
	if err != nil || got.GetUser().GetId() != graceID {
		t.Fatalf("GetUserBySubject: got %v err %v", got, err)
	}
}

// TestPGMembership covers idempotent add + the two membership read projections.
func TestPGMembership(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	id := adopt(t, s, "sub-ada", "ada@example.org", "Ada")

	for i := 0; i < 2; i++ { // second call must be a no-op
		if _, err := s.AddGroupMember(ctx, &identityv1.AddGroupMemberRequest{UserId: id, GroupId: "group-platform"}); err != nil {
			t.Fatalf("AddGroupMember #%d: %v", i, err)
		}
	}
	members, err := s.ListGroupMembers(ctx, &identityv1.ListGroupMembersRequest{GroupId: "group-platform"})
	if err != nil || len(members.GetUsers()) != 1 || members.GetUsers()[0].GetId() != id {
		t.Fatalf("ListGroupMembers: got %v err %v", members, err)
	}
	groups, err := s.ListUserGroups(ctx, &identityv1.ListUserGroupsRequest{UserId: id})
	if err != nil || len(groups.GetGroups()) != 1 || groups.GetGroups()[0].GetId() != "group-platform" {
		t.Fatalf("ListUserGroups: got %v err %v", groups, err)
	}
}

// TestPGResolveUserContextDirectoryOnly pins the AD-group retirement: the effective group names are
// exactly the user's group_membership (managed in the Sneakers admin UI), never
// anything derived from federation claims.
//
//nolint:staticcheck // SA1019: asserts the deprecated SetUserAdGroups stays Unimplemented.
func TestPGResolveUserContextDirectoryOnly(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	id := adopt(t, s, "sub-ada", "ada@example.org", "Ada")
	for _, g := range []string{"group-platform", "group-security"} {
		if _, err := s.AddGroupMember(ctx, &identityv1.AddGroupMemberRequest{UserId: id, GroupId: g}); err != nil {
			t.Fatalf("AddGroupMember(%s): %v", g, err)
		}
	}
	// The retired claim-sync write path must not be able to add groups.
	if _, err := s.SetUserAdGroups(ctx, &identityv1.SetUserAdGroupsRequest{UserId: id, Names: []string{"CN=Example-Admins"}}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("SetUserAdGroups code = %v (err %v), want Unimplemented", status.Code(err), err)
	}

	rc, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{Subject: "sub-ada"})
	if err != nil || rc.GetUser().GetId() != id {
		t.Fatalf("ResolveUserContext: got %v err %v", rc, err)
	}
	if got, want := rc.GetGroupNames(), []string{"Platform Team", "Security"}; !slices.Equal(got, want) {
		t.Fatalf("effective group names = %v, want %v", got, want)
	}

	if _, err := s.RemoveGroupMember(ctx, &identityv1.RemoveGroupMemberRequest{UserId: id, GroupId: "group-security"}); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	rc, err = s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{Subject: "sub-ada"})
	if err != nil {
		t.Fatalf("ResolveUserContext after remove: %v", err)
	}
	if got, want := rc.GetGroupNames(), []string{"Platform Team"}; !slices.Equal(got, want) {
		t.Fatalf("effective group names after remove = %v, want %v", got, want)
	}
}

// adopt runs AdoptOrProvisionFederatedUser and returns the resolved user id.
func adopt(t *testing.T, s *Server, sub, email, name string) string {
	t.Helper()
	resp, err := s.AdoptOrProvisionFederatedUser(context.Background(), &identityv1.AdoptOrProvisionFederatedUserRequest{
		Subject: sub, Email: email, Name: name,
	})
	if err != nil {
		t.Fatalf("AdoptOrProvisionFederatedUser(%s): %v", sub, err)
	}
	return resp.GetUser().GetId()
}
