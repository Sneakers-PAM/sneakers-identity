// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"os"
	"slices"
	"strings"
	"testing"

	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5"
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
	pool := db.Pool()
	for _, q := range []string{
		`TRUNCATE group_membership RESTART IDENTITY CASCADE`,
		`TRUNCATE api_tokens, service_accounts CASCADE`,
		`DELETE FROM users`,
		`DELETE FROM groups`,
		`INSERT INTO groups (id,name) VALUES ('group-platform','Platform Team'),('group-security','Security')`,
	} {
		if _, err := pool.Exec(ctx, q); err != nil {
			t.Fatalf("reset (%s): %v", q, err)
		}
	}
	return New(pool)
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
	if pc.GetUser().GetKeycloakSubject() != "" {
		t.Fatalf("pre-created user should have empty subject, got %q", pc.GetUser().GetKeycloakSubject())
	}
	preID := pc.GetUser().GetId()

	// Adopt: email matches (case-insensitive) → subject stamped onto same row.
	ad := adopt(t, s, "kc-sub-ada", "ada.lovelace@example.org", "Ada L.")
	if ad != preID {
		t.Fatalf("adopt should reuse pre-created row %s, got %s", preID, ad)
	}

	// Re-login resolves by subject (no new row).
	if again := adopt(t, s, "kc-sub-ada", "ada.lovelace@example.org", "Ada L."); again != preID {
		t.Fatalf("re-login should resolve to %s, got %s", preID, again)
	}

	// Provision: unknown subject + unmatched email → fresh user.
	graceID := adopt(t, s, "kc-sub-grace", "grace.hopper@example.org", "Grace Hopper")
	if graceID == preID {
		t.Fatal("provision should create a new user, not reuse the adopted row")
	}

	got, err := s.GetUserByKeycloakSubject(ctx, &identityv1.GetUserByKeycloakSubjectRequest{KeycloakSubject: "kc-sub-grace"})
	if err != nil || got.GetUser().GetId() != graceID {
		t.Fatalf("GetUserByKeycloakSubject: got %v err %v", got, err)
	}
}

// TestPGMembership covers idempotent add + the two membership read projections.
func TestPGMembership(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")

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
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")
	for _, g := range []string{"group-platform", "group-security"} {
		if _, err := s.AddGroupMember(ctx, &identityv1.AddGroupMemberRequest{UserId: id, GroupId: g}); err != nil {
			t.Fatalf("AddGroupMember(%s): %v", g, err)
		}
	}
	// The retired claim-sync write path must not be able to add groups.
	if _, err := s.SetUserAdGroups(ctx, &identityv1.SetUserAdGroupsRequest{UserId: id, Names: []string{"CN=Vault-Admins"}}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("SetUserAdGroups code = %v (err %v), want Unimplemented", status.Code(err), err)
	}

	rc, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{KeycloakSubject: "kc-sub-ada"})
	if err != nil || rc.GetUser().GetId() != id {
		t.Fatalf("ResolveUserContext: got %v err %v", rc, err)
	}
	if got, want := rc.GetGroupNames(), []string{"Platform Team", "Security"}; !slices.Equal(got, want) {
		t.Fatalf("effective group names = %v, want %v", got, want)
	}

	if _, err := s.RemoveGroupMember(ctx, &identityv1.RemoveGroupMemberRequest{UserId: id, GroupId: "group-security"}); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	rc, err = s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{KeycloakSubject: "kc-sub-ada"})
	if err != nil {
		t.Fatalf("ResolveUserContext after remove: %v", err)
	}
	if got, want := rc.GetGroupNames(), []string{"Platform Team"}; !slices.Equal(got, want) {
		t.Fatalf("effective group names after remove = %v, want %v", got, want)
	}
}

// TestPGDropUserAdGroupsMigrationGuard pins the AD-group drop migration: it drops the
// retired user_ad_groups table only when it is empty, and aborts loudly (no
// schema change) when any row exists.
func TestPGDropUserAdGroupsMigrationGuard(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	if tableExists(t, s.db, "user_ad_groups") {
		t.Fatal("user_ad_groups should be gone after migrate")
	}
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")

	t.Run("empty table is dropped", func(t *testing.T) {
		tx := recreateAdGroupsTable(t, s, "")
		if _, err := tx.Exec(ctx, readMigration(t, "0008_drop_user_ad_groups.up.sql")); err != nil {
			t.Fatalf("migration on empty table: %v", err)
		}
		if tableExists(t, tx, "user_ad_groups") {
			t.Fatal("table still exists after migration")
		}
	})
	t.Run("non-empty table aborts", func(t *testing.T) {
		tx := recreateAdGroupsTable(t, s, id)
		_, err := tx.Exec(ctx, readMigration(t, "0008_drop_user_ad_groups.up.sql"))
		if err == nil || !strings.Contains(err.Error(), "user_ad_groups is not empty") {
			t.Fatalf("migration on non-empty table: err = %v, want guard failure", err)
		}
	})
}

// recreateAdGroupsTable opens a transaction (rolled back at test end, so the
// migrated schema is untouched) holding the pre-0008 user_ad_groups table, with
// one row for rowUserID when it is non-empty.
func recreateAdGroupsTable(t *testing.T, s *Server, rowUserID string) pgx.Tx {
	t.Helper()
	ctx := context.Background()
	tx, err := s.db.Begin(ctx)
	if err != nil {
		t.Fatalf("begin: %v", err)
	}
	t.Cleanup(func() { _ = tx.Rollback(ctx) })
	if _, err := tx.Exec(ctx, readMigration(t, "0008_drop_user_ad_groups.down.sql")); err != nil {
		t.Fatalf("recreate table: %v", err)
	}
	if rowUserID != "" {
		if _, err := tx.Exec(ctx, `INSERT INTO public.user_ad_groups (user_id, ad_group_name) VALUES ($1, 'CN=SOC')`, rowUserID); err != nil {
			t.Fatalf("insert row: %v", err)
		}
	}
	return tx
}

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../migrations/" + name)
	if err != nil {
		t.Fatalf("read migration %s: %v", name, err)
	}
	return string(b)
}

func tableExists(t *testing.T, q interface {
	QueryRow(context.Context, string, ...any) pgx.Row
}, table string) bool {
	t.Helper()
	var exists bool
	if err := q.QueryRow(context.Background(), `SELECT to_regclass('public.' || $1) IS NOT NULL`, table).Scan(&exists); err != nil {
		t.Fatalf("to_regclass(%s): %v", table, err)
	}
	return exists
}

// adopt runs AdoptOrProvisionFederatedUser and returns the resolved user id.
func adopt(t *testing.T, s *Server, sub, email, name string) string {
	t.Helper()
	resp, err := s.AdoptOrProvisionFederatedUser(context.Background(), &identityv1.AdoptOrProvisionFederatedUserRequest{
		KeycloakSubject: sub, Email: email, Name: name,
	})
	if err != nil {
		t.Fatalf("AdoptOrProvisionFederatedUser(%s): %v", sub, err)
	}
	return resp.GetUser().GetId()
}
