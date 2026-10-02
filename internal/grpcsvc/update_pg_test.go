// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// seedUser inserts a user row for the UpdateUser tests and returns its id.
func seedUser(t *testing.T, s *Server, id, name, email, username string, roles []string, isRoot bool) string {
	t.Helper()
	ctx := context.Background()
	if _, err := s.db.Exec(ctx,
		`INSERT INTO users (id, name, email, roles, is_root, keycloak_subject, username, email_verified)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,true)`,
		id, name, email, roles, isRoot, "kc-"+id, username); err != nil {
		t.Fatalf("insert user %s: %v", id, err)
	}
	return id
}

// TestPGUpdateUserNameEmail covers the safe path: a name/email edit updates the
// lldap user in place (displayName/mail) and the row, WITHOUT recreating the
// directory user, disturbing the password, or clearing email_verified.
func TestPGUpdateUserNameEmail(t *testing.T) {
	s := newPGServer(t)
	lc := &recLldap{}
	cap := &captureSender{}
	s.WithLldap(lc).WithEmail(cap, false)
	ctx := context.Background()

	id := seedUser(t, s, "user-edit-1", "Petra Vance", "pvance@example.org", "pvance", []string{"user"}, false)

	resp, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: id, Name: "Petra Q. Vance", Email: "petra.vance@example.org", Username: "pvance",
	})
	if err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if resp.GetUser().GetName() != "Petra Q. Vance" || resp.GetUser().GetEmail() != "petra.vance@example.org" {
		t.Errorf("unexpected updated user: %+v", resp.GetUser())
	}
	if resp.GetUser().GetUsername() != "pvance" {
		t.Errorf("username changed unexpectedly: %q", resp.GetUser().GetUsername())
	}
	if !resp.GetUser().GetEmailVerified() {
		t.Error("email_verified was cleared on a name/email-only edit")
	}
	if resp.GetUser().GetKeycloakSubject() != "kc-"+id {
		t.Errorf("keycloak_subject changed on a name/email-only edit: %q", resp.GetUser().GetKeycloakSubject())
	}
	if len(lc.updated) != 1 || lc.updated[0] != [3]string{"pvance", "Petra Q. Vance", "petra.vance@example.org"} {
		t.Errorf("lldap UpdateUser calls = %v, want one for pvance", lc.updated)
	}
	if len(lc.created) != 0 || len(lc.deleted) != 0 {
		t.Errorf("directory user was recreated on a safe edit: created=%v deleted=%v", lc.created, lc.deleted)
	}
	if cap.sent != 0 {
		t.Errorf("a password-reset/verify email was sent on a safe edit (sent=%d)", cap.sent)
	}
}

// TestPGUpdateUserRename covers the careful path: a username change recreates the
// lldap user (delete old + create new), preserves the row's id/roles/is_root,
// CLEARS keycloak_subject (so the row re-adopts by the new username on next
// login), flags email_verified=false, and triggers a password-reset email to the
// (new) address.
func TestPGUpdateUserRename(t *testing.T) {
	s := newPGServer(t)
	lc := &recLldap{}
	cap := &captureSender{}
	s.WithLldap(lc).WithEmail(cap, false)
	ctx := context.Background()

	// email unchanged -> exercises the delete-first ordering.
	id := seedUser(t, s, "user-edit-2", "Petra Vance", "pvance@example.org", "ovance",
		[]string{"user", "admin"}, false)

	resp, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: id, Name: "Petra Vance", Email: "pvance@example.org", Username: "pvance",
	})
	if err != nil {
		t.Fatalf("UpdateUser (rename): %v", err)
	}
	u := resp.GetUser()
	if u.GetUsername() != "pvance" {
		t.Errorf("username = %q, want pvance", u.GetUsername())
	}
	if u.GetEmailVerified() {
		t.Error("email_verified should be false after a username change")
	}
	if len(u.GetRoles()) != 2 {
		t.Errorf("roles not preserved: %v", u.GetRoles())
	}
	// keycloak_subject must be cleared on a rename: the recreated lldap user gets
	// a new entryUUID, so Keycloak mints a new subject on next login. A blank
	// subject makes the row re-adoptable by the new username (preserving roles);
	// keeping the old subject would provision a DUPLICATE row and lose them.
	if u.GetKeycloakSubject() != "" {
		t.Errorf("keycloak_subject = %q, want cleared after rename", u.GetKeycloakSubject())
	}

	// The cleared row re-adopts by the NEW username on next federated login,
	// stamping the fresh subject and preserving id/roles/is_root.
	assertReadoptsByUsername(t, s, id, "pvance", "pvance@example.org", "Petra Vance")

	// Directory: old deleted, new created.
	if len(lc.deleted) != 1 || lc.deleted[0] != "ovance" {
		t.Errorf("deleted = %v, want [ovance]", lc.deleted)
	}
	if len(lc.created) != 1 || lc.created[0] != "pvance" {
		t.Errorf("created = %v, want [pvance]", lc.created)
	}
	// Password reset triggered to the new email.
	if cap.sent != 1 || cap.to != "pvance@example.org" || cap.subject != "Reset your Sneakers password" {
		t.Errorf("reset email = {sent:%d to:%q subj:%q}, want one reset to pvance@example.org", cap.sent, cap.to, cap.subject)
	}
}

// TestPGUpdateUserRenameFreshEmail covers a username+email change to a free
// address: the create-first ordering still ends with old deleted + new created.
func TestPGUpdateUserRenameFreshEmail(t *testing.T) {
	s := newPGServer(t)
	lc := &recLldap{}
	cap := &captureSender{}
	s.WithLldap(lc).WithEmail(cap, false)
	ctx := context.Background()

	id := seedUser(t, s, "user-edit-3", "Bob", "bob@example.org", "bwrong", []string{"user"}, false)

	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: id, Name: "Bob Right", Email: "bright@example.org", Username: "bright",
	}); err != nil {
		t.Fatalf("UpdateUser (rename+email): %v", err)
	}
	if len(lc.created) != 1 || lc.created[0] != "bright" {
		t.Errorf("created = %v, want [bright]", lc.created)
	}
	if len(lc.deleted) != 1 || lc.deleted[0] != "bwrong" {
		t.Errorf("deleted = %v, want [bwrong]", lc.deleted)
	}
	if cap.sent != 1 || cap.to != "bright@example.org" {
		t.Errorf("reset email not sent to new address: sent=%d to=%q", cap.sent, cap.to)
	}
}

// TestPGUpdateUserUniqueness covers rejection of an email/username already used
// by ANOTHER user, and NotFound for an unknown id.
func TestPGUpdateUserUniqueness(t *testing.T) {
	s := newPGServer(t)
	lc := &recLldap{}
	s.WithLldap(lc)
	ctx := context.Background()

	a := seedUser(t, s, "user-a", "Alice", "alice@example.org", "alice", []string{"user"}, false)
	seedUser(t, s, "user-b", "Bob", "bob@example.org", "bob", []string{"user"}, false)

	// Take Bob's email.
	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: a, Name: "Alice", Email: "bob@example.org", Username: "alice",
	}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("email collision: want AlreadyExists, got %v", err)
	}
	// Take Bob's username.
	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: a, Name: "Alice", Email: "alice@example.org", Username: "bob",
	}); status.Code(err) != codes.AlreadyExists {
		t.Errorf("username collision: want AlreadyExists, got %v", err)
	}
	// Nothing should have touched the directory on a rejected update.
	if len(lc.created) != 0 || len(lc.deleted) != 0 || len(lc.updated) != 0 {
		t.Errorf("directory mutated on rejected update: %+v", lc)
	}

	// Unknown id.
	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: "user-missing", Name: "X", Email: "x@example.org", Username: "x",
	}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown id: want NotFound, got %v", err)
	}
}

// assertReadoptsByUsername verifies that a renamed row (keycloak_subject cleared)
// re-adopts by its new username on the next federated login — same row id, fresh
// subject stamped, roles preserved — rather than provisioning a duplicate.
func assertReadoptsByUsername(t *testing.T, s *Server, id, username, email, name string) {
	t.Helper()
	adopt, err := s.AdoptOrProvisionFederatedUser(context.Background(), &identityv1.AdoptOrProvisionFederatedUserRequest{
		KeycloakSubject:  "kc-new-sub",
		KeycloakUsername: username,
		Email:            email,
		Name:             name,
	})
	if err != nil {
		t.Fatalf("AdoptOrProvisionFederatedUser after rename: %v", err)
	}
	u := adopt.GetUser()
	if u.GetId() != id {
		t.Errorf("rename did not re-adopt the same row: got id %q, want %q (duplicate provisioned)", u.GetId(), id)
	}
	if u.GetKeycloakSubject() != "kc-new-sub" {
		t.Errorf("adopted row subject = %q, want kc-new-sub", u.GetKeycloakSubject())
	}
	if len(u.GetRoles()) != 2 {
		t.Errorf("roles lost on re-adopt: %v", u.GetRoles())
	}
}
