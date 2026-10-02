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
		`INSERT INTO users (id, name, email, roles, is_root, subject, username, email_verified)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,true)`,
		id, name, email, roles, isRoot, "kc-"+id, username); err != nil {
		t.Fatalf("insert user %s: %v", id, err)
	}
	return id
}

// TestPGUpdateUserUniqueness covers rejection of an email/username already used
// by ANOTHER user, and NotFound for an unknown id.
func TestPGUpdateUserUniqueness(t *testing.T) {
	dir := newFakeKratosDir()
	s := newPGServer(t).WithKratos(dir)
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
	if len(dir.traits) != 0 || len(dir.deleted) != 0 {
		t.Errorf("directory mutated on rejected update: traits %v, deleted %v", dir.traits, dir.deleted)
	}

	// Unknown id.
	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{
		UserId: "user-missing", Name: "X", Email: "x@example.org", Username: "x",
	}); status.Code(err) != codes.NotFound {
		t.Errorf("unknown id: want NotFound, got %v", err)
	}
}
