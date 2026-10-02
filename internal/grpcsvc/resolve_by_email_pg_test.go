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

// TestPGResolveUserByEmail covers the pure no-JIT lookup end to end against a
// real Postgres (skips without IDENTITY_PG_DSN, via newPGServer): an existing
// user resolves by case-insensitive email match, an unknown email is
// codes.NotFound, and the miss never inserts a row.
func TestPGResolveUserByEmail(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)

	const id = "usr-sso-1"
	if _, err := s.db.Exec(ctx,
		`INSERT INTO users (id, name, email, roles, is_root, keycloak_subject, username)
		 VALUES ($1,$2,$3,$4,false,'',$5)`,
		id, "Ada Lovelace", "ada@example.org", []string{"user"}, "ada"); err != nil {
		t.Fatalf("seed: %v", err)
	}

	resp, err := s.ResolveUserByEmail(ctx, &identityv1.ResolveUserByEmailRequest{Email: "ADA@Example.org"})
	if err != nil {
		t.Fatalf("ResolveUserByEmail: %v", err)
	}
	if resp.GetUser().GetId() != id || resp.GetUser().GetEmail() != "ada@example.org" {
		t.Fatalf("wrong user: %+v", resp.GetUser())
	}

	if _, err := s.ResolveUserByEmail(ctx, &identityv1.ResolveUserByEmailRequest{Email: "nobody@example.org"}); status.Code(err) != codes.NotFound {
		t.Fatalf("unknown email: want NotFound, got %v", err)
	}

	// A miss must never create a row (pure lookup, no JIT).
	var count int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users WHERE lower(email)=lower($1)`, "nobody@example.org").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Fatalf("miss must not create a user row, found %d", count)
	}
}
