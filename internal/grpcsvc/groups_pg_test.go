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

// TestPGGroupsNameUniqueCaseInsensitive: the schema forbids two groups
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

// TestPGCreateGroupRejectsCaseInsensitiveDuplicate: a name that already exists
// in identity (any case) is AlreadyExists and no second row is written.
func TestPGCreateGroupRejectsCaseInsensitiveDuplicate(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t).WithKratos(newFakeKratosDir())
	_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "security"})
	if status.Code(err) != codes.AlreadyExists {
		t.Fatalf("code = %v, want AlreadyExists", status.Code(err))
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM groups WHERE lower(name)='security'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("security groups = %d (err %v), want 1", n, err)
	}
}

func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}
