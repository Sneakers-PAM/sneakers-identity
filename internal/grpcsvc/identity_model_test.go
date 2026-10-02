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

// TestPrefixCols is a pure-logic check that the JOIN-aliased projection stays in
// lock-step with userCols (same columns, prefixed with the table alias).
func TestPrefixCols(t *testing.T) {
	got := prefixCols("u")
	want := "u.id, u.name, u.email, u.roles, u.is_root, u.subject, u.username, u.email_verified, u.disabled_at"
	if got != want {
		t.Fatalf("prefixCols(u) = %q, want %q", got, want)
	}
}

// TestRetiredAdGroupRPCs pins the AD-group retirement: group membership is managed
// only in the Sneakers admin UI, so the AD-claim sync write path is
// Unimplemented and the deprecated readers always return an empty result. None
// of them touch the database (the server here has no pool).
//
//nolint:staticcheck // SA1019: exercises the deprecated RPCs.
func TestRetiredAdGroupRPCs(t *testing.T) {
	ctx := context.Background()
	s := New(nil)

	_, err := s.SetUserAdGroups(ctx, &identityv1.SetUserAdGroupsRequest{UserId: "u1", Names: []string{"CN=Example-Admins"}})
	if status.Code(err) != codes.Unimplemented {
		t.Fatalf("SetUserAdGroups code = %v (err %v), want Unimplemented", status.Code(err), err)
	}

	uag, err := s.UserAdGroups(ctx, &identityv1.UserAdGroupsRequest{UserId: "u1"})
	if err != nil || len(uag.GetNames()) != 0 {
		t.Fatalf("UserAdGroups = %v err %v, want empty", uag, err)
	}
	byAd, err := s.ListUsersByAdGroups(ctx, &identityv1.ListUsersByAdGroupsRequest{Names: []string{"CN=Example-Admins"}})
	if err != nil || len(byAd.GetUsers()) != 0 {
		t.Fatalf("ListUsersByAdGroups = %v err %v, want empty", byAd, err)
	}
}
