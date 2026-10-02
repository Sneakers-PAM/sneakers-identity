// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// The group ids come back next to the names, pair for pair, so the vault can
// match a group rule by id.
func TestPGResolveUserContextReturnsGroupIDs(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security", "group-platform")
	seedTokenUser(ctx, t, s, "u-grace")
	sub := mustSubject(ctx, t, s, "u-ada")

	got, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{Subject: sub})
	if err != nil {
		t.Fatalf("ResolveUserContext: %v", err)
	}
	if want := []string{"Platform Team", "Security"}; !slices.Equal(got.GetGroupNames(), want) {
		t.Fatalf("group_names = %v, want %v", got.GetGroupNames(), want)
	}
	if want := []string{"group-platform", "group-security"}; !slices.Equal(got.GetGroupIds(), want) {
		t.Fatalf("group_ids = %v, want %v", got.GetGroupIds(), want)
	}

	none, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{Subject: mustSubject(ctx, t, s, "u-grace")})
	if err != nil {
		t.Fatalf("ResolveUserContext (no groups): %v", err)
	}
	if len(none.GetGroupNames()) != 0 || len(none.GetGroupIds()) != 0 {
		t.Fatalf("a user with no groups got names %v ids %v", none.GetGroupNames(), none.GetGroupIds())
	}
}

func TestPGVerifyUserTokenReturnsGroupIDs(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security", "group-platform")
	seedTokenUser(ctx, t, s, "u-grace")

	got := verifyUserToken(ctx, t, s, mintUserToken(ctx, t, s, "u-ada").GetToken())
	if want := []string{"Platform Team", "Security"}; !slices.Equal(got.GetGroupNames(), want) {
		t.Fatalf("group_names = %v, want %v", got.GetGroupNames(), want)
	}
	if want := []string{"group-platform", "group-security"}; !slices.Equal(got.GetGroupIds(), want) {
		t.Fatalf("group_ids = %v, want %v", got.GetGroupIds(), want)
	}
	none := verifyUserToken(ctx, t, s, mintUserToken(ctx, t, s, "u-grace").GetToken())
	if !none.GetValid() || len(none.GetGroupIds()) != 0 {
		t.Fatalf("a user with no groups: %+v", none)
	}
}
