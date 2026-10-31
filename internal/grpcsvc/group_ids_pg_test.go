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

// A pre-provisioned SSO user has no login subject, so the gateway's session
// names them by user id and gets the same context as a subject lookup.
func TestPGResolveUserContextByUserID(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security")
	if _, err := s.db.Exec(ctx, `UPDATE users SET subject='' WHERE id='u-ada'`); err != nil {
		t.Fatal(err)
	}

	got, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{UserId: "u-ada"})
	if err != nil {
		t.Fatalf("ResolveUserContext: %v", err)
	}
	if got.GetUser().GetId() != "u-ada" || !slices.Equal(got.GetGroupIds(), []string{"group-security"}) {
		t.Fatalf("got user %q groups %v", got.GetUser().GetId(), got.GetGroupIds())
	}
}

func TestPGResolveUserContextKeysDontCross(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	sub := mustSubject(ctx, t, s, "u-ada")

	for name, tc := range map[string]struct {
		req  *identityv1.ResolveUserContextRequest
		want codes.Code
	}{
		"a user id is not a subject": {&identityv1.ResolveUserContextRequest{Subject: "u-ada"}, codes.NotFound},
		"a subject is not a user id": {&identityv1.ResolveUserContextRequest{UserId: sub}, codes.NotFound},
		"both":                       {&identityv1.ResolveUserContextRequest{Subject: sub, UserId: "u-ada"}, codes.InvalidArgument},
		"neither":                    {&identityv1.ResolveUserContextRequest{}, codes.InvalidArgument},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := s.ResolveUserContext(ctx, tc.req); status.Code(err) != tc.want {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}
