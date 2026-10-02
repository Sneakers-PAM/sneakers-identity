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

func setDisabled(ctx context.Context, t *testing.T, s *Server, userID string, disabled bool) *identityv1.User {
	t.Helper()
	resp, err := s.SetUserDisabled(ctx, &identityv1.SetUserDisabledRequest{UserId: userID, Disabled: disabled})
	if err != nil {
		t.Fatalf("SetUserDisabled(%s, %v): %v", userID, disabled, err)
	}
	return resp.GetUser()
}

func TestPGDisabledUserTokensStopVerifyingOnTheNextCall(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada", "group-security")
	token := mintUserToken(ctx, t, s, "u-ada").GetToken()

	if u := setDisabled(ctx, t, s, "u-ada", true); u.GetDisabledAtUnix() == 0 {
		t.Fatalf("disabled user = %+v, want disabled_at_unix set", u)
	}
	if got := verifyUserToken(ctx, t, s, token); got.GetValid() || got.GetUser() != nil {
		t.Fatalf("disabled user's token: want an empty invalid response, got %+v", got)
	}

	if u := setDisabled(ctx, t, s, "u-ada", false); u.GetDisabledAtUnix() != 0 {
		t.Fatalf("re-enabled user = %+v, want disabled_at_unix 0", u)
	}
	if !verifyUserToken(ctx, t, s, token).GetValid() {
		t.Fatal("re-enabling the user must restore their tokens")
	}
}

func TestPGDisabledStateIsVisibleOnTheUser(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	setDisabled(ctx, t, s, "u-ada", true)

	got, err := s.GetUser(ctx, &identityv1.GetUserRequest{Id: "u-ada"})
	if err != nil || got.GetUser().GetDisabledAtUnix() == 0 {
		t.Fatalf("GetUser = %+v, %v; want disabled_at_unix set", got, err)
	}
}

func TestPGDisabledUserCannotMintTokens(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	setDisabled(ctx, t, s, "u-ada", true)

	_, err := s.MintUserToken(ctx, &identityv1.MintUserTokenRequest{UserId: "u-ada", Label: "laptop"})
	if status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("mint for disabled user: want FailedPrecondition, got %v", err)
	}
}

func TestPGSetUserDisabledUnknownUser(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	_, err := s.SetUserDisabled(ctx, &identityv1.SetUserDisabledRequest{UserId: "u-nobody", Disabled: true})
	if status.Code(err) != codes.NotFound {
		t.Fatalf("disable unknown user: want NotFound, got %v", err)
	}
}
