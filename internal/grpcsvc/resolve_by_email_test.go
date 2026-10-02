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

// TestResolveUserByEmailInputValidation covers the argument check that
// short-circuits before any DB access, so it runs without a Postgres
// (unit-safe) — mirrors TestUpdateUserInputValidation.
func TestResolveUserByEmailInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.ResolveUserByEmail(ctx, &identityv1.ResolveUserByEmailRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty email: want InvalidArgument, got %v", err)
	}
	if _, err := s.ResolveUserByEmail(ctx, &identityv1.ResolveUserByEmailRequest{Email: "   "}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("blank email: want InvalidArgument, got %v", err)
	}
}
