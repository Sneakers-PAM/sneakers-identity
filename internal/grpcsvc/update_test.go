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

// TestUpdateUserInputValidation covers the argument checks that short-circuit
// before any DB access, so they run without a Postgres (unit-safe).
func TestUpdateUserInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty user_id: want InvalidArgument, got %v", err)
	}
}
