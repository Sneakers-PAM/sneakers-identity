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

func TestCreateGroup(t *testing.T) {
	ctx := context.Background()

	t.Run("empty name is InvalidArgument", func(t *testing.T) {
		s := &Server{kratos: newFakeKratosDir()}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "   "})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})

	t.Run("no directory is Unavailable", func(t *testing.T) {
		s := &Server{}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "ops"})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})
}
