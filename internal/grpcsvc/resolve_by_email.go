// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"strings"

	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ResolveUserByEmail is a pure lookup — no adopt, no create, no side effects.
// Case-insensitive exact match on email (via getUserByEmail, shared with
// resetUserByEmail's normalization). Returns NotFound when no user matches so
// the gateway SSO callback can enforce no-JIT (reject unknown federated
// emails). Deliberately distinct from AdoptOrProvisionFederatedUser, which
// creates-on-miss for the Keycloak/Kratos JIT callers.
func (s *Server) ResolveUserByEmail(ctx context.Context, req *identityv1.ResolveUserByEmailRequest) (*identityv1.ResolveUserByEmailResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}

	u, err := s.getUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "no user for email")
		}
		return nil, status.Errorf(codes.Internal, "resolve user by email: %v", err)
	}
	return &identityv1.ResolveUserByEmailResponse{User: u}, nil
}
