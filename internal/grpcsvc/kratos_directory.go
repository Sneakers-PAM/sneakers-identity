// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
)

type kratosDirectory interface {
	CreateIdentity(ctx context.Context, email, name string) (string, error)
	FindIdentityByEmail(ctx context.Context, email string) (string, error)
}

type kratosAdmin interface {
	kratosDirectory
	SetPassword(ctx context.Context, id, password string) error
	UpdateTraits(ctx context.Context, id, email, name string) error
	DeleteIdentity(ctx context.Context, id string) error
}

// WithKratos makes Kratos the credential directory: users are provisioned as
// Kratos identities, their row stores the identity id as the login subject,
// and groups live only in identity.
func (s *Server) WithKratos(k kratosAdmin) *Server {
	s.kratos = k
	return s
}

// provisionKratos returns the identity id to store as the user's subject so
// their first Kratos login adopts this row directly.
func (s *Server) provisionKratos(ctx context.Context, email, name, password string) (string, error) {
	id, err := s.kratos.CreateIdentity(ctx, email, name)
	if err != nil {
		return "", fmt.Errorf("kratos create identity: %w", err)
	}
	if err := s.kratos.SetPassword(ctx, id, password); err != nil {
		_ = s.kratos.DeleteIdentity(ctx, id)
		return "", fmt.Errorf("kratos set password: %w", err)
	}
	return id, nil
}
