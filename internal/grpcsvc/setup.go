// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"strings"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// hasRootUser reports whether any user is already a root/site-admin — the
// no-root invariant that gates first-run setup. True once a user has is_root or
// carries the site-admin role.
func (s *Server) hasRootUser(ctx context.Context) (bool, error) {
	var exists bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE is_root = true OR 'site-admin' = ANY(roles))`).Scan(&exists)
	return exists, err
}

// GetSetupState reports whether the system still needs first-run setup: true
// when NO root/site-admin user exists yet. Unauthenticated — self-guards via the
// no-root invariant.
func (s *Server) GetSetupState(ctx context.Context, _ *identityv1.GetSetupStateRequest) (*identityv1.GetSetupStateResponse, error) {
	has, err := s.hasRootUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "setup state: %v", err)
	}
	return &identityv1.GetSetupStateResponse{NeedsSetup: !has}, nil
}

// BootstrapRoot creates the very first admin: a brand-new Kratos identity
// (email, name, password set) so they can sign in, plus the identity row
// marked is_root=true and granted the
// site-admin role. Self-guards on the no-root invariant (FailedPrecondition if a
// root/site-admin already exists) and on empty username/email/password
// (InvalidArgument).
func (s *Server) BootstrapRoot(ctx context.Context, req *identityv1.BootstrapRootRequest) (*identityv1.BootstrapRootResponse, error) {
	username := strings.TrimSpace(req.GetUsername())
	email := strings.TrimSpace(req.GetEmail())
	password := req.GetPassword()
	if username == "" || email == "" || password == "" {
		return nil, status.Error(codes.InvalidArgument, "username, email, password required")
	}

	has, err := s.hasRootUser(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "setup state: %v", err)
	}
	if has {
		return nil, status.Error(codes.FailedPrecondition, "a root user already exists")
	}
	if s.kratos == nil {
		return nil, status.Error(codes.Unavailable, "no user directory configured")
	}

	name := req.GetName()
	if name == "" {
		name = username
	}

	subject, rollback, err := s.provisionDirectoryUser(ctx, email, name, password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	// Create the identity row: is_root=true and the site-admin role (is_root on
	// its own confers no permissions — they derive from roles — so grant
	// site-admin too or the first /setup user is locked out of the admin console).
	// The subject is the new Kratos identity id, so the first login resolves
	// this row directly. The users_single_root_idx partial unique index is the atomic
	// backstop: a concurrent bootstrap racing this INSERT conflicts and is
	// reported as FailedPrecondition rather than a generic Internal error.
	id := "user-" + uuid.NewString()
	var newID string
	err = s.db.QueryRow(ctx,
		`INSERT INTO users (id, name, email, roles, is_root, subject, username)
		 VALUES ($1,$2,$3,$4,true,$5,$6)
		 RETURNING id`,
		id, name, email, []string{"site-admin"}, subject, username).Scan(&newID)
	if err != nil {
		rollback()
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.FailedPrecondition, "a root user already exists")
		}
		return nil, status.Errorf(codes.Internal, "pre-create root: %v", err)
	}

	u, err := s.getUserByID(ctx, newID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load created root: %v", err)
	}
	lg := s.lg(ctx)
	lg.Info("BootstrapRoot: first admin created", log.F("username", username), log.F("user_id", newID))
	s.record(ctx, audit.Event{
		Action: audit.ActionUserCreate, ActorUserID: newID, Subject: newID,
		Attributes: map[string]string{"source": "bootstrap", "username": username, "root": "true", "roles": "site-admin"},
	})
	// Email the first admin a verification code (username + email in the body)
	// so a typo in the bootstrap details is caught. Best-effort — never block setup.
	if verr := s.sendVerificationEmail(ctx, newID); verr != nil {
		lg.Warn("BootstrapRoot: verification email not sent", log.F("error", verr.Error()), log.F("user_id", newID))
	}
	return &identityv1.BootstrapRootResponse{User: u}, nil
}
