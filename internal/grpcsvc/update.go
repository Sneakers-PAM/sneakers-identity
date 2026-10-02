// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UpdateUser edits a user's profile — display name, email, and username.
// A misspelled account can be fixed in place instead of deleted and
// recreated. Name/email changes update the Kratos identity's traits and the
// identity row; a username change only touches the row, since Kratos signs
// users in by email. The password is never disturbed.
//
// The row's root/roles/subject are preserved on every path — a username change
// never strips is_root. Admin-gated at the gateway. Returns the updated user.
func (s *Server) UpdateUser(ctx context.Context, req *identityv1.UpdateUserRequest) (*identityv1.UpdateUserResponse, error) {
	in, cur, err := s.validateUpdateUser(ctx, req)
	if err != nil {
		return nil, err
	}
	if in.usernameChanged {
		return s.updateUserWithRename(ctx, cur, in)
	}
	return s.updateUserProfile(ctx, cur, in)
}

// updateUserInput holds the trimmed, validated inputs for UpdateUser.
type updateUserInput struct {
	id              string
	name            string
	email           string
	username        string
	usernameChanged bool
}

// validateUpdateUser loads the current user and validates the requested changes,
// keeping the branchy checks out of UpdateUser (gocyclo). It enforces: user
// exists; email non-empty + parseable + not taken by another user; a changed
// username is not an email and not taken by another user; name defaults to the
// (new) username when blank.
func (s *Server) validateUpdateUser(ctx context.Context, req *identityv1.UpdateUserRequest) (updateUserInput, *identityv1.User, error) {
	in := updateUserInput{
		id:       strings.TrimSpace(req.GetUserId()),
		name:     strings.TrimSpace(req.GetName()),
		email:    strings.TrimSpace(req.GetEmail()),
		username: strings.TrimSpace(req.GetUsername()),
	}
	if in.id == "" {
		return in, nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	cur, err := s.getUserByID(ctx, in.id)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return in, nil, status.Error(codes.NotFound, "user not found")
		}
		return in, nil, status.Errorf(codes.Internal, "load user: %v", err)
	}

	// A blank username means "leave the login handle unchanged".
	if in.username == "" {
		in.username = cur.GetUsername()
	}
	in.usernameChanged = in.username != cur.GetUsername()

	if in.email == "" {
		return in, nil, status.Error(codes.InvalidArgument, "email is required")
	}
	if _, perr := mail.ParseAddress(in.email); perr != nil {
		return in, nil, status.Error(codes.InvalidArgument, "email is not a valid address")
	}
	if in.usernameChanged && strings.Contains(in.username, "@") {
		return in, nil, status.Error(codes.InvalidArgument, "username must not be an email address")
	}
	if in.name == "" {
		in.name = in.username
	}

	if err := s.assertUpdateUnique(ctx, in); err != nil {
		return in, nil, err
	}
	return in, cur, nil
}

// assertUpdateUnique rejects an email already used by ANOTHER user, and (only on
// a username change) a username already used by another user.
func (s *Server) assertUpdateUnique(ctx context.Context, in updateUserInput) error {
	var taken bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE lower(email)=lower($1) AND id<>$2)`,
		in.email, in.id).Scan(&taken); err != nil {
		return status.Errorf(codes.Internal, "email uniqueness check: %v", err)
	}
	if taken {
		return status.Error(codes.AlreadyExists, "a user with that email already exists")
	}
	if in.usernameChanged {
		if err := s.db.QueryRow(ctx,
			`SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 AND id<>$2)`,
			in.username, in.id).Scan(&taken); err != nil {
			return status.Errorf(codes.Internal, "username uniqueness check: %v", err)
		}
		if taken {
			return status.Error(codes.AlreadyExists, "a user with that username already exists")
		}
	}
	return nil
}

// updateUserProfile is the name/email path. It updates the Kratos identity's
// traits then the identity row, leaving id/roles/subject/is_root and the
// password untouched.
func (s *Server) updateUserProfile(ctx context.Context, cur *identityv1.User, in updateUserInput) (*identityv1.UpdateUserResponse, error) {
	if err := s.updateDirectoryProfile(ctx, cur, in); err != nil {
		return nil, err
	}
	ct, err := s.db.Exec(ctx, `UPDATE users SET name=$2, email=$3 WHERE id=$1`, in.id, in.name, in.email)
	if err != nil {
		return nil, updateRowErr(err)
	}
	if ct.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	return s.loadUpdatedUser(ctx, in.id)
}

// updateUserWithRename is the username-change path. Kratos signs users in by
// email, so a new username needs no directory account of its own; the identity
// keeps its id and the row keeps its subject.
func (s *Server) updateUserWithRename(ctx context.Context, cur *identityv1.User, in updateUserInput) (*identityv1.UpdateUserResponse, error) {
	if err := s.updateDirectoryProfile(ctx, cur, in); err != nil {
		return nil, err
	}
	ct, err := s.db.Exec(ctx, `UPDATE users SET name=$2, email=$3, username=$4 WHERE id=$1`, in.id, in.name, in.email, in.username)
	if err != nil {
		return nil, updateRowErr(err)
	}
	if ct.RowsAffected() == 0 {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	return s.loadUpdatedUser(ctx, in.id)
}

// loadUpdatedUser re-reads the row after an update for the response.
func (s *Server) loadUpdatedUser(ctx context.Context, id string) (*identityv1.UpdateUserResponse, error) {
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load updated user: %v", err)
	}
	return &identityv1.UpdateUserResponse{User: u}, nil
}

// updateRowErr maps a unique-constraint violation to AlreadyExists and anything
// else to Internal.
func updateRowErr(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return status.Error(codes.AlreadyExists, "a user with that username or email already exists")
	}
	return status.Errorf(codes.Internal, "update user row: %v", err)
}

func (s *Server) updateDirectoryProfile(ctx context.Context, cur *identityv1.User, in updateUserInput) error {
	if s.kratos != nil && cur.GetSubject() != "" {
		if err := s.kratos.UpdateTraits(ctx, cur.GetSubject(), in.email, in.name); err != nil {
			return status.Errorf(codes.Internal, "kratos update identity: %v", err)
		}
	}
	return nil
}
