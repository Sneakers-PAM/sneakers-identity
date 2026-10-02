// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// UpdateUser edits a user's profile — display name, email, and username.
// A misspelled account can be fixed in place instead of deleted and
// recreated. Two paths:
//
//   - name/email only (safe): update the lldap user's displayName/mail and the
//     identity row. The password is never disturbed.
//   - username change (careful): lldap cannot rename a uid in place, so the
//     directory user is deleted + recreated under the new username. That drops
//     the password, so the identity row keeps its id/roles/is_root but is flagged
//     email_verified=false, has keycloak_subject cleared (the recreated lldap
//     user gets a new Keycloak subject on next login — clearing lets the row
//     re-adopt by the new username instead of a duplicate being provisioned), and
//     a password-reset email is triggered to the (new) address.
//
// The row's root/roles are preserved on every path — a username change never
// strips is_root. Admin-gated at the gateway. Returns the updated user.
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

// updateUserProfile is the safe path: name/email only. It updates the lldap
// user's displayName/mail (when the client is configured) then the identity row,
// leaving id/roles/keycloak_subject/is_root and the password untouched.
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

// updateUserWithRename is the careful path: the lldap uid is immutable, so the
// directory user is recreated under the new username. Ordering is chosen to stay
// fail-closed against lldap's email-uniqueness constraint:
//
//   - when the email is also changing to a free address, create the new lldap
//     user first, then update the row, then delete the old lldap user — so a
//     create failure leaves the row untouched;
//   - when the email is unchanged, the new user would collide with the old one's
//     address, so the old lldap user is deleted first, then the new one created
//     (with a best-effort restore of the old on failure).
//
// On success the recreated user has no password, so the row is flagged
// email_verified=false and a password-reset email is triggered.
func (s *Server) updateUserWithRename(ctx context.Context, cur *identityv1.User, in updateUserInput) (*identityv1.UpdateUserResponse, error) {
	if s.kratos != nil {
		// Kratos logs users in by email, so a new username needs no directory
		// account of its own; the identity keeps its id and the row keeps its subject.
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
	if s.lldap == nil {
		return nil, status.Error(codes.Unavailable, "lldap admin not configured")
	}
	lg := s.lg(ctx)

	if !strings.EqualFold(in.email, cur.GetEmail()) {
		// New email is free: create-first keeps the row-update fail-closed.
		if err := s.lldap.CreateUser(ctx, in.username, in.email, in.name); err != nil {
			return nil, status.Errorf(codes.Internal, "lldap create user (rename): %v", err)
		}
		if err := s.renameUserRow(ctx, in); err != nil {
			_ = s.lldap.DeleteUser(ctx, in.username) // roll back the new directory user
			return nil, err
		}
		if derr := s.lldap.DeleteUser(ctx, cur.GetUsername()); derr != nil {
			lg.Warn("update user: old lldap user not deleted after rename (orphaned)", log.F("error", derr.Error()), log.F("old_username", cur.GetUsername()))
		}
	} else {
		// Email unchanged: delete-first to avoid the lldap email-uniqueness clash.
		if err := s.lldap.DeleteUser(ctx, cur.GetUsername()); err != nil {
			return nil, status.Errorf(codes.Internal, "lldap delete user (rename): %v", err)
		}
		if err := s.lldap.CreateUser(ctx, in.username, in.email, in.name); err != nil {
			_ = s.lldap.CreateUser(ctx, cur.GetUsername(), cur.GetEmail(), cur.GetName()) // best-effort restore
			return nil, status.Errorf(codes.Internal, "lldap create user (rename): %v", err)
		}
		if err := s.renameUserRow(ctx, in); err != nil {
			_ = s.lldap.DeleteUser(ctx, in.username)
			_ = s.lldap.CreateUser(ctx, cur.GetUsername(), cur.GetEmail(), cur.GetName())
			return nil, err
		}
	}

	// The recreated directory user has no password: force a reset so the user can
	// set one (best-effort — never fail the update on a send error).
	if _, rerr := s.RequestPasswordReset(ctx, &identityv1.RequestPasswordResetRequest{Email: in.email}); rerr != nil {
		lg.Warn("update user: password-reset email not sent after rename", log.F("error", rerr.Error()), log.F("user_id", in.id))
	}
	return s.loadUpdatedUser(ctx, in.id)
}

// renameUserRow updates the identity row for a username change, preserving
// id/roles/is_root and flagging the account unverified (the recreated lldap user
// must re-establish a password + confirm the email). It also clears
// keycloak_subject: recreating the lldap user gives it a new entryUUID, so
// Keycloak mints a NEW subject on the user's next login. Keeping the OLD subject
// would leave the row un-adoptable (AdoptOrProvisionFederatedUser only adopts
// keycloak_subject=” rows), which would provision a DUPLICATE row and lose the
// user's roles/groups. Blanking it makes the row re-adopt by the new username on
// next login, preserving roles/is_root.
func (s *Server) renameUserRow(ctx context.Context, in updateUserInput) error {
	ct, err := s.db.Exec(ctx,
		`UPDATE users SET name=$2, email=$3, username=$4, email_verified=false, keycloak_subject='' WHERE id=$1`,
		in.id, in.name, in.email, in.username)
	if err != nil {
		return updateRowErr(err)
	}
	if ct.RowsAffected() == 0 {
		return status.Error(codes.NotFound, "user not found")
	}
	return nil
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
	switch {
	case s.kratos != nil && cur.GetKeycloakSubject() != "":
		if err := s.kratos.UpdateTraits(ctx, cur.GetKeycloakSubject(), in.email, in.name); err != nil {
			return status.Errorf(codes.Internal, "kratos update identity: %v", err)
		}
	case s.kratos == nil && s.lldap != nil:
		if err := s.lldap.UpdateUser(ctx, cur.GetUsername(), in.name, in.email); err != nil {
			return status.Errorf(codes.Internal, "lldap update user: %v", err)
		}
	}
	return nil
}
