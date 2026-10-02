// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Self-service password reset. "Our login only, never Keycloak": identity
// mints/emails/verifies a reset code, then sets the new password in lldap (which
// Keycloak federates, so the lldap password IS the login password). Never routes
// through Keycloak admin. Keyed by email since the user is unauthenticated.

const minResetPasswordLen = 8

// resetUserByEmail resolves an email to (id, username); ok=false when no such
// user. Callers must NOT leak that distinction to the client.
func (s *Server) resetUserByEmail(ctx context.Context, email string) (id, username string, ok bool, err error) {
	err = s.db.QueryRow(ctx, `SELECT id, username FROM users WHERE lower(email)=lower($1) ORDER BY id LIMIT 1`, email).Scan(&id, &username)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", false, nil
	}
	if err != nil {
		return "", "", false, err
	}
	return id, username, true, nil
}

// RequestPasswordReset mints + emails a reset code for the account. It ALWAYS
// returns an empty success — an unknown email, a rate-limited re-issue, or a send
// failure all look identical to the caller, so the endpoint never reveals whether
// an account exists.
func (s *Server) RequestPasswordReset(ctx context.Context, req *identityv1.RequestPasswordResetRequest) (*identityv1.RequestPasswordResetResponse, error) {
	email := req.GetEmail()
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	lg := log.Ctx(ctx)
	id, _, ok, err := s.resetUserByEmail(ctx, email)
	if err != nil {
		lg.Warn().Err(err).Msg("password reset: lookup failed")
		return &identityv1.RequestPasswordResetResponse{}, nil // fail closed, no leak
	}
	if !ok {
		return &identityv1.RequestPasswordResetResponse{}, nil // unknown email → silent
	}
	code, otpID, cerr := s.createEmailOTP(ctx, id, emailOTPPurposeReset)
	if cerr != nil {
		// Rate-limited or otherwise — stay silent so the cooldown/existence never leaks.
		lg.Info().Err(cerr).Msg("password reset: code not issued")
		return &identityv1.RequestPasswordResetResponse{}, nil
	}
	if s.devEcho {
		lg.Info().Str("email", email).Str("otp_code", code).Msg("DEV: password-reset code (OTP_DEV_ECHO)")
	}
	if s.sender != nil {
		body := "Use this code to reset your Sneakers password:\n\n    " + code +
			"\n\nThis code expires in 5 minutes and can be used once. If you did not request a reset, ignore this email."
		if serr := s.sender.Send(email, "Reset your Sneakers password", body); serr != nil {
			lg.Warn().Err(serr).Msg("password reset: email send failed")
			_ = s.cancelEmailOTP(ctx, otpID)
		}
	}
	return &identityv1.RequestPasswordResetResponse{}, nil
}

// ConfirmPasswordReset verifies the reset code and, on success, sets the new
// password in lldap. ok=false covers a wrong/expired code or an unknown email
// alike (uniform answer). Requires the lldap write client (else Unavailable).
func (s *Server) ConfirmPasswordReset(ctx context.Context, req *identityv1.ConfirmPasswordResetRequest) (*identityv1.ConfirmPasswordResetResponse, error) {
	if req.GetEmail() == "" || req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "email and code are required")
	}
	if len(req.GetNewPassword()) < minResetPasswordLen {
		return nil, status.Errorf(codes.InvalidArgument, "password must be at least %d characters", minResetPasswordLen)
	}
	if s.lldap == nil && s.kratos == nil {
		return nil, status.Error(codes.Unavailable, "password reset not configured")
	}
	id, username, ok, err := s.resetUserByEmail(ctx, req.GetEmail())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "lookup: %v", err)
	}
	if !ok {
		return &identityv1.ConfirmPasswordResetResponse{Ok: false}, nil // no leak
	}
	verified, verr := s.verifyEmailOTP(ctx, id, emailOTPPurposeReset, req.GetCode())
	if verr != nil {
		return nil, status.Errorf(codes.Internal, "verify code: %v", verr)
	}
	if !verified {
		return &identityv1.ConfirmPasswordResetResponse{Ok: false}, nil
	}
	if serr := s.setDirectoryPassword(ctx, id, username, req.GetEmail(), req.GetNewPassword()); serr != nil {
		return nil, status.Errorf(codes.Internal, "set password: %v", serr)
	}
	return &identityv1.ConfirmPasswordResetResponse{Ok: true}, nil
}

// setDirectoryPassword writes the new password where the login backend reads
// it: the user's Kratos identity (their stored subject, or found by email if the
// row was never re-keyed) or, before the cutover, lldap.
func (s *Server) setDirectoryPassword(ctx context.Context, userID, username, email, password string) error {
	if s.kratos == nil {
		return s.lldap.SetPassword(ctx, username, password)
	}
	var subject string
	if err := s.db.QueryRow(ctx, `SELECT keycloak_subject FROM users WHERE id=$1`, userID).Scan(&subject); err != nil {
		return err
	}
	if subject == "" {
		found, err := s.kratos.FindIdentityByEmail(ctx, email)
		if err != nil {
			return err
		}
		subject = found
	}
	return s.kratos.SetPassword(ctx, subject, password)
}
