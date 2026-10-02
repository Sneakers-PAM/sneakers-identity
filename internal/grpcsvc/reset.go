// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Self-service password reset: identity mints/emails/verifies a reset code, then
// sets the new password on the user's Kratos identity. Keyed by email since the
// user is unauthenticated.

const minResetPasswordLen = 8

// resetUserByEmail resolves an email to (id, username); ok=false when no such
// user. Callers must NOT leak that distinction to the client.
func (s *Server) resetUserByEmail(ctx context.Context, email string) (id, username string, ok bool, err error) {
	err = s.db.QueryRow(ctx, `SELECT id, username FROM users WHERE lower(email)=lower($1) ORDER BY id LIMIT 1`, email).Scan(&id, &username)
	if errors.Is(err, postgres.ErrNoRows) {
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
	lg := s.lg(ctx)
	id, _, ok, err := s.resetUserByEmail(ctx, email)
	if err != nil {
		lg.Warn("password reset: lookup failed", log.F("error", err.Error()))
		return &identityv1.RequestPasswordResetResponse{}, nil // fail closed, no leak
	}
	if !ok {
		return &identityv1.RequestPasswordResetResponse{}, nil // unknown email → silent
	}
	code, otpID, cerr := s.createEmailOTP(ctx, id, emailOTPPurposeReset)
	if cerr != nil {
		// Rate-limited or otherwise — stay silent so the cooldown/existence never leaks.
		lg.Info("password reset: code not issued", log.F("error", cerr.Error()))
		return &identityv1.RequestPasswordResetResponse{}, nil
	}
	if s.devEcho {
		lg.Info("DEV: password-reset code (OTP_DEV_ECHO)", log.F("email", email), log.F("otp_code", code))
	}
	if s.sender != nil {
		body := "Use this code to reset your Sneakers password:\n\n    " + code +
			"\n\nThis code expires in 5 minutes and can be used once. If you did not request a reset, ignore this email."
		if serr := s.sender.Send(email, "Reset your Sneakers password", body); serr != nil {
			lg.Warn("password reset: email send failed", log.F("error", serr.Error()))
			_ = s.cancelEmailOTP(ctx, otpID)
		}
	}
	return &identityv1.RequestPasswordResetResponse{}, nil
}

// ConfirmPasswordReset verifies the reset code and, on success, sets the new
// password on the user's Kratos identity. ok=false covers a wrong/expired code
// or an unknown email alike (uniform answer). Requires Kratos (else Unavailable).
func (s *Server) ConfirmPasswordReset(ctx context.Context, req *identityv1.ConfirmPasswordResetRequest) (*identityv1.ConfirmPasswordResetResponse, error) {
	if req.GetEmail() == "" || req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "email and code are required")
	}
	if len(req.GetNewPassword()) < minResetPasswordLen {
		return nil, status.Errorf(codes.InvalidArgument, "password must be at least %d characters", minResetPasswordLen)
	}
	if s.kratos == nil {
		return nil, status.Error(codes.Unavailable, "password reset not configured")
	}
	id, _, ok, err := s.resetUserByEmail(ctx, req.GetEmail())
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
		s.recordPasswordReset(ctx, id, false)
		return &identityv1.ConfirmPasswordResetResponse{Ok: false}, nil
	}
	if serr := s.setDirectoryPassword(ctx, id, req.GetEmail(), req.GetNewPassword()); serr != nil {
		return nil, status.Errorf(codes.Internal, "set password: %v", serr)
	}
	s.recordPasswordReset(ctx, id, true)
	return &identityv1.ConfirmPasswordResetResponse{Ok: true}, nil
}

func (s *Server) recordPasswordReset(ctx context.Context, userID string, ok bool) {
	s.record(ctx, audit.Event{
		Action: audit.ActionPasswordReset, ActorUserID: userID, Subject: userID,
		Attributes: map[string]string{"outcome": outcome(ok)},
	})
}

// setDirectoryPassword writes the new password on the user's Kratos identity:
// their stored subject, or the identity found by email when the row has no
// subject yet.
func (s *Server) setDirectoryPassword(ctx context.Context, userID, email, password string) error {
	var subject string
	if err := s.db.QueryRow(ctx, `SELECT subject FROM users WHERE id=$1`, userID).Scan(&subject); err != nil {
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
