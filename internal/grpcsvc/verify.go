// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"strings"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Email verification confirms the email/username spelling, so a misspelled
// account is caught early: identity mints a single-use verify-purpose OTP
// (reusing the email-OTP store) and emails it in a body that prominently shows
// BOTH the username and the email, so the operator/user can spot a typo before
// trusting the account. Confirming the code marks the user email_verified.
// Login and admin are deliberately NOT gated on the flag (avoid lockout).

// verificationEmailBody is the plaintext body for the verification email. It
// leads with the username AND email precisely so a misspelling is obvious, and
// tells the reader NOT to verify if either is wrong.
func verificationEmailBody(username, email, code string) string {
	return "Confirm your Sneakers account details below, then enter the code to finish verifying.\n\n" +
		"    Username:  " + username + "\n" +
		"    Email:     " + email + "\n\n" +
		"Verification code:\n\n    " + code + "\n\n" +
		"If the username or email above is misspelled, do NOT verify — contact your administrator so it can be corrected.\n\n" +
		"This code expires in 5 minutes and can be used once. If you did not expect this email, you can ignore it."
}

// sendVerificationEmail mints a verify-purpose OTP for the user and emails it.
// Shared by the RequestEmailVerification RPC and the account-creation triggers
// (CreateLocalUser, BootstrapRoot). A nil sender (dev) still mints the code (and
// dev-echoes it); a send failure cancels the freshly-minted code so it neither
// lingers nor holds the re-issue cooldown. Callers that must not fail on a bad
// send (the triggers) invoke this best-effort and log the error.
func (s *Server) sendVerificationEmail(ctx context.Context, userID string) error {
	lg := log.Ctx(ctx)
	var username, email string
	if err := s.db.QueryRow(ctx, `SELECT username, email FROM users WHERE id=$1`, userID).Scan(&username, &email); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return status.Error(codes.NotFound, "user not found")
		}
		return status.Errorf(codes.Internal, "load user: %v", err)
	}
	if email == "" {
		return status.Error(codes.FailedPrecondition, "user has no email address")
	}
	code, otpID, cerr := s.createEmailOTP(ctx, userID, emailOTPPurposeVerify)
	if cerr != nil {
		if errors.Is(cerr, errOTPRateLimited) {
			return status.Error(codes.ResourceExhausted, "a verification code was sent recently; wait before requesting another")
		}
		return status.Errorf(codes.Internal, "create verification code: %v", cerr)
	}
	if s.devEcho {
		lg.Info().Str("email", email).Str("username", username).Str("otp_code", code).
			Msg("DEV: email-verification code (OTP_DEV_ECHO)")
	}
	if s.sender != nil {
		if serr := s.sender.Send(email, "Verify your Sneakers account", verificationEmailBody(username, email, code)); serr != nil {
			lg.Warn().Err(serr).Str("email", email).Msg("email verification: send failed")
			_ = s.cancelEmailOTP(ctx, otpID)
			return status.Error(codes.Unavailable, "could not send the verification email")
		}
	}
	return nil
}

// RequestEmailVerification mints + emails a verification code for the account.
// Keyed by the internal user_id and admin-gated at the gateway, so it surfaces
// the actionable NotFound / FailedPrecondition (no email) / ResourceExhausted
// (cooldown) / Unavailable (send failed) codes to the caller.
func (s *Server) RequestEmailVerification(ctx context.Context, req *identityv1.RequestEmailVerificationRequest) (*identityv1.RequestEmailVerificationResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if err := s.sendVerificationEmail(ctx, userID); err != nil {
		return nil, err
	}
	return &identityv1.RequestEmailVerificationResponse{}, nil
}

// ConfirmEmailVerification verifies a verify-purpose code (keyed by user_id, or
// by email when no id is supplied) and, on success, marks the user
// email_verified. ok=false covers a wrong/expired/consumed code and an unknown
// email alike (uniform answer — never leaks whether the account exists).
func (s *Server) ConfirmEmailVerification(ctx context.Context, req *identityv1.ConfirmEmailVerificationRequest) (*identityv1.ConfirmEmailVerificationResponse, error) {
	code := strings.TrimSpace(req.GetCode())
	if code == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		email := strings.TrimSpace(req.GetEmail())
		if email == "" {
			return nil, status.Error(codes.InvalidArgument, "user_id or email is required")
		}
		id, _, ok, err := s.resetUserByEmail(ctx, email)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "lookup: %v", err)
		}
		if !ok {
			return &identityv1.ConfirmEmailVerificationResponse{Ok: false}, nil // no leak
		}
		userID = id
	}
	verified, verr := s.verifyEmailOTP(ctx, userID, emailOTPPurposeVerify, code)
	if verr != nil {
		return nil, status.Errorf(codes.Internal, "verify code: %v", verr)
	}
	if !verified {
		return &identityv1.ConfirmEmailVerificationResponse{Ok: false}, nil
	}
	if _, err := s.db.Exec(ctx, `UPDATE users SET email_verified=true WHERE id=$1`, userID); err != nil {
		return nil, status.Errorf(codes.Internal, "mark verified: %v", err)
	}
	return &identityv1.ConfirmEmailVerificationResponse{Ok: true}, nil
}
