// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MFA TOTP second factor. Identity is the factor authority: it
// owns the encrypted shared secret (user_totp) and performs all code
// verification. The gateway BFF drives EnrollTotp/ConfirmTotp for the authed
// user and GetMfaStatus + VerifyTotp for the 2-step login. All RPCs are keyed
// by the platform user_id.

// defaultTotpIssuer is the authenticator-app issuer label when TOTP_ISSUER is
// unset (prod uses the bare product name).
const defaultTotpIssuer = "Sneakers"

// effectiveTotpIssuer resolves the configured issuer label, falling back to the
// bare product name. Non-prod stacks set TOTP_ISSUER (e.g. "Sneakers (local)")
// so authenticator entries don't collide across environments.
func (s *Server) effectiveTotpIssuer() string {
	if s.totpIssuer != "" {
		return s.totpIssuer
	}
	return defaultTotpIssuer
}

// totpEnabled returns the at-rest cipher, or Unavailable when TOTP is not
// configured (no TOTP_ENC_KEY). Fail-closed: with no cipher no secret can be
// sealed or opened, so the factor cannot be enrolled or verified.
func (s *Server) totpEnabled() error {
	if s.cipher == nil {
		return status.Error(codes.Unavailable, "totp not configured")
	}
	return nil
}

// totpAccount resolves the authenticator-app account label (email, else name,
// else id) and confirms the user exists. NotFound when the id maps to no user.
func (s *Server) totpAccount(ctx context.Context, userID string) (string, error) {
	var email, name string
	err := s.db.QueryRow(ctx, `SELECT email, name FROM users WHERE id=$1`, userID).Scan(&email, &name)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", status.Error(codes.NotFound, "user not found")
		}
		return "", status.Errorf(codes.Internal, "load user: %v", err)
	}
	switch {
	case email != "":
		return email, nil
	case name != "":
		return name, nil
	default:
		return userID, nil
	}
}

// EnrollTotp mints a fresh TOTP secret for the user, stores it encrypted and
// UNCONFIRMED, and returns the base32 secret + otpauth:// URI for the
// authenticator app / QR. A confirmed enrollment is never replaced
// (AlreadyExists — DisableTotp first); a pending one is restarted.
func (s *Server) EnrollTotp(ctx context.Context, req *identityv1.EnrollTotpRequest) (*identityv1.EnrollTotpResponse, error) {
	if err := s.totpEnabled(); err != nil {
		return nil, err
	}
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	account, err := s.totpAccount(ctx, userID)
	if err != nil {
		return nil, err
	}
	key, err := totp.Generate(totp.GenerateOpts{Issuer: s.effectiveTotpIssuer(), AccountName: account})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate totp secret: %v", err)
	}
	sealed, err := s.cipher.Seal(key.Secret())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "seal totp secret: %v", err)
	}
	// Replace a PENDING row (restarted enrollment); protect a CONFIRMED one so an
	// active factor can never be silently swapped without an explicit DisableTotp.
	tag, err := s.db.Exec(ctx,
		`INSERT INTO user_totp (user_id, encrypted_secret)
		 VALUES ($1, $2)
		 ON CONFLICT (user_id) DO UPDATE
		    SET encrypted_secret = EXCLUDED.encrypted_secret,
		        confirmed_at     = NULL,
		        updated_at       = now()
		  WHERE user_totp.confirmed_at IS NULL`,
		userID, sealed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "upsert pending totp: %v", err)
	}
	if tag.RowsAffected() == 0 {
		return nil, status.Error(codes.AlreadyExists, "totp already enrolled; disable it first")
	}
	return &identityv1.EnrollTotpResponse{
		Secret:     key.Secret(),
		OtpauthUri: key.URL(),
	}, nil
}

// ConfirmTotp proves possession of the pending secret with a current code
// (RFC 6238 defaults, ±1 period skew) and activates the enrollment. A wrong
// code is InvalidArgument; no pending enrollment is FailedPrecondition. An
// already-confirmed enrollment is idempotent success.
func (s *Server) ConfirmTotp(ctx context.Context, req *identityv1.ConfirmTotpRequest) (*identityv1.ConfirmTotpResponse, error) {
	if err := s.totpEnabled(); err != nil {
		return nil, err
	}
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	var (
		sealed      string
		confirmedAt *time.Time
	)
	err := s.db.QueryRow(ctx,
		`SELECT encrypted_secret, confirmed_at FROM user_totp WHERE user_id=$1`, userID).
		Scan(&sealed, &confirmedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.FailedPrecondition, "no totp enrollment in progress")
		}
		return nil, status.Errorf(codes.Internal, "load totp: %v", err)
	}
	if confirmedAt != nil {
		return &identityv1.ConfirmTotpResponse{}, nil // already active — idempotent
	}
	secret, err := s.cipher.Open(sealed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open totp secret: %v", err)
	}
	if !totp.Validate(req.GetCode(), secret) {
		return nil, status.Error(codes.InvalidArgument, "invalid code")
	}
	if _, err := s.db.Exec(ctx,
		`UPDATE user_totp SET confirmed_at=now(), updated_at=now() WHERE user_id=$1`, userID); err != nil {
		return nil, status.Errorf(codes.Internal, "confirm totp: %v", err)
	}
	return &identityv1.ConfirmTotpResponse{}, nil
}

// VerifyTotp checks a code against the user's CONFIRMED secret (the login step).
// ok=false covers a wrong code, a pending-only enrollment, and no enrollment
// alike — never distinguishing them to the caller.
func (s *Server) VerifyTotp(ctx context.Context, req *identityv1.VerifyTotpRequest) (*identityv1.VerifyTotpResponse, error) {
	if err := s.totpEnabled(); err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	var (
		sealed      string
		confirmedAt *time.Time
	)
	err := s.db.QueryRow(ctx,
		`SELECT encrypted_secret, confirmed_at FROM user_totp WHERE user_id=$1`, req.GetUserId()).
		Scan(&sealed, &confirmedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &identityv1.VerifyTotpResponse{Ok: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "load totp: %v", err)
	}
	if confirmedAt == nil {
		return &identityv1.VerifyTotpResponse{Ok: false}, nil
	}
	secret, err := s.cipher.Open(sealed)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "open totp secret: %v", err)
	}
	return &identityv1.VerifyTotpResponse{Ok: totp.Validate(req.GetCode(), secret)}, nil
}

// GetMfaStatus reports whether the user has a CONFIRMED TOTP factor. It does not
// require the cipher (it inspects only confirmed_at), so the BFF can always
// consult it to decide whether a login owes a second factor.
func (s *Server) GetMfaStatus(ctx context.Context, req *identityv1.GetMfaStatusRequest) (*identityv1.GetMfaStatusResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	// Enrolled if the user has a confirmed TOTP factor OR a passkey — either
	// is a strong second factor.
	var enrolled bool
	err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM user_totp WHERE user_id=$1 AND confirmed_at IS NOT NULL)
		     OR EXISTS(SELECT 1 FROM user_webauthn_credentials WHERE user_id=$1)`,
		req.GetUserId()).Scan(&enrolled)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mfa status: %v", err)
	}
	return &identityv1.GetMfaStatusResponse{Enrolled: enrolled}, nil
}

// DisableTotp removes the user's TOTP factor (pending or confirmed). Idempotent:
// removing a non-existent factor is a success (no NotFound), so a re-enroll
// after DisableTotp always succeeds.
func (s *Server) DisableTotp(ctx context.Context, req *identityv1.DisableTotpRequest) (*identityv1.DisableTotpResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if _, err := s.db.Exec(ctx, `DELETE FROM user_totp WHERE user_id=$1`, req.GetUserId()); err != nil {
		return nil, status.Errorf(codes.Internal, "disable totp: %v", err)
	}
	return &identityv1.DisableTotpResponse{}, nil
}
