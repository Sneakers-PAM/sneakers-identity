// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"math/big"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// MFA email OTP + generalized factor model. Email OTP is a
// single-use, short-lived numeric code delivered by email, stored ONLY as a
// sha256 hash in user_email_otp. Identity is the factor authority: it mints,
// hashes, rate-limits and verifies codes; the gateway BFF drives the send/verify
// during its 2-step login and enrollment flows.

// Factor kinds reported by ListUserFactors / accepted by RemoveFactor.
const (
	factorKindTotp    = "totp"
	factorKindEmail   = "email"
	factorKindPasskey = "passkey" // deferred
)

// Email-OTP purposes. Handlers validate against this closed set so the purpose
// column stays a controlled vocabulary and a code minted for one flow can never
// satisfy another.
const (
	emailOTPPurposeLogin  = "login"
	emailOTPPurposeEnroll = "enroll"
	emailOTPPurposeReset  = "reset"  // self-service password reset
	emailOTPPurposeVerify = "verify" // email/username confirmation
)

const (
	// emailOTPDigits is the numeric code length.
	emailOTPDigits = 6
	// emailOTPTTL is the code lifetime (5 min).
	emailOTPTTL = 5 * time.Minute
	// emailOTPCooldown is the minimum interval between issuing codes for the same
	// (user, purpose); a live code younger than this blocks re-issue.
	emailOTPCooldown = 30 * time.Second
	// emailOTPMaxAttempts caps wrong guesses; hitting the limit consumes the code.
	emailOTPMaxAttempts = 5
)

// emailOTPPurpose validates the request purpose against the closed vocabulary.
func emailOTPPurpose(p string) (string, error) {
	switch p {
	case emailOTPPurposeLogin, emailOTPPurposeEnroll:
		return p, nil
	default:
		return "", status.Errorf(codes.InvalidArgument, "unknown purpose %q", p)
	}
}

// SendEmailOtp mints a single-use 5-minute code for (user, purpose), stores only
// its hash, and emails it. Re-issue inside the cooldown window is
// ResourceExhausted; a user without an email is FailedPrecondition. When the send
// fails the freshly-minted challenge is cancelled so the failure does not hold
// the cooldown against the user.
func (s *Server) SendEmailOtp(ctx context.Context, req *identityv1.SendEmailOtpRequest) (*identityv1.SendEmailOtpResponse, error) {
	purpose, err := emailOTPPurpose(req.GetPurpose())
	if err != nil {
		return nil, err
	}
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	var email string
	if err := s.db.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).Scan(&email); err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "load user: %v", err)
	}
	if email == "" {
		return nil, status.Error(codes.FailedPrecondition, "user has no email address")
	}

	code, otpID, err := s.createEmailOTP(ctx, userID, purpose)
	if err != nil {
		if errors.Is(err, errOTPRateLimited) {
			return nil, status.Error(codes.ResourceExhausted, "a code was sent recently; wait before requesting another")
		}
		return nil, status.Errorf(codes.Internal, "create email otp: %v", err)
	}

	lg := s.lg(ctx)
	if s.devEcho {
		// Dev ergonomics; never enabled in prod (OTP_DEV_ECHO).
		lg.Info("DEV: one-time code (OTP_DEV_ECHO)", log.F("purpose", purpose), log.F("email", email), log.F("otp_code", code))
	}
	if s.sender != nil {
		body := "Use this code to verify your identity on Sneakers:\n\n    " + code +
			"\n\nThis code expires in 5 minutes and can be used once. If you did not request it, ignore this email."
		if serr := s.sender.Send(email, "Your Sneakers verification code", body); serr != nil {
			lg.Warn("mfa otp email send failed", log.F("error", serr.Error()), log.F("email", email))
			if cerr := s.cancelEmailOTP(ctx, otpID); cerr != nil {
				lg.Warn("cancel undeliverable mfa otp failed", log.F("error", cerr.Error()))
			}
			return nil, status.Error(codes.Unavailable, "could not send the verification email")
		}
	}
	return &identityv1.SendEmailOtpResponse{}, nil
}

// VerifyEmailOtp verifies an emailed code for (user, purpose). ok=false covers
// wrong/expired/consumed/attempt-locked codes alike (single-use, constant-time
// compare, lockout after repeated wrong guesses).
func (s *Server) VerifyEmailOtp(ctx context.Context, req *identityv1.VerifyEmailOtpRequest) (*identityv1.VerifyEmailOtpResponse, error) {
	purpose, err := emailOTPPurpose(req.GetPurpose())
	if err != nil {
		return nil, err
	}
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	if req.GetCode() == "" {
		return nil, status.Error(codes.InvalidArgument, "code is required")
	}
	ok, err := s.verifyEmailOTP(ctx, req.GetUserId(), purpose, req.GetCode())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verify email otp: %v", err)
	}
	s.recordMfaVerify(ctx, req.GetUserId(), factorKindEmail, purpose, ok)
	return &identityv1.VerifyEmailOtpResponse{Ok: ok}, nil
}

// ListUserFactors reports the factor kinds the user can currently satisfy:
// "totp" when a confirmed enrollment exists, "email" whenever the user has an
// email address (implicit fallback factor). Passkey is deferred.
func (s *Server) ListUserFactors(ctx context.Context, req *identityv1.ListUserFactorsRequest) (*identityv1.ListUserFactorsResponse, error) {
	userID := req.GetUserId()
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	var email string
	if err := s.db.QueryRow(ctx, `SELECT email FROM users WHERE id=$1`, userID).Scan(&email); err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "load user: %v", err)
	}

	factors := []*identityv1.UserFactor{}
	var confirmedAt *time.Time
	err := s.db.QueryRow(ctx,
		`SELECT confirmed_at FROM user_totp WHERE user_id=$1 AND confirmed_at IS NOT NULL`, userID).
		Scan(&confirmedAt)
	switch {
	case err == nil:
		factors = append(factors, &identityv1.UserFactor{
			Kind:       factorKindTotp,
			EnrolledAt: confirmedAt.UTC().Format(time.RFC3339),
		})
	case errors.Is(err, postgres.ErrNoRows):
		// no confirmed TOTP enrollment — fine
	default:
		return nil, status.Errorf(codes.Internal, "load totp: %v", err)
	}
	// Passkey: a strong factor. Offered when the user has ≥1 credential;
	// EnrolledAt = the earliest credential's creation.
	var pkAt *time.Time
	if perr := s.db.QueryRow(ctx, `SELECT min(created_at) FROM user_webauthn_credentials WHERE user_id=$1`, userID).Scan(&pkAt); perr == nil && pkAt != nil {
		factors = append(factors, &identityv1.UserFactor{Kind: factorKindPasskey, EnrolledAt: pkAt.UTC().Format(time.RFC3339)})
	}
	if email != "" {
		factors = append(factors, &identityv1.UserFactor{Kind: factorKindEmail})
	}
	return &identityv1.ListUserFactorsResponse{Factors: factors}, nil
}

// RemoveFactor deletes the user's credential for the given kind. "totp" removes
// the TOTP enrollment; "email" is implicit (derived from the address) and cannot
// be removed; "passkey" is deferred.
func (s *Server) RemoveFactor(ctx context.Context, req *identityv1.RemoveFactorRequest) (*identityv1.RemoveFactorResponse, error) {
	if req.GetUserId() == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	switch req.GetKind() {
	case factorKindTotp:
		tag, err := s.db.Exec(ctx, `DELETE FROM user_totp WHERE user_id=$1`, req.GetUserId())
		if err != nil {
			return nil, status.Errorf(codes.Internal, "remove totp: %v", err)
		}
		if tag.RowsAffected() == 0 {
			return nil, status.Error(codes.NotFound, "no totp enrollment to remove")
		}
		s.recordMfaRemove(ctx, req.GetActingUserId(), req.GetUserId(), factorKindTotp, nil)
		return &identityv1.RemoveFactorResponse{}, nil
	case factorKindEmail:
		return nil, status.Error(codes.FailedPrecondition, "the email factor is implicit and cannot be removed")
	case factorKindPasskey:
		return nil, status.Error(codes.Unimplemented, "passkey factor is not yet supported")
	default:
		return nil, status.Errorf(codes.InvalidArgument, "unknown factor kind %q", req.GetKind())
	}
}

// --- email OTP store helpers (inline SQL over the pool) ---

// errOTPRateLimited is returned by createEmailOTP when a live code younger than
// the cooldown already exists for (user, purpose).
var errOTPRateLimited = errors.New("email otp rate limited")

// createEmailOTP mints a fresh code for (userID, purpose), stores only its hash
// with a 5-minute TTL, and returns the plaintext (to email + dev-log) plus the
// row id (so a failed send can be cancelled). A live, unconsumed code younger
// than the cooldown blocks re-issue with errOTPRateLimited.
func (s *Server) createEmailOTP(ctx context.Context, userID, purpose string) (string, string, error) {
	var code, id string
	err := s.pg.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		// Prune dead rows so the table stays small and the cooldown query only ever
		// sees genuinely-live codes.
		if _, err := tx.Exec(ctx,
			`DELETE FROM user_email_otp
			  WHERE user_id=$1 AND purpose=$2
			    AND (consumed_at IS NOT NULL OR expires_at <= now())`,
			userID, purpose); err != nil {
			return err
		}

		// Cooldown: reject when the newest live code is younger than the window.
		var recent int
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM user_email_otp
			  WHERE user_id=$1 AND purpose=$2
			    AND created_at > now() - make_interval(secs => $3)`,
			userID, purpose, int(emailOTPCooldown.Seconds())).Scan(&recent); err != nil {
			return err
		}
		if recent > 0 {
			return errOTPRateLimited
		}

		var err error
		code, err = randomNumericCode(emailOTPDigits)
		if err != nil {
			return err
		}
		return tx.QueryRow(ctx,
			`INSERT INTO user_email_otp (user_id, purpose, code_hash, expires_at)
			 VALUES ($1, $2, $3, now() + make_interval(secs => $4))
			 RETURNING id`,
			userID, purpose, hashOTPCode(code), int(emailOTPTTL.Seconds())).Scan(&id)
	})
	if err != nil {
		return "", "", err
	}
	return code, id, nil
}

// cancelEmailOTP hard-deletes a freshly-minted challenge (used when the email
// send fails, so the failed attempt neither lingers as a live code nor holds the
// re-issue cooldown).
func (s *Server) cancelEmailOTP(ctx context.Context, id string) error {
	_, err := s.db.Exec(ctx, `DELETE FROM user_email_otp WHERE id=$1`, id)
	return err
}

// verifyEmailOTP checks a plaintext code against the newest live challenge for
// (userID, purpose). Success consumes the row (single-use) and returns true.
// Wrong/expired/consumed/attempt-locked all return (false, nil). Wrong guesses
// bump attempts; hitting the limit consumes the code. The compare is
// constant-time.
func (s *Server) verifyEmailOTP(ctx context.Context, userID, purpose, code string) (bool, error) {
	var ok bool
	err := s.pg.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		ok = false
		// Lock the newest candidate so concurrent verifies serialise on the attempts
		// counter and the single-use guarantee.
		var (
			id       string
			stored   string
			attempts int
		)
		err := tx.QueryRow(ctx,
			`SELECT id, code_hash, attempts FROM user_email_otp
			  WHERE user_id=$1 AND purpose=$2 AND consumed_at IS NULL AND expires_at > now()
			  ORDER BY created_at DESC
			  LIMIT 1
			  FOR UPDATE`,
			userID, purpose).Scan(&id, &stored, &attempts)
		if err != nil {
			if errors.Is(err, postgres.ErrNoRows) {
				return nil
			}
			return err
		}

		if attempts >= emailOTPMaxAttempts {
			// Already locked out; consume defensively and fail.
			_, err := tx.Exec(ctx, `UPDATE user_email_otp SET consumed_at=now() WHERE id=$1`, id)
			return err
		}

		if subtle.ConstantTimeCompare([]byte(hashOTPCode(code)), []byte(stored)) == 1 {
			if _, err := tx.Exec(ctx, `UPDATE user_email_otp SET consumed_at=now() WHERE id=$1`, id); err != nil {
				return err
			}
			ok = true
			return nil
		}

		// Wrong code: bump attempts; consume the row when this hits the limit so a
		// burned code cannot be retried further.
		newAttempts := attempts + 1
		if newAttempts >= emailOTPMaxAttempts {
			_, err = tx.Exec(ctx, `UPDATE user_email_otp SET attempts=$2, consumed_at=now() WHERE id=$1`, id, newAttempts)
		} else {
			_, err = tx.Exec(ctx, `UPDATE user_email_otp SET attempts=$2 WHERE id=$1`, id, newAttempts)
		}
		return err
	})
	if err != nil {
		return false, err
	}
	return ok, nil
}

// hashOTPCode returns the hex sha256 of a plaintext code (what we store at rest).
func hashOTPCode(code string) string {
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// randomNumericCode returns an n-digit numeric string using crypto/rand, with
// leading zeros preserved (so a 6-digit code is always exactly n chars).
func randomNumericCode(n int) (string, error) {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		d, err := rand.Int(rand.Reader, big.NewInt(10))
		if err != nil {
			return "", err
		}
		digit := d.Int64()         // bounded to [0,9] by big.NewInt(10) above
		buf[i] = byte('0' + digit) // #nosec G115 -- digit in [0,9], so '0'+digit is in [48,57], well within byte range
	}
	return string(buf), nil
}
