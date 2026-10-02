// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/secrets"
	"github.com/pquerna/otp/totp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// newMFAServer is newPGServer wired with an at-rest cipher so the TOTP RPCs are
// enabled. Skips (via newPGServer) when IDENTITY_PG_DSN is unset.
func newMFAServer(t *testing.T) *Server {
	t.Helper()
	cipher, err := secrets.NewFromString(strings.Repeat("a", 64)) // 32 bytes hex
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return newPGServer(t).WithCipher(cipher)
}

// mfaStatus is a small helper reading GetMfaStatus.Enrolled.
func mfaStatus(t *testing.T, s *Server, id string) bool {
	t.Helper()
	st, err := s.GetMfaStatus(context.Background(), &identityv1.GetMfaStatusRequest{UserId: id})
	if err != nil {
		t.Fatalf("GetMfaStatus: %v", err)
	}
	return st.GetEnrolled()
}

// enrollAndConfirm enrolls TOTP and confirms it with a generated code, returning
// the base32 secret. Fails the test on any step error.
func enrollAndConfirm(t *testing.T, s *Server, id string) string {
	t.Helper()
	ctx := context.Background()
	enroll, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: id})
	if err != nil {
		t.Fatalf("EnrollTotp: %v", err)
	}
	code, err := totp.GenerateCode(enroll.GetSecret(), time.Now())
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	if _, err := s.ConfirmTotp(ctx, &identityv1.ConfirmTotpRequest{UserId: id, Code: code}); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	return enroll.GetSecret()
}

// TestPGTotpEnrollAndConfirm covers enroll → (pending, not enrolled, unverifiable)
// → wrong confirm rejected → correct confirm → enrolled. Exercises the real
// encrypt-at-rest path (secret sealed on enroll, opened on confirm/verify).
func TestPGTotpEnrollAndConfirm(t *testing.T) {
	ctx := context.Background()
	s := newMFAServer(t)
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")

	if mfaStatus(t, s, id) {
		t.Fatal("fresh user must not be enrolled")
	}
	enroll, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: id})
	if err != nil {
		t.Fatalf("EnrollTotp: %v", err)
	}
	if enroll.GetSecret() == "" || !strings.HasPrefix(enroll.GetOtpauthUri(), "otpauth://totp/") {
		t.Fatalf("enroll response missing secret/otpauth: %+v", enroll)
	}
	// Pending (unconfirmed) does NOT count as enrolled, and cannot verify yet.
	if mfaStatus(t, s, id) {
		t.Fatal("pending enrollment must not report enrolled")
	}
	code, _ := totp.GenerateCode(enroll.GetSecret(), time.Now())
	if vr, _ := s.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: id, Code: code}); vr.GetOk() {
		t.Fatal("verify must fail against a pending (unconfirmed) enrollment")
	}
	if _, err := s.ConfirmTotp(ctx, &identityv1.ConfirmTotpRequest{UserId: id, Code: "000000"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("ConfirmTotp wrong code: want InvalidArgument, got %v", err)
	}
	if _, err := s.ConfirmTotp(ctx, &identityv1.ConfirmTotpRequest{UserId: id, Code: code}); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	if !mfaStatus(t, s, id) {
		t.Fatal("confirmed enrollment must report enrolled")
	}
}

// TestPGTotpVerifyAndReEnrollGuard covers verify against a confirmed secret
// (right + wrong code) and the guard against silently replacing a confirmed
// factor.
func TestPGTotpVerifyAndReEnrollGuard(t *testing.T) {
	ctx := context.Background()
	s := newMFAServer(t)
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")
	secret := enrollAndConfirm(t, s, id)

	code, _ := totp.GenerateCode(secret, time.Now())
	if vr, err := s.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: id, Code: code}); err != nil || !vr.GetOk() {
		t.Fatalf("VerifyTotp confirmed: ok=%v err=%v", vr.GetOk(), err)
	}
	if vr, _ := s.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: id, Code: "000000"}); vr.GetOk() {
		t.Fatal("VerifyTotp must reject a wrong code")
	}
	if _, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: id}); status.Code(err) != codes.AlreadyExists {
		t.Fatalf("re-enroll of confirmed factor: want AlreadyExists, got %v", err)
	}
}

// TestPGTotpDisable covers disable → not enrolled → re-enroll succeeds.
func TestPGTotpDisable(t *testing.T) {
	ctx := context.Background()
	s := newMFAServer(t)
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")
	enrollAndConfirm(t, s, id)

	if _, err := s.DisableTotp(ctx, &identityv1.DisableTotpRequest{UserId: id}); err != nil {
		t.Fatalf("DisableTotp: %v", err)
	}
	if mfaStatus(t, s, id) {
		t.Fatal("disabled factor must not report enrolled")
	}
	if _, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: id}); err != nil {
		t.Fatalf("re-enroll after disable: %v", err)
	}
}

// TestPGTotpNoCipherUnavailable: without a cipher the TOTP RPCs fail closed
// (Unavailable) rather than storing secrets in the clear.
func TestPGTotpNoCipherUnavailable(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t) // no WithCipher
	id := adopt(t, s, "kc-sub-ada", "ada@example.org", "Ada")
	if _, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: id}); status.Code(err) != codes.Unavailable {
		t.Fatalf("EnrollTotp without cipher: want Unavailable, got %v", err)
	}
	// GetMfaStatus does not need the cipher and stays available.
	if mfaStatus(t, s, id) {
		t.Fatal("status without enrollment must be false")
	}
}
