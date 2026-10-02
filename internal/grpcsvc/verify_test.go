// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestVerificationEmailBody is the anti-typo guarantee: the verification
// email must lead with BOTH the username and the email so a misspelling
// ("ovance" for "pvance") is obvious, carry the code, and warn against verifying
// a wrong value.
func TestVerificationEmailBody(t *testing.T) {
	body := verificationEmailBody("pvance", "pvance@example.org", "123456")
	for _, want := range []string{"pvance", "pvance@example.org", "123456", "do NOT verify", "Username", "Email"} {
		if !strings.Contains(body, want) {
			t.Errorf("verification body missing %q\n---\n%s", want, body)
		}
	}
}

// TestVerifyInputValidation covers the argument checks that short-circuit before
// any DB access, so they run without a Postgres (unit-safe).
func TestVerifyInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.RequestEmailVerification(ctx, &identityv1.RequestEmailVerificationRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("RequestEmailVerification empty user_id: want InvalidArgument, got %v", err)
	}
	if _, err := s.ConfirmEmailVerification(ctx, &identityv1.ConfirmEmailVerificationRequest{UserId: "user-1"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("ConfirmEmailVerification empty code: want InvalidArgument, got %v", err)
	}
	if _, err := s.ConfirmEmailVerification(ctx, &identityv1.ConfirmEmailVerificationRequest{Code: "123456"}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("ConfirmEmailVerification no user_id/email: want InvalidArgument, got %v", err)
	}
}
