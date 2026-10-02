// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"regexp"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

// captureSender is an email.Sender fake that records the last message so a test
// can read back the emailed verification code.
type captureSender struct {
	to, subject, body string
	sent              int
}

func (c *captureSender) Send(to, subject, body string) error {
	c.to, c.subject, c.body, c.sent = to, subject, body, c.sent+1
	return nil
}

var sixDigits = regexp.MustCompile(`\b\d{6}\b`)

// TestPGEmailVerificationRoundTrip exercises Request -> Confirm end to end
// against a real Postgres (skips without IDENTITY_PG_DSN): the emailed code
// confirms and flips users.email_verified; a wrong code returns ok=false and
// leaves the flag untouched.
func TestPGEmailVerificationRoundTrip(t *testing.T) {
	s := newPGServer(t)
	cap := &captureSender{}
	s.WithEmail(cap, false)
	ctx := context.Background()

	const id = "user-verify-1"
	if _, err := s.db.Exec(ctx,
		`INSERT INTO users (id, name, email, roles, subject, username)
		 VALUES ($1,$2,$3,$4,'',$5)`,
		id, "Petra Vance", "pvance@example.org", []string{}, "pvance"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	if _, err := s.RequestEmailVerification(ctx, &identityv1.RequestEmailVerificationRequest{UserId: id}); err != nil {
		t.Fatalf("RequestEmailVerification: %v", err)
	}
	if cap.sent != 1 {
		t.Fatalf("want 1 email sent, got %d", cap.sent)
	}
	if cap.subject != "Verify your Sneakers account" {
		t.Errorf("unexpected subject %q", cap.subject)
	}
	code := sixDigits.FindString(cap.body)
	if code == "" {
		t.Fatalf("no 6-digit code in email body:\n%s", cap.body)
	}

	// Wrong code: ok=false, flag stays false.
	resp, err := s.ConfirmEmailVerification(ctx, &identityv1.ConfirmEmailVerificationRequest{UserId: id, Code: "000000"})
	if err != nil {
		t.Fatalf("ConfirmEmailVerification (wrong): %v", err)
	}
	if resp.GetOk() {
		t.Error("wrong code unexpectedly verified")
	}
	if verified := emailVerified(t, s, id); verified {
		t.Error("email_verified set after a wrong code")
	}

	// A fresh, correct code confirms and flips the flag (re-request because the
	// wrong-code attempt is bounded but the original code is still live here).
	resp, err = s.ConfirmEmailVerification(ctx, &identityv1.ConfirmEmailVerificationRequest{UserId: id, Code: code})
	if err != nil {
		t.Fatalf("ConfirmEmailVerification (right): %v", err)
	}
	if !resp.GetOk() {
		t.Fatal("correct code did not verify")
	}
	if verified := emailVerified(t, s, id); !verified {
		t.Error("email_verified not set after a correct code")
	}

	// Confirm by email (no user_id) for an unknown address is a silent ok=false.
	resp, err = s.ConfirmEmailVerification(ctx, &identityv1.ConfirmEmailVerificationRequest{Email: "nobody@example.org", Code: code})
	if err != nil {
		t.Fatalf("ConfirmEmailVerification (unknown email): %v", err)
	}
	if resp.GetOk() {
		t.Error("unknown email unexpectedly verified")
	}
}

// emailVerified reads back the persisted flag; also proves the projection
// column resolves.
func emailVerified(t *testing.T, s *Server, id string) bool {
	t.Helper()
	u, err := s.getUserByID(context.Background(), id)
	if err != nil {
		t.Fatalf("getUserByID: %v", err)
	}
	return u.GetEmailVerified()
}
