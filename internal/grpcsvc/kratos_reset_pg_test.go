// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"

	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
)

func resetCodeFrom(t *testing.T, mail *fakeMailbox, to string) string {
	t.Helper()
	for i := len(mail.sent) - 1; i >= 0; i-- {
		if mail.sent[i].to == to {
			if c := sixDigits.FindString(mail.sent[i].body); c != "" {
				return c
			}
		}
	}
	t.Fatalf("no reset code emailed to %s", to)
	return ""
}

func seedKratosUser(ctx context.Context, t *testing.T, s *Server, id, email, subject string) {
	t.Helper()
	if _, err := s.db.Exec(ctx, `INSERT INTO users (id,name,email,roles,subject,username) VALUES ($1,'Ada',$2,'{user}',$3,'ada')`, id, email, subject); err != nil {
		t.Fatal(err)
	}
}

// The self-service reset is identity's own emailed code; under Kratos the
// verified reset sets the password on the user's Kratos identity.
func TestPGKratosPasswordResetSetsTheKratosPassword(t *testing.T) {
	ctx := context.Background()
	dir, mail := newFakeKratosDir(), &fakeMailbox{}
	s := newPGServer(t).WithKratos(dir).WithEmail(mail, false)
	seedKratosUser(ctx, t, s, "u-ada", "ada@example.org", "kid-ada")

	if _, err := s.RequestPasswordReset(ctx, &identityv1.RequestPasswordResetRequest{Email: "ada@example.org"}); err != nil {
		t.Fatal(err)
	}
	code := resetCodeFrom(t, mail, "ada@example.org")

	wrong, err := s.ConfirmPasswordReset(ctx, &identityv1.ConfirmPasswordResetRequest{Email: "ada@example.org", Code: "000000", NewPassword: "a-new-long-password"})
	if err != nil || wrong.GetOk() || dir.passwords["kid-ada"] != "" {
		t.Fatalf("wrong code: ok=%v err=%v password=%q", wrong.GetOk(), err, dir.passwords["kid-ada"])
	}
	ok, err := s.ConfirmPasswordReset(ctx, &identityv1.ConfirmPasswordResetRequest{Email: "ada@example.org", Code: code, NewPassword: "a-new-long-password"})
	if err != nil || !ok.GetOk() {
		t.Fatalf("right code: ok=%v err=%v", ok.GetOk(), err)
	}
	if dir.passwords["kid-ada"] != "a-new-long-password" {
		t.Fatalf("kratos password = %q, want it set on the user's identity", dir.passwords["kid-ada"])
	}
}

// The reset flow end to end against a real Kratos: request a reset,
// redeem the emailed code, then sign in through Kratos with the new password.
func TestPGRealKratosPasswordResetThenLogin(t *testing.T) {
	adminURL, publicURL := os.Getenv("KRATOS_TEST_ADMIN_URL"), os.Getenv("KRATOS_TEST_PUBLIC_URL")
	if adminURL == "" || publicURL == "" {
		t.Skip("set KRATOS_TEST_ADMIN_URL and KRATOS_TEST_PUBLIC_URL to run against a real Kratos")
	}
	ctx := context.Background()
	admin, mail := kratos.NewAdmin(adminURL), &fakeMailbox{}
	s := newPGServer(t).WithKratos(admin).WithEmail(mail, false)
	email := "reset-e2e@example.org"
	if old, err := admin.FindIdentityByEmail(ctx, email); err == nil {
		_ = admin.DeleteIdentity(ctx, old)
	}
	kid, err := admin.CreateIdentity(ctx, email, "Reset Ee")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.DeleteIdentity(context.Background(), kid) })
	seedKratosUser(ctx, t, s, "u-e2e", email, kid)

	if _, err := s.RequestPasswordReset(ctx, &identityv1.RequestPasswordResetRequest{Email: email}); err != nil {
		t.Fatal(err)
	}
	ok, err := s.ConfirmPasswordReset(ctx, &identityv1.ConfirmPasswordResetRequest{Email: email, Code: resetCodeFrom(t, mail, email), NewPassword: "sneakers-e2e-password"})
	if err != nil || !ok.GetOk() {
		t.Fatalf("ConfirmPasswordReset: ok=%v err=%v", ok.GetOk(), err)
	}
	if !kratosLogin(t, publicURL, email, "sneakers-e2e-password") {
		t.Fatal("the reset password must work for a Kratos sign-in")
	}
}

func kratosLogin(t *testing.T, public, identifier, password string) bool {
	t.Helper()
	res, err := http.Get(public + "/self-service/login/api")
	if err != nil {
		t.Fatal(err)
	}
	var flow struct{ ID string }
	_ = json.NewDecoder(res.Body).Decode(&flow)
	_ = res.Body.Close()
	body, _ := json.Marshal(map[string]string{"method": "password", "identifier": identifier, "password": password})
	res, err = http.Post(public+"/self-service/login?flow="+flow.ID, "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()
	return res.StatusCode == http.StatusOK
}
