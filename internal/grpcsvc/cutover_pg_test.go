// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
)

type fakeKratosDir struct {
	mu           sync.Mutex
	byEmail      map[string]string
	creates      int
	failFor      map[string]bool
	failPassword bool
	passwords    map[string]string
	traits       map[string][2]string
	deleted      []string
}

func newFakeKratosDir() *fakeKratosDir {
	return &fakeKratosDir{byEmail: map[string]string{}, failFor: map[string]bool{}}
}

func (f *fakeKratosDir) CreateIdentity(_ context.Context, email, _ string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failFor[email] {
		return "", errors.New("kratos down")
	}
	f.creates++
	id := "kid-" + email
	f.byEmail[strings.ToLower(email)] = id
	return id, nil
}

func (f *fakeKratosDir) FindIdentityByEmail(_ context.Context, email string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if id, ok := f.byEmail[strings.ToLower(email)]; ok {
		return id, nil
	}
	return "", kratos.ErrNotFound
}

type sentMail struct{ to, subject, body string }

type cutoverMailbox struct {
	mu   sync.Mutex
	sent []sentMail
}

func (f *cutoverMailbox) Send(to, subject, body string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.sent = append(f.sent, sentMail{to, subject, body})
	return nil
}

const cutoverResetURL = "https://sneakers.example.org/login"

func seedCutoverUsers(ctx context.Context, t *testing.T, s *Server) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO users (id,name,email,roles,is_root,keycloak_subject,username) VALUES
		   ('u-root','Root Admin','root@example.org','{site-admin}',true,'kc-root','root'),
		   ('u-admin','Site Admin','admin@example.org','{site-admin}',false,'kc-admin','admin'),
		   ('u-ada','Ada Lovelace','ada@example.org','{user}',false,'kc-ada','ada')`,
	} {
		if _, err := s.db.Exec(ctx, q); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
}

func subjectOf(ctx context.Context, t *testing.T, s *Server, userID string) string {
	t.Helper()
	var sub string
	if err := s.db.QueryRow(ctx, `SELECT keycloak_subject FROM users WHERE id=$1`, userID).Scan(&sub); err != nil {
		t.Fatal(err)
	}
	return sub
}

// Without the re-key a user's first Kratos login would provision a second
// account, detached from their groups and personal folder.
func TestPGCutoverRekeysSoKratosLoginAdoptsTheSameUser(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir, mail := newFakeKratosDir(), &cutoverMailbox{}

	rep, err := s.Cutover(ctx, dir, mail, cutoverResetURL)
	if err != nil || len(rep.Failures) != 0 || rep.Users != 3 {
		t.Fatalf("Cutover = %+v, %v", rep, err)
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kid-ada@example.org" {
		t.Fatalf("u-ada subject = %q, want the Kratos identity id", got)
	}
	adopted, err := s.AdoptOrProvisionFederatedUser(ctx, &identityv1.AdoptOrProvisionFederatedUserRequest{
		KeycloakSubject: "kid-ada@example.org", Email: "ada@example.org",
	})
	if err != nil || adopted.GetUser().GetId() != "u-ada" {
		t.Fatalf("Kratos login adopted %v (err %v), want u-ada", adopted.GetUser(), err)
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("users = %d, want 3 (no duplicate)", n)
	}
}

// The notice carries no code: users request one through "Forgot password",
// so no long-lived reset secret sits in anyone's inbox.
func TestPGCutoverEmailsEachUserHowToSetAPassword(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir, mail := newFakeKratosDir(), &cutoverMailbox{}

	if _, err := s.Cutover(ctx, dir, mail, cutoverResetURL); err != nil {
		t.Fatal(err)
	}
	if len(mail.sent) != 3 {
		t.Fatalf("sent %d emails, want 3", len(mail.sent))
	}
	for _, m := range mail.sent {
		if !strings.Contains(m.body, cutoverResetURL) || !strings.Contains(m.body, "Forgot password") || sixDigits.MatchString(m.body) {
			t.Fatalf("email to %s must point to Forgot password and carry no code: %q", m.to, m.body)
		}
	}
}

func TestPGCutoverReportsAnOutcomePerUser(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir := newFakeKratosDir()
	if _, err := dir.CreateIdentity(ctx, "ada@example.org", "Ada"); err != nil {
		t.Fatal(err)
	}

	rep, err := s.Cutover(ctx, dir, &cutoverMailbox{}, cutoverResetURL)
	if err != nil || len(rep.Outcomes) != 3 {
		t.Fatalf("Cutover = %+v, %v", rep, err)
	}
	byUser := map[string]CutoverOutcome{}
	for _, o := range rep.Outcomes {
		byUser[o.UserID] = o
	}
	if o := byUser["u-ada"]; o.Action != "existing" || o.KratosID != "kid-ada@example.org" || !o.Emailed {
		t.Fatalf("u-ada outcome = %+v", o)
	}
	if o := byUser["u-root"]; o.Action != "created" || o.KratosID == "" {
		t.Fatalf("u-root outcome = %+v", o)
	}
}

func TestPGPlanCutoverChangesNothing(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir := newFakeKratosDir()

	rep, err := s.PlanCutover(ctx, dir)
	if err != nil || len(rep.Outcomes) != 3 {
		t.Fatalf("PlanCutover = %+v, %v", rep, err)
	}
	for _, o := range rep.Outcomes {
		if o.Action != "would create" || o.Emailed {
			t.Fatalf("dry-run outcome = %+v", o)
		}
	}
	if dir.creates != 0 {
		t.Fatalf("a dry run created %d Kratos identities", dir.creates)
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kc-ada" {
		t.Fatalf("a dry run re-keyed u-ada to %q", got)
	}
}

func TestPGCutoverIsIdempotent(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir, mail := newFakeKratosDir(), &cutoverMailbox{}

	for i := 0; i < 2; i++ {
		if _, err := s.Cutover(ctx, dir, mail, cutoverResetURL); err != nil {
			t.Fatalf("run %d: %v", i+1, err)
		}
	}
	if dir.creates != 3 {
		t.Fatalf("Kratos identities created = %d, want 3 across both runs", dir.creates)
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kid-ada@example.org" {
		t.Fatalf("u-ada subject after re-run = %q", got)
	}
}

func TestPGCutoverHaltsWhenAPrivilegedUserFails(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	dir, mail := newFakeKratosDir(), &cutoverMailbox{}
	dir.failFor["admin@example.org"] = true

	if _, err := s.Cutover(ctx, dir, mail, cutoverResetURL); err == nil {
		t.Fatal("a site-admin failure must halt the cutover")
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kc-ada" {
		t.Fatalf("regular user touched after a privileged failure: subject = %q", got)
	}
	for _, m := range mail.sent {
		if m.to == "ada@example.org" {
			t.Fatal("regular user emailed after a privileged failure")
		}
	}
}

func TestPGCutoverRekeysButDoesNotEmailDisabledUsers(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	setDisabled(ctx, t, s, "u-ada", true)
	mail := &cutoverMailbox{}

	if _, err := s.Cutover(ctx, newFakeKratosDir(), mail, cutoverResetURL); err != nil {
		t.Fatal(err)
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kid-ada@example.org" {
		t.Fatalf("disabled user not re-keyed: %q", got)
	}
	for _, m := range mail.sent {
		if m.to == "ada@example.org" {
			t.Fatal("disabled user must not receive a sign-in code")
		}
	}
}

func TestPGCutoverReportsRegularUserFailuresAndContinues(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t)
	seedCutoverUsers(ctx, t, s)
	if _, err := s.db.Exec(ctx, `INSERT INTO users (id,name,email,roles,keycloak_subject,username) VALUES ('u-bob','Bob','bob@example.org','{user}','kc-bob','bob')`); err != nil {
		t.Fatal(err)
	}
	dir := newFakeKratosDir()
	dir.failFor["bob@example.org"] = true

	rep, err := s.Cutover(ctx, dir, &cutoverMailbox{}, cutoverResetURL)
	if err != nil {
		t.Fatalf("a regular user failure must not halt: %v", err)
	}
	if len(rep.Failures) != 1 || rep.Failures[0].UserID != "u-bob" {
		t.Fatalf("failures = %+v, want exactly u-bob", rep.Failures)
	}
	if got := subjectOf(ctx, t, s, "u-ada"); got != "kid-ada@example.org" {
		t.Fatalf("other users must still be cut over: u-ada subject = %q", got)
	}
}
