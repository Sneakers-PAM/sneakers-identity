// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/pquerna/otp/totp"
)

type recordingAuditor struct {
	mu     sync.Mutex
	events []audit.Event
	err    error
}

func (r *recordingAuditor) Record(_ context.Context, ev audit.Event) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, ev)
	return r.err
}

// take returns the events recorded so far and clears them.
func (r *recordingAuditor) take() []audit.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := r.events
	r.events = nil
	return out
}

// only asserts exactly one event was recorded since the last take and returns it.
func (r *recordingAuditor) only(t *testing.T) audit.Event {
	t.Helper()
	evs := r.take()
	if len(evs) != 1 {
		t.Fatalf("recorded %d events, want 1: %+v", len(evs), evs)
	}
	return evs[0]
}

func (r *recordingAuditor) none(t *testing.T) {
	t.Helper()
	if evs := r.take(); len(evs) != 0 {
		t.Fatalf("recorded %+v, want no event", evs)
	}
}

func newAuditedServer(t *testing.T) (*Server, *recordingAuditor) {
	t.Helper()
	rec := &recordingAuditor{}
	return newMFAServer(t).WithKratos(newFakeKratosDir()).WithAudit(rec), rec
}

func wantEvent(t *testing.T, got audit.Event, action, actor, subject string, attrs map[string]string) {
	t.Helper()
	if got.Action != action || got.ActorUserID != actor || got.Subject != subject {
		t.Fatalf("event = %+v, want action %q actor %q subject %q", got, action, actor, subject)
	}
	for k, v := range attrs {
		if got.Attributes[k] != v {
			t.Fatalf("event %s attribute %s = %q, want %q (all: %v)", action, k, got.Attributes[k], v, got.Attributes)
		}
	}
}

// assertNoSecretIn fails when any field of any event contains one of the
// given values (passwords, codes, tokens).
func assertNoSecretIn(t *testing.T, evs []audit.Event, secrets ...string) {
	t.Helper()
	for _, ev := range evs {
		fields := []string{ev.Action, ev.ActorUserID, ev.Subject, ev.GroupID}
		for k, v := range ev.Attributes {
			fields = append(fields, k, v)
		}
		for _, f := range fields {
			for _, sec := range secrets {
				if sec != "" && strings.Contains(f, sec) {
					t.Fatalf("event %s carries a secret value in %q", ev.Action, f)
				}
			}
		}
	}
}

func TestPGAuditSignIn(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)

	first, err := s.AdoptOrProvisionFederatedUser(ctx, &identityv1.AdoptOrProvisionFederatedUserRequest{
		Subject: "sub-ada", Email: "ada@example.org", Username: "ada",
	})
	if err != nil {
		t.Fatalf("AdoptOrProvisionFederatedUser: %v", err)
	}
	id := first.GetUser().GetId()
	evs := rec.take()
	if len(evs) != 2 {
		t.Fatalf("first sign-in recorded %+v, want user.create and auth.signin", evs)
	}
	wantEvent(t, evs[0], audit.ActionUserCreate, id, id, map[string]string{"source": "signin"})
	wantEvent(t, evs[1], audit.ActionSignIn, id, id, map[string]string{"result": "provisioned", "outcome": audit.OutcomeOK})

	if _, err := s.AdoptOrProvisionFederatedUser(ctx, &identityv1.AdoptOrProvisionFederatedUserRequest{Subject: "sub-ada"}); err != nil {
		t.Fatalf("second sign-in: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionSignIn, id, id, map[string]string{"result": "existing"})

	pre, err := s.PreCreateLocalUser(ctx, &identityv1.PreCreateLocalUserRequest{Email: "grace@example.org", ActingUserId: "u-admin"})
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	rec.take()
	if _, err := s.AdoptOrProvisionFederatedUser(ctx, &identityv1.AdoptOrProvisionFederatedUserRequest{Subject: "sub-grace", Email: "grace@example.org"}); err != nil {
		t.Fatalf("adopting sign-in: %v", err)
	}
	preID := pre.GetUser().GetId()
	wantEvent(t, rec.only(t), audit.ActionSignIn, preID, preID, map[string]string{"result": "adopted"})
}

func TestPGAuditTotpEnrolVerifyRemove(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	enroll, err := s.EnrollTotp(ctx, &identityv1.EnrollTotpRequest{UserId: "u-ada"})
	if err != nil {
		t.Fatalf("EnrollTotp: %v", err)
	}
	rec.none(t)
	code, err := totp.GenerateCode(enroll.GetSecret(), time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmTotp(ctx, &identityv1.ConfirmTotpRequest{UserId: "u-ada", Code: code}); err != nil {
		t.Fatalf("ConfirmTotp: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaEnroll, "u-ada", "u-ada", map[string]string{"factor": "totp"})
	if _, err := s.ConfirmTotp(ctx, &identityv1.ConfirmTotpRequest{UserId: "u-ada", Code: code}); err != nil {
		t.Fatalf("repeat ConfirmTotp: %v", err)
	}
	rec.none(t)

	if _, err := s.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: "u-ada", Code: code}); err != nil {
		t.Fatalf("VerifyTotp: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaVerify, "u-ada", "u-ada", map[string]string{"factor": "totp", "outcome": audit.OutcomeOK})
	if _, err := s.VerifyTotp(ctx, &identityv1.VerifyTotpRequest{UserId: "u-ada", Code: "000000x"}); err != nil {
		t.Fatalf("VerifyTotp (wrong): %v", err)
	}
	failed := rec.only(t)
	wantEvent(t, failed, audit.ActionMfaVerify, "u-ada", "u-ada", map[string]string{"factor": "totp", "outcome": audit.OutcomeFail})
	assertNoSecretIn(t, []audit.Event{failed}, code, "000000x", enroll.GetSecret())

	if _, err := s.DisableTotp(ctx, &identityv1.DisableTotpRequest{UserId: "u-ada", ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("DisableTotp: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaRemove, "u-admin", "u-ada", map[string]string{"factor": "totp"})
	if _, err := s.DisableTotp(ctx, &identityv1.DisableTotpRequest{UserId: "u-ada"}); err != nil {
		t.Fatalf("DisableTotp (nothing left): %v", err)
	}
	rec.none(t)

	enrollAndConfirm(t, s, "u-ada")
	rec.take()
	if _, err := s.RemoveFactor(ctx, &identityv1.RemoveFactorRequest{UserId: "u-ada", Kind: "totp"}); err != nil {
		t.Fatalf("RemoveFactor: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaRemove, "u-ada", "u-ada", map[string]string{"factor": "totp"})
}

func TestPGAuditEmailOtpVerify(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	code, _, err := s.createEmailOTP(ctx, "u-ada", "login")
	if err != nil {
		t.Fatalf("createEmailOTP: %v", err)
	}
	if _, err := s.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: "u-ada", Code: code, Purpose: "login"}); err != nil {
		t.Fatalf("VerifyEmailOtp: %v", err)
	}
	ok := rec.only(t)
	wantEvent(t, ok, audit.ActionMfaVerify, "u-ada", "u-ada", map[string]string{"factor": "email", "purpose": "login", "outcome": audit.OutcomeOK})
	if _, err := s.VerifyEmailOtp(ctx, &identityv1.VerifyEmailOtpRequest{UserId: "u-ada", Code: code, Purpose: "login"}); err != nil {
		t.Fatalf("VerifyEmailOtp (reused): %v", err)
	}
	reused := rec.only(t)
	wantEvent(t, reused, audit.ActionMfaVerify, "u-ada", "u-ada", map[string]string{"factor": "email", "outcome": audit.OutcomeFail})
	assertNoSecretIn(t, []audit.Event{ok, reused}, code)
}

func TestPGAuditPasskeyVerifyFailureAndRemove(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	wa, err := webauthn.New(&webauthn.Config{RPID: "example.org", RPDisplayName: "Sneakers", RPOrigins: []string{"https://example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	s = s.WithWebauthn(wa)
	seedTokenUser(ctx, t, s, "u-ada")
	credID := base64.RawURLEncoding.EncodeToString([]byte("credential-1"))
	if _, err := s.db.Exec(ctx,
		`INSERT INTO user_webauthn_credentials (credential_id, user_id, public_key, sign_count, aaguid, transports, label)
		 VALUES ($1,'u-ada','\x00'::bytea,0,'\x00'::bytea,'{}','laptop')`, credID); err != nil {
		t.Fatalf("seed credential: %v", err)
	}

	begin, err := s.WebauthnAssertBegin(ctx, &identityv1.WebauthnAssertBeginRequest{UserId: "u-ada"})
	if err != nil {
		t.Fatalf("WebauthnAssertBegin: %v", err)
	}
	rec.none(t)
	resp, err := s.WebauthnAssertFinish(ctx, &identityv1.WebauthnAssertFinishRequest{UserId: "u-ada", SessionId: begin.GetSessionId(), CredentialJson: "{}"})
	if err != nil || resp.GetOk() {
		t.Fatalf("WebauthnAssertFinish = %v, %v; want ok=false", resp, err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaVerify, "u-ada", "u-ada", map[string]string{"factor": "passkey", "outcome": audit.OutcomeFail})

	if _, err := s.RemoveWebauthnCredential(ctx, &identityv1.RemoveWebauthnCredentialRequest{UserId: "u-ada", CredentialId: credID, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("RemoveWebauthnCredential: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionMfaRemove, "u-admin", "u-ada", map[string]string{"factor": "passkey", "credential_id": credID})
}

func TestPGAuditUserChanges(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	const password = "correct horse battery"

	created, err := s.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{
		Username: "ada", Email: "ada@example.org", Name: "Ada", Password: password, ActingUserId: "u-admin",
	})
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	id := created.GetUser().GetId()
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionUserCreate, "u-admin", id, map[string]string{"source": "local", "username": "ada"})
	assertNoSecretIn(t, []audit.Event{ev}, password)

	pre, err := s.PreCreateLocalUser(ctx, &identityv1.PreCreateLocalUserRequest{Email: "grace@example.org", Roles: []string{"user"}, ActingUserId: "u-admin"})
	if err != nil {
		t.Fatalf("PreCreateLocalUser: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserCreate, "u-admin", pre.GetUser().GetId(), map[string]string{"source": "precreate", "roles": "user"})

	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{UserId: id, Name: "Ada King", Email: "ada@example.org", ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserUpdate, "u-admin", id, map[string]string{"changed": "name"})

	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: id, Roles: []string{"site-admin", "user"}, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserRolesSet, "u-admin", id, map[string]string{"roles": "site-admin,user", "added": "site-admin,user", "removed": ""})
	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: id, Roles: []string{"user"}, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserRolesSet, "u-admin", id, map[string]string{"roles": "user", "added": "", "removed": "site-admin"})
	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: "u-missing", Roles: []string{"user"}}); err == nil {
		t.Fatal("SetUserRoles on a missing user must fail")
	}
	rec.none(t)

	if _, err := s.SetUserDisabled(ctx, &identityv1.SetUserDisabledRequest{UserId: id, Disabled: true, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserDisable, "u-admin", id, nil)
	if _, err := s.SetUserDisabled(ctx, &identityv1.SetUserDisabledRequest{UserId: id, Disabled: false, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("SetUserDisabled: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserEnable, "u-admin", id, nil)
}

func TestPGAuditBootstrapRoot(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	const password = "long root password"
	resp, err := s.BootstrapRoot(ctx, &identityv1.BootstrapRootRequest{Username: "root", Email: "root@example.org", Password: password})
	if err != nil {
		t.Fatalf("BootstrapRoot: %v", err)
	}
	id := resp.GetUser().GetId()
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionUserCreate, id, id, map[string]string{"source": "bootstrap", "root": "true", "roles": "site-admin"})
	assertNoSecretIn(t, []audit.Event{ev}, password)
}

func TestPGAuditPasswordReset(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedTokenUser(ctx, t, s, "u-ada")
	if _, err := s.db.Exec(ctx, `UPDATE users SET subject='kid-ada' WHERE id='u-ada'`); err != nil {
		t.Fatal(err)
	}
	const newPassword = "a brand new password"

	code, _, err := s.createEmailOTP(ctx, "u-ada", emailOTPPurposeReset)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.ConfirmPasswordReset(ctx, &identityv1.ConfirmPasswordResetRequest{Email: "u-ada@example.org", Code: "wrong", NewPassword: newPassword}); err != nil {
		t.Fatalf("ConfirmPasswordReset (wrong code): %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionPasswordReset, "u-ada", "u-ada", map[string]string{"outcome": audit.OutcomeFail})
	if _, err := s.ConfirmPasswordReset(ctx, &identityv1.ConfirmPasswordResetRequest{Email: "u-ada@example.org", Code: code, NewPassword: newPassword}); err != nil {
		t.Fatalf("ConfirmPasswordReset: %v", err)
	}
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionPasswordReset, "u-ada", "u-ada", map[string]string{"outcome": audit.OutcomeOK})
	assertNoSecretIn(t, []audit.Event{ev}, code, newPassword)
}

func TestPGAuditGroupChanges(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	g, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "Help Desk", ActingUserId: "u-admin"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	gid := g.GetGroup().GetId()
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionGroupCreate, "u-admin", gid, map[string]string{"name": "Help Desk"})
	if ev.GroupID != gid {
		t.Fatalf("group.create GroupID = %q, want %q", ev.GroupID, gid)
	}

	if _, err := s.AddGroupMember(ctx, &identityv1.AddGroupMemberRequest{UserId: "u-ada", GroupId: gid, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("AddGroupMember: %v", err)
	}
	ev = rec.only(t)
	wantEvent(t, ev, audit.ActionGroupMemberAdd, "u-admin", "u-ada", nil)
	if ev.GroupID != gid {
		t.Fatalf("group.member.add GroupID = %q, want %q", ev.GroupID, gid)
	}
	if _, err := s.RemoveGroupMember(ctx, &identityv1.RemoveGroupMemberRequest{UserId: "u-ada", GroupId: gid, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("RemoveGroupMember: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionGroupMemberRemove, "u-admin", "u-ada", nil)
	if _, err := s.RemoveGroupMember(ctx, &identityv1.RemoveGroupMemberRequest{UserId: "u-ada", GroupId: gid}); err != nil {
		t.Fatalf("RemoveGroupMember (not a member): %v", err)
	}
	rec.none(t)
}

func TestPGAuditServiceAccountsAndAPITokens(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)

	sa, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{Name: "ci-runner", CreatedBy: "u-admin"})
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v", err)
	}
	saID := sa.GetServiceAccount().GetId()
	wantEvent(t, rec.only(t), audit.ActionServiceAccountCreate, "u-admin", saID, map[string]string{"name": "ci-runner"})

	minted, err := s.MintApiToken(ctx, &identityv1.MintApiTokenRequest{ServiceAccountId: saID, Scope: "Security", CreatedBy: "u-admin"})
	if err != nil {
		t.Fatalf("MintApiToken: %v", err)
	}
	tokID := minted.GetMeta().GetId()
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionAPITokenMint, "u-admin", tokID, map[string]string{"service_account_id": saID, "scope": "group-security"})
	assertNoSecretIn(t, []audit.Event{ev}, minted.GetToken())

	if _, err := s.RevokeApiToken(ctx, &identityv1.RevokeApiTokenRequest{Id: tokID, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("RevokeApiToken: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionAPITokenRevoke, "u-admin", tokID, map[string]string{"service_account_id": saID})

	if _, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
		ServiceAccountId: saID, OidcIssuer: "https://hydra.example.org/", OidcSubject: "client-1", ActingAdmin: "u-admin", AllowedGroups: []string{"Security"},
	}); err != nil {
		t.Fatalf("LinkOidcClient: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionOidcClientLink, "u-admin", saID, map[string]string{"oidc_issuer": "https://hydra.example.org/", "oidc_subject": "client-1", "allowed_groups": "group-security"})
	if _, err := s.UnlinkOidcClient(ctx, &identityv1.UnlinkOidcClientRequest{ServiceAccountId: saID, ActingAdmin: "u-admin"}); err != nil {
		t.Fatalf("UnlinkOidcClient: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionOidcClientUnlink, "u-admin", saID, nil)

	if _, err := s.DisableServiceAccount(ctx, &identityv1.DisableServiceAccountRequest{Id: saID, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("DisableServiceAccount: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionServiceAccountDisable, "u-admin", saID, nil)
}

func TestPGAuditUserTokens(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedTokenUser(ctx, t, s, "u-ada")

	minted := mintUserToken(ctx, t, s, "u-ada")
	tokID := minted.GetMeta().GetId()
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionUserTokenMint, "u-ada", tokID, map[string]string{"user_id": "u-ada", "label": "laptop", "client_name": "Example CLI"})
	assertNoSecretIn(t, []audit.Event{ev}, minted.GetToken())

	verifyUserToken(ctx, t, s, minted.GetToken())
	rec.none(t)

	if _, err := s.RevokeUserToken(ctx, &identityv1.RevokeUserTokenRequest{Id: tokID, UserId: "u-ada"}); err != nil {
		t.Fatalf("RevokeUserToken: %v", err)
	}
	wantEvent(t, rec.only(t), audit.ActionUserTokenRevoke, "u-ada", tokID, map[string]string{"user_id": "u-ada"})
}

// An audit service that is down never fails the change it records.
func TestPGAuditFailureDoesNotFailTheChange(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	rec.err = errors.New("audit unavailable")

	g, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "Help Desk", ActingUserId: "u-admin"})
	if err != nil || g.GetGroup().GetId() == "" {
		t.Fatalf("CreateGroup with audit down = %v, %v", g, err)
	}
	if evs := rec.take(); len(evs) != 1 || !slices.ContainsFunc(evs, func(e audit.Event) bool { return e.Action == audit.ActionGroupCreate }) {
		t.Fatalf("events = %+v", evs)
	}
}
