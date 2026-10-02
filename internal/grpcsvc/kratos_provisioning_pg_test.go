// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
)

func (f *fakeKratosDir) SetPassword(_ context.Context, id, password string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.failPassword {
		return errors.New("kratos rejected the password")
	}
	if f.passwords == nil {
		f.passwords = map[string]string{}
	}
	f.passwords[id] = password
	return nil
}

func (f *fakeKratosDir) UpdateTraits(_ context.Context, id, email, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.traits == nil {
		f.traits = map[string][2]string{}
	}
	f.traits[id] = [2]string{email, name}
	return nil
}

func (f *fakeKratosDir) DeleteIdentity(_ context.Context, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for e, v := range f.byEmail {
		if v == id {
			delete(f.byEmail, e)
		}
	}
	f.deleted = append(f.deleted, id)
	return nil
}

func TestPGKratosCreateLocalUserStoresTheIdentityAsSubject(t *testing.T) {
	ctx := context.Background()
	dir := newFakeKratosDir()
	s := newPGServer(t).WithKratos(dir)

	resp, err := s.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{
		Username: "ada", Email: "ada@example.org", Name: "Ada Lovelace", Password: "correct horse battery",
	})
	if err != nil {
		t.Fatalf("CreateLocalUser: %v", err)
	}
	u := resp.GetUser()
	if u.GetKeycloakSubject() != "kid-ada@example.org" || dir.passwords["kid-ada@example.org"] != "correct horse battery" {
		t.Fatalf("user = %+v, kratos passwords = %v", u, dir.passwords)
	}
	adopted, err := s.AdoptOrProvisionFederatedUser(ctx, &identityv1.AdoptOrProvisionFederatedUserRequest{
		KeycloakSubject: "kid-ada@example.org", Email: "ada@example.org",
	})
	if err != nil || adopted.GetUser().GetId() != u.GetId() {
		t.Fatalf("first Kratos login adopted %v (err %v), want %s", adopted.GetUser(), err, u.GetId())
	}
}

func TestPGKratosCreateLocalUserRollsBackTheIdentity(t *testing.T) {
	ctx := context.Background()
	dir := newFakeKratosDir()
	dir.failPassword = true
	s := newPGServer(t).WithKratos(dir)

	if _, err := s.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{
		Username: "ada", Email: "ada@example.org", Name: "Ada", Password: "pw",
	}); err == nil {
		t.Fatal("a Kratos password failure must fail the create")
	}
	if len(dir.deleted) != 1 || len(dir.byEmail) != 0 {
		t.Fatalf("identity not rolled back: deleted=%v remaining=%v", dir.deleted, dir.byEmail)
	}
	var n int
	if err := s.db.QueryRow(ctx, `SELECT count(*) FROM users`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("users = %d, want 0", n)
	}
}

func TestPGKratosBootstrapRoot(t *testing.T) {
	ctx := context.Background()
	dir := newFakeKratosDir()
	s := newPGServer(t).WithKratos(dir)

	resp, err := s.BootstrapRoot(ctx, &identityv1.BootstrapRootRequest{
		Username: "root", Email: "root@example.org", Name: "Root", Password: "long root password",
	})
	if err != nil {
		t.Fatalf("BootstrapRoot: %v", err)
	}
	if u := resp.GetUser(); !u.GetIsRoot() || u.GetKeycloakSubject() != "kid-root@example.org" || dir.passwords["kid-root@example.org"] == "" {
		t.Fatalf("root = %+v", u)
	}
}

func TestPGKratosUpdateUserUpdatesTraits(t *testing.T) {
	ctx := context.Background()
	dir := newFakeKratosDir()
	s := newPGServer(t).WithKratos(dir)
	created, err := s.CreateLocalUser(ctx, &identityv1.CreateLocalUserRequest{Username: "ada", Email: "ada@example.org", Name: "Ada", Password: "pw pw pw pw"})
	if err != nil {
		t.Fatal(err)
	}
	id := created.GetUser().GetId()

	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{UserId: id, Name: "Ada King", Email: "ada.k@example.org"}); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if got := dir.traits["kid-ada@example.org"]; got != [2]string{"ada.k@example.org", "Ada King"} {
		t.Fatalf("kratos traits = %v", got)
	}
	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{UserId: id, Name: "Ada King", Email: "ada.k@example.org", Username: "aking"}); err != nil {
		t.Fatalf("rename under Kratos: %v", err)
	}
	u, _ := s.getUserByID(ctx, id)
	if u.GetUsername() != "aking" || u.GetKeycloakSubject() != "kid-ada@example.org" {
		t.Fatalf("after rename user = %+v, want username aking and the same subject", u)
	}
}

func TestPGCreateGroupWithoutLldapIsIdentityOnly(t *testing.T) {
	ctx := context.Background()
	s := newPGServer(t).WithKratos(newFakeKratosDir())

	resp, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "Help Desk"})
	if err != nil {
		t.Fatalf("CreateGroup: %v", err)
	}
	var name string
	if err := s.db.QueryRow(ctx, `SELECT name FROM groups WHERE id=$1`, resp.GetGroup().GetId()).Scan(&name); err != nil || name != "Help Desk" {
		t.Fatalf("group row = %q, %v", name, err)
	}
	if _, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "help desk"}); err == nil {
		t.Fatal("a case-insensitive duplicate must be refused")
	}
}
