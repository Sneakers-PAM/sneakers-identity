// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func seedRoleUser(ctx context.Context, t *testing.T, s *Server, id string, root bool, roles ...string) {
	t.Helper()
	if roles == nil {
		roles = []string{}
	}
	if _, err := s.db.Exec(ctx, `INSERT INTO users (id,name,email,roles,is_root) VALUES ($1,$1,$1||'@example.org',$2,$3)`, id, roles, root); err != nil {
		t.Fatalf("seed user %s: %v", id, err)
	}
}

func userRoles(ctx context.Context, t *testing.T, s *Server, id string) []string {
	t.Helper()
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		t.Fatalf("load %s: %v", id, err)
	}
	return u.GetRoles()
}

func wantCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if status.Code(err) != want {
		t.Fatalf("err = %v, want %s", err, want)
	}
}

func TestPGRecoveryRoleGrantedAndRevokedBySiteAdmin(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedRoleUser(ctx, t, s, "u-admin", false, "site-admin")
	seedRoleUser(ctx, t, s, "u-ada", false, "user")

	resp, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: "u-ada", Roles: []string{"user", RoleRecovery}, ActingUserId: "u-admin"})
	if err != nil {
		t.Fatalf("SetUserRoles: %v", err)
	}
	if !slices.Contains(resp.GetUser().GetRoles(), "recovery") {
		t.Fatalf("roles = %v, want recovery", resp.GetUser().GetRoles())
	}
	evs := rec.take()
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want user.roles.set and role.recovery.grant", evs)
	}
	wantEvent(t, evs[0], audit.ActionUserRolesSet, "u-admin", "u-ada", map[string]string{"added": "recovery"})
	wantEvent(t, evs[1], audit.ActionRecoveryRoleGrant, "u-admin", "u-ada", map[string]string{"role": "recovery", "severity": "high"})

	ctxResp, err := s.ResolveUserContext(ctx, &identityv1.ResolveUserContextRequest{Subject: mustSubject(ctx, t, s, "u-ada")})
	if err != nil || !slices.Contains(ctxResp.GetRoles(), "recovery") {
		t.Fatalf("ResolveUserContext roles = %v, %v; want recovery", ctxResp.GetRoles(), err)
	}

	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: "u-ada", Roles: []string{"user"}, ActingUserId: "u-admin"}); err != nil {
		t.Fatalf("SetUserRoles (revoke): %v", err)
	}
	evs = rec.take()
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want user.roles.set and role.recovery.revoke", evs)
	}
	wantEvent(t, evs[1], audit.ActionRecoveryRoleRevoke, "u-admin", "u-ada", map[string]string{"role": "recovery", "severity": "high"})
}

func TestPGRecoveryRoleGrantedByRoot(t *testing.T) {
	ctx := context.Background()
	s, _ := newAuditedServer(t)
	seedRoleUser(ctx, t, s, "u-root", true)
	seedRoleUser(ctx, t, s, "u-ada", false, "user")

	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: "u-ada", Roles: []string{RoleRecovery}, ActingUserId: "u-root"}); err != nil {
		t.Fatalf("root grant: %v", err)
	}
}

func TestPGRecoveryRoleRefusedWithoutSiteAdmin(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedRoleUser(ctx, t, s, "u-ops", false, "user", "approver")
	seedRoleUser(ctx, t, s, "u-ada", false, "user")
	seedRoleUser(ctx, t, s, "u-held", false, "user", RoleRecovery)
	seedRoleUser(ctx, t, s, "u-disabled-admin", false, "site-admin")
	if _, err := s.db.Exec(ctx, `UPDATE users SET disabled_at=now() WHERE id='u-disabled-admin'`); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, actor, target string
		roles               []string
	}{
		{"grant by a non-admin", "u-ops", "u-ada", []string{"user", RoleRecovery}},
		{"revoke by a non-admin", "u-ops", "u-held", []string{"user"}},
		{"grant with no actor", "", "u-ada", []string{RoleRecovery}},
		{"grant by an unknown actor", "u-missing", "u-ada", []string{RoleRecovery}},
		{"grant by a disabled admin", "u-disabled-admin", "u-ada", []string{RoleRecovery}},
		{"grant by a recovery holder", "u-held", "u-ada", []string{"user", RoleRecovery}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			before := userRoles(ctx, t, s, tc.target)
			_, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: tc.target, Roles: tc.roles, ActingUserId: tc.actor})
			wantCode(t, err, codes.PermissionDenied)
			if got := userRoles(ctx, t, s, tc.target); !slices.Equal(got, before) {
				t.Fatalf("roles changed to %v after a refused call, were %v", got, before)
			}
			rec.none(t)
		})
	}

	// A change that leaves the recovery role as it is needs no site admin.
	if _, err := s.SetUserRoles(ctx, &identityv1.SetUserRolesRequest{UserId: "u-held", Roles: []string{"user", RoleRecovery, "approver"}}); err != nil {
		t.Fatalf("SetUserRoles keeping recovery: %v", err)
	}
}

func TestPGRecoveryRoleOnPreCreate(t *testing.T) {
	ctx := context.Background()
	s, rec := newAuditedServer(t)
	seedRoleUser(ctx, t, s, "u-admin", false, "admin")
	seedRoleUser(ctx, t, s, "u-ops", false, "user")

	_, err := s.PreCreateLocalUser(ctx, &identityv1.PreCreateLocalUserRequest{Email: "grace@example.org", Roles: []string{RoleRecovery}, ActingUserId: "u-ops"})
	wantCode(t, err, codes.PermissionDenied)
	rec.none(t)

	pre, err := s.PreCreateLocalUser(ctx, &identityv1.PreCreateLocalUserRequest{Email: "grace@example.org", Roles: []string{"user", RoleRecovery}, ActingUserId: "u-admin"})
	if err != nil {
		t.Fatalf("PreCreateLocalUser by an admin: %v", err)
	}
	evs := rec.take()
	if len(evs) != 2 {
		t.Fatalf("events = %+v, want user.create and role.recovery.grant", evs)
	}
	wantEvent(t, evs[1], audit.ActionRecoveryRoleGrant, "u-admin", pre.GetUser().GetId(), map[string]string{"severity": "high"})
}

func mustSubject(ctx context.Context, t *testing.T, s *Server, id string) string {
	t.Helper()
	sub := "sub-" + id
	if _, err := s.db.Exec(ctx, `UPDATE users SET subject=$2 WHERE id=$1`, id, sub); err != nil {
		t.Fatal(err)
	}
	return sub
}
