// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/lldap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recLldap is a recording lldap.Admin fake for the UpdateUser handler tests: it
// captures the create/delete/update calls the rename + profile paths make so a
// test can assert the directory side-effects (and none happened when they must
// not). Optional errors let a test drive the fail-closed rollback branches.
type recLldap struct {
	created   []string    // usernames passed to CreateUser
	deleted   []string    // usernames passed to DeleteUser
	updated   [][3]string // {username, name, email} passed to UpdateUser
	createErr error
	deleteErr error
}

func (r *recLldap) CreateUser(_ context.Context, username, _ /*email*/, _ /*name*/ string) error {
	if r.createErr != nil {
		return r.createErr
	}
	r.created = append(r.created, username)
	return nil
}

func (r *recLldap) DeleteUser(_ context.Context, username string) error {
	if r.deleteErr != nil {
		return r.deleteErr
	}
	r.deleted = append(r.deleted, username)
	return nil
}

func (r *recLldap) UpdateUser(_ context.Context, username, name, email string) error {
	r.updated = append(r.updated, [3]string{username, name, email})
	return nil
}

func (r *recLldap) SetPassword(context.Context, string, string) error { return nil }
func (r *recLldap) ListGroups(context.Context) ([]lldap.Group, error) { return nil, nil }
func (r *recLldap) CreateGroup(context.Context, string) (lldap.Group, error) {
	return lldap.Group{}, nil
}
func (r *recLldap) DeleteGroup(context.Context, int) error                    { return nil }
func (r *recLldap) RenameGroup(context.Context, int, string) error            { return nil }
func (r *recLldap) AddUserToGroup(context.Context, string, int) error         { return nil }
func (r *recLldap) RemoveUserFromGroup(context.Context, string, int) error    { return nil }
func (r *recLldap) GroupMembers(context.Context, int) ([]lldap.Member, error) { return nil, nil }
func (r *recLldap) UserExists(context.Context, string) (bool, error)          { return false, nil }
func (r *recLldap) UserGroups(context.Context, string) ([]lldap.Group, error) { return nil, nil }

// TestUpdateUserInputValidation covers the argument checks that short-circuit
// before any DB access, so they run without a Postgres (unit-safe).
func TestUpdateUserInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.UpdateUser(ctx, &identityv1.UpdateUserRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty user_id: want InvalidArgument, got %v", err)
	}
}
