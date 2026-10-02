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

// fakeLldap is a stub lldap.Admin for the handler and group-sync tests. The
// group surface (CreateGroup, ListGroups, DeleteGroup) is pluggable; every
// other method is a no-op so the fake satisfies the interface.
type fakeLldap struct {
	createGroup func(ctx context.Context, name string) (lldap.Group, error)
	listGroups  func(ctx context.Context) ([]lldap.Group, error)
	deleteGroup func(ctx context.Context, groupID int) error
}

func (f *fakeLldap) CreateGroup(ctx context.Context, name string) (lldap.Group, error) {
	return f.createGroup(ctx, name)
}

func (f *fakeLldap) CreateUser(context.Context, string, string, string) error { return nil }
func (f *fakeLldap) DeleteUser(context.Context, string) error                 { return nil }
func (f *fakeLldap) SetPassword(context.Context, string, string) error        { return nil }
func (f *fakeLldap) UpdateUser(context.Context, string, string, string) error { return nil }
func (f *fakeLldap) ListGroups(ctx context.Context) ([]lldap.Group, error) {
	if f.listGroups == nil {
		return nil, nil
	}
	return f.listGroups(ctx)
}

func (f *fakeLldap) DeleteGroup(ctx context.Context, groupID int) error {
	if f.deleteGroup == nil {
		return nil
	}
	return f.deleteGroup(ctx, groupID)
}

func (f *fakeLldap) RenameGroup(context.Context, int, string) error            { return nil }
func (f *fakeLldap) AddUserToGroup(context.Context, string, int) error         { return nil }
func (f *fakeLldap) RemoveUserFromGroup(context.Context, string, int) error    { return nil }
func (f *fakeLldap) GroupMembers(context.Context, int) ([]lldap.Member, error) { return nil, nil }
func (f *fakeLldap) UserExists(context.Context, string) (bool, error)          { return false, nil }
func (f *fakeLldap) UserGroups(context.Context, string) ([]lldap.Group, error) { return nil, nil }

func TestCreateGroup(t *testing.T) {
	ctx := context.Background()

	t.Run("empty name is InvalidArgument", func(t *testing.T) {
		s := &Server{lldap: &fakeLldap{}}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "   "})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
	})

	t.Run("missing lldap is Unavailable", func(t *testing.T) {
		s := &Server{}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "ops"})
		if status.Code(err) != codes.Unavailable {
			t.Fatalf("code = %v, want Unavailable", status.Code(err))
		}
	})

	t.Run("reserved lldap_ prefix is InvalidArgument", func(t *testing.T) {
		called := false
		s := &Server{lldap: &fakeLldap{
			createGroup: func(context.Context, string) (lldap.Group, error) {
				called = true
				return lldap.Group{}, nil
			},
		}}
		_, err := s.CreateGroup(ctx, &identityv1.CreateGroupRequest{Name: "LLDAP_admin"})
		if status.Code(err) != codes.InvalidArgument {
			t.Fatalf("code = %v, want InvalidArgument", status.Code(err))
		}
		if called {
			t.Fatal("lldap CreateGroup must not be called for a reserved name")
		}
	})
}
