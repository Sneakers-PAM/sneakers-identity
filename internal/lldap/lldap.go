// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package lldap is the admin client for the lldap directory: users/groups/
// membership over lldap's GraphQL API, and passwords over the LDAP
// Password-Modify extended operation. It is the single write path to the
// directory (Keycloak federates lldap READ_ONLY).
//
// Sneakers' identity is otherwise
// read-mostly (it adopts lldap/Keycloak but writes no directory), and the
// first-run /setup bootstrap needs to create the very first admin in lldap so
// Keycloak federation can log them in.
package lldap

import "context"

type Group struct {
	ID   int
	Name string
}
type Member struct {
	Username string
	Name     string
	Email    string
}

// Admin is the directory write/read surface the identity handlers depend on.
type Admin interface {
	CreateUser(ctx context.Context, username, email, name string) error
	// DeleteUser removes a user from the directory by username (lldap uid).
	// Used to roll back an orphaned lldap user when a later step of local-user
	// creation (SetPassword / DB pre-create) fails after CreateUser succeeded.
	DeleteUser(ctx context.Context, username string) error
	SetPassword(ctx context.Context, username, password string) error
	UpdateUser(ctx context.Context, username, name, email string) error
	ListGroups(ctx context.Context) ([]Group, error)
	CreateGroup(ctx context.Context, name string) (Group, error)
	DeleteGroup(ctx context.Context, groupID int) error
	RenameGroup(ctx context.Context, groupID int, name string) error
	AddUserToGroup(ctx context.Context, username string, groupID int) error
	RemoveUserFromGroup(ctx context.Context, username string, groupID int) error
	GroupMembers(ctx context.Context, groupID int) ([]Member, error)
	// UserExists reports whether a user with the given username (lldap uid)
	// exists in the directory. Used before an ensure-create so an already-present
	// user (e.g. the bootstrapped root) isn't re-created into a unique-constraint
	// violation.
	UserExists(ctx context.Context, username string) (bool, error)
	// UserGroups returns the groups the given user is currently a member of.
	UserGroups(ctx context.Context, username string) ([]Group, error)
}
