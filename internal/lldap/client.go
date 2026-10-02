// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package lldap

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
)

// Config carries the lldap admin endpoints + credentials (from env/secret).
type Config struct {
	AdminURL  string // e.g. http://lldap:17170
	LDAPURL   string // e.g. ldap://lldap:3890
	BaseDN    string // e.g. dc=example,dc=org
	AdminUser string // admin
	AdminPass string // the admin password
}

// Client implements Admin.
type Client struct {
	cfg  Config
	http *http.Client

	mu       sync.Mutex
	token    string
	tokenExp time.Time
}

// New returns a new lldap admin Client.
func New(cfg Config) *Client {
	return &Client{cfg: cfg, http: &http.Client{Timeout: 10 * time.Second}}
}

func (c *Client) userDN(username string) string {
	return fmt.Sprintf("uid=%s,ou=people,%s", username, c.cfg.BaseDN)
}
func (c *Client) adminDN() string {
	return fmt.Sprintf("uid=%s,ou=people,%s", c.cfg.AdminUser, c.cfg.BaseDN)
}

// login fetches (and caches) an lldap admin bearer token.
func (c *Client) login(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.token != "" && time.Now().Before(c.tokenExp) {
		return c.token, nil
	}
	body, _ := json.Marshal(map[string]string{"username": c.cfg.AdminUser, "password": c.cfg.AdminPass})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.AdminURL+"/auth/simple/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("lldap login: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("lldap login: status %d", resp.StatusCode)
	}
	var out struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	c.token, c.tokenExp = out.Token, time.Now().Add(50*time.Minute)
	return c.token, nil
}

// gql runs a GraphQL query/mutation, decoding data into out.
func (c *Client) gql(ctx context.Context, query string, vars map[string]any, out any) error {
	tok, err := c.login(ctx)
	if err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]any{"query": query, "variables": vars})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.AdminURL+"/api/graphql", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		return fmt.Errorf("lldap graphql: HTTP %d", resp.StatusCode)
	}
	var env struct {
		Data   json.RawMessage `json:"data"`
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return err
	}
	if len(env.Errors) > 0 {
		return fmt.Errorf("lldap graphql: %s", env.Errors[0].Message)
	}
	if out != nil {
		return json.Unmarshal(env.Data, out)
	}
	return nil
}

// isLldapUniqueErr reports whether err is lldap's uniqueness-violation error.
// lldap returns GraphQL errors whose message contains "Uniqueness violation"
// when the user already exists. Matching is case-insensitive to be resilient to
// lldap message-text changes across versions.
func isLldapUniqueErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	// "unique constraint failed" catches lldap's raw SQLite backend error, e.g.
	// `UNIQUE constraint failed: users.lowercase_email`, which is what surfaces
	// when a create collides on email (not username) and is NOT phrased as a
	// "Uniqueness violation".
	return containsAny(msg, "Uniqueness violation", "already exists", "duplicate", "unique constraint failed")
}

// isLldapNotFoundErr reports whether err is lldap's entity-not-found error,
// returned by the user(userId:) query when no such user exists. Matching is
// case-insensitive and covers the common phrasings across lldap versions.
func isLldapNotFoundErr(err error) bool {
	if err == nil {
		return false
	}
	return containsAny(err.Error(), "entity not found", "not found", "no such")
}

// containsAny reports whether s contains any of the given substrings
// (case-insensitive).
func containsAny(s string, substrs ...string) bool {
	lower := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(lower, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

// CreateUser creates a new user in lldap. If lldap reports a uniqueness
// violation (the username already exists), the error is silently discarded and
// nil is returned, making CreateUser a create-or-exists (idempotent) operation.
// This is required for retry-safety: if a previous call succeeded at CreateUser
// but failed at SetPassword, the next call must be able to proceed past
// CreateUser and re-attempt SetPassword without being blocked by a duplicate
// error.
func (c *Client) CreateUser(ctx context.Context, username, email, name string) error {
	const q = `mutation($u:CreateUserInput!){ createUser(user:$u){ id } }`
	err := c.gql(ctx, q, map[string]any{"u": map[string]any{
		"id": username, "email": email, "displayName": name,
	}}, nil)
	if err != nil && isLldapUniqueErr(err) {
		return nil // already exists — idempotent
	}
	return err
}

// DeleteUser removes a user from lldap by username (lldap uid). Used to roll
// back an orphaned directory user when a later step of local-user creation
// fails after CreateUser succeeded.
func (c *Client) DeleteUser(ctx context.Context, username string) error {
	const q = `mutation($u:String!){ deleteUser(userId:$u){ ok } }`
	return c.gql(ctx, q, map[string]any{"u": username}, nil)
}

// UpdateUser updates a user's display name and email in lldap.
func (c *Client) UpdateUser(ctx context.Context, username, name, email string) error {
	const q = `mutation($u:UpdateUserInput!){ updateUser(user:$u){ ok } }`
	return c.gql(ctx, q, map[string]any{"u": map[string]any{
		"id": username, "email": email, "displayName": name,
	}}, nil)
}

// ListGroups returns all groups in the directory.
func (c *Client) ListGroups(ctx context.Context) ([]Group, error) {
	const q = `{ groups { id displayName } }`
	var out struct {
		Groups []struct {
			ID          int    `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"groups"`
	}
	if err := c.gql(ctx, q, nil, &out); err != nil {
		return nil, err
	}
	gs := make([]Group, len(out.Groups))
	for i, g := range out.Groups {
		gs[i] = Group{ID: g.ID, Name: g.DisplayName}
	}
	return gs, nil
}

// CreateGroup creates a new group in lldap and returns it.
func (c *Client) CreateGroup(ctx context.Context, name string) (Group, error) {
	const q = `mutation($n:String!){ createGroup(name:$n){ id displayName } }`
	var out struct {
		CreateGroup struct {
			ID          int    `json:"id"`
			DisplayName string `json:"displayName"`
		} `json:"createGroup"`
	}
	if err := c.gql(ctx, q, map[string]any{"n": name}, &out); err != nil {
		return Group{}, err
	}
	return Group{ID: out.CreateGroup.ID, Name: out.CreateGroup.DisplayName}, nil
}

// DeleteGroup deletes a group by ID.
func (c *Client) DeleteGroup(ctx context.Context, groupID int) error {
	const q = `mutation($g:Int!){ deleteGroup(groupId:$g){ ok } }`
	return c.gql(ctx, q, map[string]any{"g": groupID}, nil)
}

// RenameGroup changes a group's display name via lldap's updateGroup mutation
// (UpdateGroupInput mirrors the updateUser shape: an id + the fields to change).
func (c *Client) RenameGroup(ctx context.Context, groupID int, name string) error {
	const q = `mutation($g:UpdateGroupInput!){ updateGroup(group:$g){ ok } }`
	return c.gql(ctx, q, map[string]any{"g": map[string]any{
		"id": groupID, "displayName": name,
	}}, nil)
}

// AddUserToGroup adds a user to a group.
func (c *Client) AddUserToGroup(ctx context.Context, username string, groupID int) error {
	const q = `mutation($u:String!,$g:Int!){ addUserToGroup(userId:$u, groupId:$g){ ok } }`
	return c.gql(ctx, q, map[string]any{"u": username, "g": groupID}, nil)
}

// RemoveUserFromGroup removes a user from a group.
func (c *Client) RemoveUserFromGroup(ctx context.Context, username string, groupID int) error {
	const q = `mutation($u:String!,$g:Int!){ removeUserFromGroup(userId:$u, groupId:$g){ ok } }`
	return c.gql(ctx, q, map[string]any{"u": username, "g": groupID}, nil)
}

// GroupMembers returns the members of the given group.
func (c *Client) GroupMembers(ctx context.Context, groupID int) ([]Member, error) {
	const q = `query($g:Int!){ group(groupId:$g){ users { id displayName email } } }`
	var out struct {
		Group struct {
			Users []struct {
				ID          string `json:"id"`
				DisplayName string `json:"displayName"`
				Email       string `json:"email"`
			} `json:"users"`
		} `json:"group"`
	}
	if err := c.gql(ctx, q, map[string]any{"g": groupID}, &out); err != nil {
		return nil, err
	}
	ms := make([]Member, len(out.Group.Users))
	for i, u := range out.Group.Users {
		ms[i] = Member{Username: u.ID, Name: u.DisplayName, Email: u.Email}
	}
	return ms, nil
}

// UserExists reports whether a user with the given username exists in lldap.
// It queries user(userId:) and treats an entity-not-found error as a clean
// "false"; any other error is propagated.
func (c *Client) UserExists(ctx context.Context, username string) (bool, error) {
	const q = `query($u:String!){ user(userId:$u){ id } }`
	var out struct {
		User struct {
			ID string `json:"id"`
		} `json:"user"`
	}
	err := c.gql(ctx, q, map[string]any{"u": username}, &out)
	if err != nil {
		if isLldapNotFoundErr(err) {
			return false, nil
		}
		return false, err
	}
	return out.User.ID != "", nil
}

// UserGroups returns the groups the given user currently belongs to. A
// not-found user yields an empty slice (no groups) rather than an error, so
// callers re-syncing membership converge to "no groups" cleanly.
func (c *Client) UserGroups(ctx context.Context, username string) ([]Group, error) {
	const q = `query($u:String!){ user(userId:$u){ groups { id displayName } } }`
	var out struct {
		User struct {
			Groups []struct {
				ID          int    `json:"id"`
				DisplayName string `json:"displayName"`
			} `json:"groups"`
		} `json:"user"`
	}
	if err := c.gql(ctx, q, map[string]any{"u": username}, &out); err != nil {
		if isLldapNotFoundErr(err) {
			return nil, nil
		}
		return nil, err
	}
	gs := make([]Group, len(out.User.Groups))
	for i, g := range out.User.Groups {
		gs[i] = Group{ID: g.ID, Name: g.DisplayName}
	}
	return gs, nil
}

// SetPassword sets a user's password via the LDAP Password-Modify extended op.
func (c *Client) SetPassword(ctx context.Context, username, password string) error {
	conn, err := ldap.DialURL(c.cfg.LDAPURL)
	if err != nil {
		return fmt.Errorf("lldap ldap dial: %w", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.Bind(c.adminDN(), c.cfg.AdminPass); err != nil {
		return fmt.Errorf("lldap admin bind: %w", err)
	}
	req := ldap.NewPasswordModifyRequest(c.userDN(username), "", password)
	if _, err := conn.PasswordModify(req); err != nil {
		return fmt.Errorf("lldap set password: %w", err)
	}
	return nil
}

// Ensure Client implements Admin at compile time.
var _ Admin = (*Client)(nil)
