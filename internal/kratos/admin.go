// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package kratos is identity's client for the Ory Kratos admin API: the
// directory writes (create, update, delete, set password) and the recovery
// codes identity needs to provision users now that Kratos holds credentials.
package kratos

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Sneakers-PAM/sneakers-identity/internal/health"
)

var (
	ErrNotFound = errors.New("kratos: identity not found")
	ErrConflict = errors.New("kratos: identity already exists")
)

type Admin struct {
	baseURL string
	http    *http.Client
}

func NewAdmin(adminURL string) *Admin {
	return &Admin{baseURL: strings.TrimRight(adminURL, "/"), http: &http.Client{Timeout: 15 * time.Second}}
}

type traits struct {
	Email     string `json:"email"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`
}

func traitsFor(email, name string) traits {
	first, last, _ := strings.Cut(strings.TrimSpace(name), " ")
	return traits{Email: strings.TrimSpace(email), FirstName: first, LastName: strings.TrimSpace(last)}
}

type identity struct {
	ID       string          `json:"id"`
	SchemaID string          `json:"schema_id"`
	State    string          `json:"state"`
	Traits   json.RawMessage `json:"traits"`
}

func (a *Admin) do(ctx context.Context, method, path string, body, out any) (int, error) {
	var rd *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, rd) // #nosec G704 -- baseURL is the operator-configured Kratos admin URL
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := a.http.Do(req) // #nosec G704 -- see above
	if err != nil {
		return 0, fmt.Errorf("kratos %s %s: %w", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	if out != nil && res.StatusCode < 300 {
		if err := json.NewDecoder(res.Body).Decode(out); err != nil {
			return res.StatusCode, fmt.Errorf("kratos %s %s: decode: %w", method, path, err)
		}
	}
	return res.StatusCode, nil
}

func statusErr(method, path string, code int) error {
	switch code {
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusConflict:
		return ErrConflict
	}
	return fmt.Errorf("kratos %s %s: unexpected status %d", method, path, code)
}

// CreateIdentity creates an identity with no credentials; the user sets a
// password through a recovery code, so nobody else ever handles it.
func (a *Admin) CreateIdentity(ctx context.Context, email, name string) (string, error) {
	var out identity
	code, err := a.do(ctx, http.MethodPost, "/admin/identities", map[string]any{
		"schema_id": "default", "traits": traitsFor(email, name),
	}, &out)
	if err != nil {
		return "", err
	}
	if code != http.StatusCreated && code != http.StatusOK {
		return "", statusErr(http.MethodPost, "/admin/identities", code)
	}
	return out.ID, nil
}

func (a *Admin) FindIdentityByEmail(ctx context.Context, email string) (string, error) {
	var out []identity
	path := "/admin/identities?credentials_identifier=" + url.QueryEscape(strings.TrimSpace(email))
	code, err := a.do(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return "", err
	}
	if code != http.StatusOK {
		return "", statusErr(http.MethodGet, "/admin/identities", code)
	}
	if len(out) == 0 {
		return "", ErrNotFound
	}
	return out[0].ID, nil
}

func (a *Admin) get(ctx context.Context, id string) (identity, error) {
	var out identity
	path := "/admin/identities/" + url.PathEscape(id)
	code, err := a.do(ctx, http.MethodGet, path, nil, &out)
	if err != nil {
		return identity{}, err
	}
	if code != http.StatusOK {
		return identity{}, statusErr(http.MethodGet, "/admin/identities/{id}", code)
	}
	return out, nil
}

// put replaces the identity; Kratos's PUT requires schema, state and traits,
// so they are carried over from the current identity.
func (a *Admin) put(ctx context.Context, cur identity, tr any, credentials map[string]any) error {
	body := map[string]any{"schema_id": cur.SchemaID, "state": cur.State, "traits": tr}
	if credentials != nil {
		body["credentials"] = credentials
	}
	code, err := a.do(ctx, http.MethodPut, "/admin/identities/"+url.PathEscape(cur.ID), body, nil)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return statusErr(http.MethodPut, "/admin/identities/{id}", code)
	}
	return nil
}

func (a *Admin) SetPassword(ctx context.Context, id, password string) error {
	cur, err := a.get(ctx, id)
	if err != nil {
		return err
	}
	return a.put(ctx, cur, cur.Traits, map[string]any{
		"password": map[string]any{"config": map[string]string{"password": password}},
	})
}

func (a *Admin) UpdateTraits(ctx context.Context, id, email, name string) error {
	cur, err := a.get(ctx, id)
	if err != nil {
		return err
	}
	return a.put(ctx, cur, traitsFor(email, name), nil)
}

func (a *Admin) DeleteIdentity(ctx context.Context, id string) error {
	code, err := a.do(ctx, http.MethodDelete, "/admin/identities/"+url.PathEscape(id), nil, nil)
	if err != nil {
		return err
	}
	if code != http.StatusNoContent && code != http.StatusOK && code != http.StatusNotFound {
		return statusErr(http.MethodDelete, "/admin/identities/{id}", code)
	}
	return nil
}

// Ready asks Kratos's /health/ready, for identity's readiness. A status other
// than 2xx is a health.HTTPStatusError.
func (a *Admin) Ready(ctx context.Context) error {
	code, err := a.do(ctx, http.MethodGet, "/health/ready", nil, nil)
	if err != nil {
		return err
	}
	if code < 200 || code > 299 {
		return &health.HTTPStatusError{Code: code}
	}
	return nil
}
