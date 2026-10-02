// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strings"
	"testing"
)

func TestLoadRequiredAndDefault(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.DatabaseDSN != "postgres://x" {
		t.Fatalf("got %q", c.DatabaseDSN)
	}
	if c.GRPCPort != "9090" {
		t.Fatalf("default GRPCPort got %q", c.GRPCPort)
	}
}

func TestLoadMissingRequired(t *testing.T) {
	if err := os.Unsetenv("DATABASE_DSN"); err != nil {
		t.Fatalf("unsetenv: %v", err)
	}
	if _, err := Load(); err == nil {
		t.Fatal("expected error for missing DATABASE_DSN")
	}
}

func TestLoadAuthBackend(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	for _, ok := range []string{"", "kratos"} {
		t.Setenv("AUTH_BACKEND", ok)
		if _, err := Load(); err != nil {
			t.Errorf("AUTH_BACKEND=%q: unexpected err: %v", ok, err)
		}
	}
	t.Setenv("AUTH_BACKEND", "keycloak")
	_, err := Load()
	if err == nil || !strings.Contains(err.Error(), "Keycloak is not supported") {
		t.Errorf("AUTH_BACKEND=keycloak: err = %v, want a Keycloak is not supported error", err)
	}
	t.Setenv("AUTH_BACKEND", "ldap")
	if _, err := Load(); err == nil {
		t.Error("AUTH_BACKEND=ldap: want an error for an unknown backend")
	}
}
