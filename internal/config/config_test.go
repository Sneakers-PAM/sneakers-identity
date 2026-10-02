// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
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

func TestLoadAuditAddr(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	t.Setenv("AUDIT_ADDR", "")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.AuditAddr != "" {
		t.Fatalf("AuditAddr unset got %q, want empty (audit off)", c.AuditAddr)
	}
	t.Setenv("AUDIT_ADDR", "sneakers-audit:9194")
	if c, _ = Load(); c.AuditAddr != "sneakers-audit:9194" {
		t.Fatalf("AuditAddr got %q", c.AuditAddr)
	}
}
