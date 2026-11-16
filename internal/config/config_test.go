// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"testing"

	mtls "github.com/Bugs5382/go-mtls"
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
	if c.OTLPEndpoint != "" {
		t.Fatalf("default OTLPEndpoint got %q, want empty (no collector)", c.OTLPEndpoint)
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

func TestOTLPSwitchesAreOnOnlyForTrue(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	for value, want := range map[string]bool{"": false, "1": false, "TRUE": false, "true": true} {
		t.Setenv("OTLP_INSECURE_SKIP_VERIFY", value)
		t.Setenv("OTLP_LOGS_ENABLED", value)
		c, err := Load()
		if err != nil {
			t.Fatal(err)
		}
		if c.OTLPInsecureSkipVerify != want || c.OTLPLogsEnabled != want {
			t.Fatalf("%q: skip %v logs %v, want %v", value, c.OTLPInsecureSkipVerify, c.OTLPLogsEnabled, want)
		}
	}
}

func clearMTLS(t *testing.T) {
	t.Helper()
	for _, k := range []string{"MTLS_CERT_FILE", "MTLS_KEY_FILE", "MTLS_CA_FILE"} {
		t.Setenv(k, "")
	}
}

func TestLoadMTLSOffByDefault(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	clearMTLS(t)
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if c.MTLSEnabled {
		t.Fatal("MTLSEnabled with no MTLS_* set, want plaintext")
	}
	if c.HealthPort != "9091" {
		t.Fatalf("default HealthPort got %q", c.HealthPort)
	}
}

func TestLoadMTLSFiles(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	t.Setenv("MTLS_CERT_FILE", "/tls/tls.crt")
	t.Setenv("MTLS_KEY_FILE", "/tls/tls.key")
	t.Setenv("MTLS_CA_FILE", "/tls/ca.crt")
	t.Setenv("HEALTH_PORT", "9999")
	c, err := Load()
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	want := mtls.Files{Cert: "/tls/tls.crt", Key: "/tls/tls.key", CA: "/tls/ca.crt"}
	if !c.MTLSEnabled || c.MTLSFiles != want {
		t.Fatalf("got %+v", c)
	}
	if c.HealthPort != "9999" {
		t.Fatalf("HealthPort got %q", c.HealthPort)
	}
}

// A half-set trio must stop the boot instead of quietly serving plaintext.
func TestLoadMTLSPartialFailsClosed(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	clearMTLS(t)
	t.Setenv("MTLS_CERT_FILE", "/tls/tls.crt")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when only some MTLS_* variables are set")
	}
}

func TestLoadMTLSHealthPortMustDiffer(t *testing.T) {
	t.Setenv("DATABASE_DSN", "postgres://x")
	t.Setenv("MTLS_CERT_FILE", "/tls/tls.crt")
	t.Setenv("MTLS_KEY_FILE", "/tls/tls.key")
	t.Setenv("MTLS_CA_FILE", "/tls/ca.crt")
	t.Setenv("HEALTH_PORT", "9090")
	if _, err := Load(); err == nil {
		t.Fatal("expected an error when HEALTH_PORT equals GRPC_PORT under mTLS")
	}
}
