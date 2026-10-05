// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/Bugs5382/go-buildinfo/health"
	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc/metadata"
)

// healthHeaders runs a server whose postgres dependency reports version, and
// returns one readiness check's response headers.
func healthHeaders(t *testing.T, version func(context.Context) (string, error)) metadata.MD {
	t.Helper()
	hc := startWithHealth(t, newTestChecker(t, health.Dependency{Name: "postgres", Required: true,
		Check: func(context.Context) error { return nil }, Version: version}))
	_, md, err := check(t, hc, "")
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	return md
}

func rawVersion(raw string) func(context.Context) (string, error) {
	return func(context.Context) (string, error) { return dependencyVersion(raw), nil }
}

func TestHealthCheck_ReportsDependencyVersion(t *testing.T) {
	if got := healthHeaders(t, rawVersion("16.4 (Debian 16.4-1.pgdg120+2)")).Get("sneakers-dep-postgres"); len(got) != 1 || got[0] != "16.4" {
		t.Fatalf("sneakers-dep-postgres = %v, want [16.4]", got)
	}
}

func TestHealthCheck_DependencyVersionCapped(t *testing.T) {
	if got := healthHeaders(t, rawVersion(strings.Repeat("9", 100))).Get("sneakers-dep-postgres"); len(got) != 1 || len(got[0]) != 64 {
		t.Fatalf("sneakers-dep-postgres = %v, want one value of 64 characters", got)
	}
}

func TestHealthCheck_DependencyVersionUnknownWhenUnread(t *testing.T) {
	failed := func(context.Context) (string, error) { return "", errors.New("no database") }
	if got := healthHeaders(t, failed).Get("sneakers-dep-postgres"); len(got) != 1 || got[0] != "unknown" {
		t.Fatalf("sneakers-dep-postgres = %v, want [unknown]", got)
	}
}

// TestPostgresVersion reads the version from a real server. Set IDENTITY_PG_DSN to run it.
func TestPostgresVersion(t *testing.T) {
	dsn := os.Getenv("IDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set IDENTITY_PG_DSN to run the Postgres integration test")
	}
	ctx := context.Background()
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer db.Close()
	got := healthHeaders(t, PostgresVersion(db.Querier())).Get("sneakers-dep-postgres")
	if len(got) != 1 || got[0] == "" || got[0] == "unknown" || strings.ContainsAny(got[0], " (") {
		t.Fatalf("sneakers-dep-postgres = %v, want the bare server version", got)
	}
	t.Logf("server version %s", got[0])
}
