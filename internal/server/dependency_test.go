// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	postgres "github.com/Bugs5382/go-postgres"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

// healthHeaders runs a server and returns one health check's response headers.
func healthHeaders(t *testing.T) metadata.MD {
	t.Helper()
	port := freePort(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, port, nil) }()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient("127.0.0.1:"+port, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	var md metadata.MD
	deadline := time.Now().Add(5 * time.Second)
	for {
		cctx, ccancel := context.WithTimeout(context.Background(), time.Second)
		_, err = healthpb.NewHealthClient(conn).Check(cctx, &healthpb.HealthCheckRequest{}, grpc.Header(&md), grpc.WaitForReady(true))
		ccancel()
		if err == nil || time.Now().After(deadline) {
			break
		}
	}
	if err != nil {
		t.Fatalf("health check: %v", err)
	}
	return md
}

func TestHealthCheck_ReportsDependencyVersion(t *testing.T) {
	SetDependencyVersion("postgres", "16.4 (Debian 16.4-1.pgdg120+2)")
	t.Cleanup(func() { SetDependencyVersion("postgres", "") })
	if got := healthHeaders(t).Get(HeaderDependencyPrefix + "postgres"); len(got) != 1 || got[0] != "16.4" {
		t.Fatalf("sneakers-dep-postgres = %v, want [16.4]", got)
	}
}

func TestHealthCheck_DependencyVersionCapped(t *testing.T) {
	SetDependencyVersion("postgres", strings.Repeat("9", 100))
	t.Cleanup(func() { SetDependencyVersion("postgres", "") })
	if got := healthHeaders(t).Get(HeaderDependencyPrefix + "postgres"); len(got) != 1 || len(got[0]) != 64 {
		t.Fatalf("sneakers-dep-postgres = %v, want one value of 64 characters", got)
	}
}

func TestHealthCheck_NoDependencyHeaderWhenUnknown(t *testing.T) {
	SetDependencyVersion("postgres", "")
	if got := healthHeaders(t).Get(HeaderDependencyPrefix + "postgres"); len(got) != 0 {
		t.Fatalf("sneakers-dep-postgres = %v, want none", got)
	}
}

// TestRecordPostgresVersion reads the version from a real server. Set IDENTITY_PG_DSN to run it.
func TestRecordPostgresVersion(t *testing.T) {
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
	t.Cleanup(func() { SetDependencyVersion("postgres", "") })
	if err := RecordPostgresVersion(ctx, db.Querier()); err != nil {
		t.Fatalf("RecordPostgresVersion: %v", err)
	}
	got := healthHeaders(t).Get(HeaderDependencyPrefix + "postgres")
	if len(got) != 1 || got[0] == "" || strings.ContainsAny(got[0], " (") {
		t.Fatalf("sneakers-dep-postgres = %v, want the bare server version", got)
	}
	t.Logf("server version %s", got[0])
}
