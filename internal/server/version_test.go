// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	buildinfo "github.com/Bugs5382/go-buildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
)

func stampBuild(t *testing.T) {
	t.Helper()
	oldV, oldC := buildinfo.Version, buildinfo.Commit
	buildinfo.Version, buildinfo.Commit = "v9.9.9-test", "0123456789abcdef"
	t.Cleanup(func() { buildinfo.Version, buildinfo.Commit = oldV, oldC })
}

// TestRun_HealthCheckReportsBuild checks the health answer carries the build's
// version and commit in its response headers, for the gateway's diagnostics.
func TestRun_HealthCheckReportsBuild(t *testing.T) {
	stampBuild(t)

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
	if got := md.Get("sneakers-version"); len(got) != 1 || got[0] != "v9.9.9-test" {
		t.Errorf("sneakers-version = %v, want v9.9.9-test", got)
	}
	if got := md.Get("sneakers-commit"); len(got) != 1 || got[0] != "0123456789abcdef" {
		t.Errorf("sneakers-commit = %v, want 0123456789abcdef", got)
	}
}

// TestHealthCheck_HeaderNames pins the exact header names the gateway's
// diagnostics read, on readiness and on liveness.
func TestHealthCheck_HeaderNames(t *testing.T) {
	stampBuild(t)
	hc := startWithHealth(t, newTestChecker(t,
		health.Dependency{Name: "postgres", Required: true, Check: func(context.Context) error { return nil },
			Version: func(context.Context) (string, error) { return "17.11", nil }},
		health.Dependency{Name: "kratos", Required: true, Check: func(context.Context) error { return nil }},
	))
	sneakersKeys := func(md metadata.MD) []string {
		var keys []string
		for k := range md {
			if strings.HasPrefix(k, "sneakers-") {
				keys = append(keys, k)
			}
		}
		slices.Sort(keys)
		return keys
	}

	_, md, err := check(t, hc, "")
	if err != nil {
		t.Fatalf("readiness: %v", err)
	}
	want := []string{"sneakers-commit", "sneakers-dep-postgres", "sneakers-depstate-kratos", "sneakers-depstate-postgres", "sneakers-health", "sneakers-version"}
	if got := sneakersKeys(md); !slices.Equal(got, want) {
		t.Fatalf("readiness headers = %v, want %v", got, want)
	}
	if got := md.Get("sneakers-dep-postgres"); len(got) != 1 || got[0] != "17.11" {
		t.Fatalf("sneakers-dep-postgres = %v", got)
	}

	_, md, err = check(t, hc, LivenessService)
	if err != nil {
		t.Fatalf("liveness: %v", err)
	}
	if got, want := sneakersKeys(md), []string{"sneakers-commit", "sneakers-version"}; !slices.Equal(got, want) {
		t.Fatalf("liveness headers = %v, want %v", got, want)
	}
}
