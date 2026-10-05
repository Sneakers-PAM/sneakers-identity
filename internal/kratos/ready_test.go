// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Bugs5382/go-buildinfo/health"
)

func TestAdmin_Ready(t *testing.T) {
	var code atomic.Int32
	code.Store(http.StatusOK)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/health/ready" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(int(code.Load()))
	}))
	a := NewAdmin(srv.URL + "/")
	if err := a.Ready(context.Background()); err != nil {
		t.Fatalf("ready: %v", err)
	}
	code.Store(http.StatusServiceUnavailable)
	if err := a.Ready(context.Background()); classOf(t, a) != "error" {
		t.Fatalf("503: %v", err)
	}
	code.Store(http.StatusForbidden)
	if err := a.Ready(context.Background()); classOf(t, a) != "unauthenticated" {
		t.Fatalf("403: %v", err)
	}
	srv.Close()
	if err := a.Ready(context.Background()); err == nil || classOf(t, a) == "error" {
		t.Fatalf("closed: %v (class %q), want a network class", err, classOf(t, a))
	}
}

// classOf is the error class a readiness report gives a failing Ready.
func classOf(t *testing.T, a *Admin) string {
	t.Helper()
	c := health.New()
	if err := c.Register(health.Dependency{Name: "kratos", Required: true, Check: a.Ready}); err != nil {
		t.Fatal(err)
	}
	return c.Report(context.Background()).Dependencies[0].Error
}
