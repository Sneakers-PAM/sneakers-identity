// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package kratos

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/Sneakers-PAM/sneakers-identity/internal/health"
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
	if err := a.Ready(context.Background()); health.Classify(err) != "error" {
		t.Fatalf("503: %v", err)
	}
	srv.Close()
	if err := a.Ready(context.Background()); err == nil || health.Classify(err) == "error" {
		t.Fatalf("closed: %v (class %q), want a network class", err, health.Classify(err))
	}
}
