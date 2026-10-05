// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-identity/internal/health"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
)

// cutProxy forwards TCP to a real Postgres; Cut drops the listener and every
// open connection, as if the database went away, and Resume brings it back on
// the same address.
type cutProxy struct {
	t      *testing.T
	target string
	addr   string
	mu     sync.Mutex
	lis    net.Listener
	conns  []net.Conn
}

func newCutProxy(t *testing.T, target string) *cutProxy {
	p := &cutProxy{t: t, target: target}
	p.listen("127.0.0.1:0")
	t.Cleanup(p.Cut)
	return p
}

func (p *cutProxy) listen(addr string) {
	lis, err := net.Listen("tcp", addr)
	if err != nil {
		p.t.Fatalf("proxy listen: %v", err)
	}
	p.mu.Lock()
	p.lis, p.addr = lis, lis.Addr().String()
	p.mu.Unlock()
	go func() {
		for {
			c, err := lis.Accept()
			if err != nil {
				return
			}
			up, err := net.Dial("tcp", p.target)
			if err != nil {
				_ = c.Close()
				continue
			}
			p.mu.Lock()
			p.conns = append(p.conns, c, up)
			p.mu.Unlock()
			go func() { _, _ = io.Copy(up, c); _ = up.Close() }()
			go func() { _, _ = io.Copy(c, up); _ = c.Close() }()
		}
	}()
}

func (p *cutProxy) Cut() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.lis != nil {
		_ = p.lis.Close()
		p.lis = nil
	}
	for _, c := range p.conns {
		_ = c.Close()
	}
	p.conns = nil
}

func (p *cutProxy) Resume() { p.listen(p.addr) }

// TestHealth_PostgresGoesAwayAndComesBack runs readiness against a real
// Postgres (IDENTITY_PG_DSN) and a fake Kratos: cutting the database makes
// readiness NOT_SERVING while liveness stays SERVING, and readiness recovers
// once the database is back and the cache window has passed.
func TestHealth_PostgresGoesAwayAndComesBack(t *testing.T) {
	dsn := os.Getenv("IDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("set IDENTITY_PG_DSN to run the Postgres integration test")
	}
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	proxy := newCutProxy(t, u.Host)
	u.Host = proxy.addr
	ctx := context.Background()
	db, err := postgres.New(ctx, u.String())
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(db.Close)

	kratosSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/ready" {
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(kratosSrv.Close)

	clk := &testClock{t: time.Now()}
	checker := health.New(log.Nop(), []health.Dep{
		{Name: "postgres", Required: true, Check: db.Ping},
		{Name: "kratos", Required: true, Check: kratos.NewAdmin(kratosSrv.URL).Ready},
	}, health.WithClock(clk.now))
	hc := startWithHealth(t, checker)

	if st, _, err := check(t, hc, ""); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("start: %v %v", st, err)
	}
	proxy.Cut()
	clk.add(health.CacheTTL)
	st, md, err := check(t, hc, "")
	if err != nil || st != healthpb.HealthCheckResponse_NOT_SERVING {
		t.Fatalf("postgres gone: %v %v, want NOT_SERVING", st, err)
	}
	if r := healthHeader(t, md); r.Dependencies[0].State != health.Down || r.Dependencies[1].State != health.OK {
		t.Fatalf("header: %+v", r)
	}
	if st, _, err := check(t, hc, LivenessService); err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("liveness: %v %v", st, err)
	}

	proxy.Resume()
	deadline := time.Now().Add(15 * time.Second)
	for {
		clk.add(health.CacheTTL)
		st, _, err = check(t, hc, "")
		if (err == nil && st == healthpb.HealthCheckResponse_SERVING) || time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if err != nil || st != healthpb.HealthCheckResponse_SERVING {
		t.Fatalf("recovered: %v %v", st, err)
	}
}
