// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"bytes"
	"context"
	"errors"
	stdlog "log"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	"go.opentelemetry.io/otel"
	collogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
)

type collector struct {
	collogspb.UnimplementedLogsServiceServer
	fail error

	mu   sync.Mutex
	wire strings.Builder
}

func (c *collector) Export(_ context.Context, req *collogspb.ExportLogsServiceRequest) (*collogspb.ExportLogsServiceResponse, error) {
	if c.fail != nil {
		return nil, c.fail
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wire.WriteString(prototext.Format(req))
	return &collogspb.ExportLogsServiceResponse{}, nil
}

func (c *collector) received() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.wire.String()
}

func startCollector(t *testing.T, c *collector) string {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := grpc.NewServer()
	collogspb.RegisterLogsServiceServer(s, c)
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return "http://" + lis.Addr().String()
}

func start(t *testing.T, s Settings) {
	t.Helper()
	shutdown, err := Start(context.Background(), "identity-test", s)
	if err != nil {
		t.Fatalf("start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = shutdown(ctx)
	})
}

func TestDependenciesOnlyWithAnEndpoint(t *testing.T) {
	if got := Dependencies(Settings{}); len(got) != 0 {
		t.Fatalf("no endpoint: %+v", got)
	}
	got := Dependencies(Settings{Endpoint: "http://collector.example.org:4317"})
	if len(got) != 1 || got[0].Name != "otlp" || got[0].Required {
		t.Fatalf("with endpoint: %+v", got)
	}
}

func TestUnsetSettingsExportNothing(t *testing.T) {
	start(t, Settings{})
	st := gootel.ExportState()
	if st.Configured {
		t.Fatalf("state: %+v", st)
	}
	if off := st.Logs.Disabled; off != "" {
		t.Fatalf("logs off reason with no collector: %q", off)
	}
}

func TestExportCheck(t *testing.T) {
	now := time.Now()
	ok := gootel.SignalStatus{LastSuccess: now}
	failing := gootel.SignalStatus{LastSuccess: now.Add(-time.Minute), LastErrorAt: now}
	cases := []struct {
		name string
		st   gootel.ExportStatus
		logs bool
		down bool
	}{
		{name: "nothing yet"},
		{name: "healthy", st: gootel.ExportStatus{Traces: ok, Metrics: ok}},
		{name: "traces failing", st: gootel.ExportStatus{Traces: failing, Metrics: ok}, down: true},
		{name: "metrics failing", st: gootel.ExportStatus{Traces: ok, Metrics: failing}, down: true},
		{name: "logs failing, logs off", st: gootel.ExportStatus{Logs: failing}},
		{name: "logs failing, logs on", st: gootel.ExportStatus{Logs: failing}, logs: true, down: true},
		{name: "recovered", st: gootel.ExportStatus{Traces: gootel.SignalStatus{LastErrorAt: now.Add(-time.Minute), LastSuccess: now}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := exportCheck(c.st, c.logs); (err != nil) != c.down {
				t.Fatalf("err = %v, want down %v", err, c.down)
			}
		})
	}
}

// A collector that refuses every export degrades the service; readiness holds.
func TestFailingCollectorDegradesAndKeepsReadiness(t *testing.T) {
	const canary = "collector-text-canary"
	endpoint := startCollector(t, &collector{fail: status.Error(codes.PermissionDenied, canary)})
	s := Settings{Endpoint: endpoint, Logs: true}
	start(t, s)

	lg := NewLogger("identity-test", true)
	checker := health.New(health.WithTTL(time.Millisecond), health.WithTimeout(time.Second))
	if err := checker.Register(Dependencies(s)...); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		lg.Info("export attempt")
		rep := checker.Report(context.Background())
		if rep.Status == health.StateDegraded {
			if !rep.Ready {
				t.Fatalf("not ready: %+v", rep)
			}
			if strings.Contains(rep.Dependencies[0].Error, canary) {
				t.Fatalf("report carries collector text: %+v", rep)
			}
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("never degraded: %+v", gootel.ExportState())
}

func TestUnallowedFieldsNeverReachTheCollector(t *testing.T) {
	c := &collector{}
	start(t, Settings{Endpoint: startCollector(t, c), Logs: true})

	lg := NewLogger("identity-test", true)
	lg.Info("canary line",
		log.F("user_id", "usr-allowed"),
		log.F("email", "canary-email@example.org"),
		log.F("username", "canary-username"),
		log.F("otp_code", "canary-otp"),
		log.F("error", "canary-error-text"),
		log.F("stack", "canary-stack"),
	)
	lg.Info("key snk_canaryTokenValue1 used")

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(c.received(), "key ") {
		time.Sleep(100 * time.Millisecond)
	}
	wire := c.received()
	if !strings.Contains(wire, "usr-allowed") {
		t.Fatalf("allowed field missing from export: %q", wire)
	}
	for _, canary := range []string{"canary-email", "canary-username", "canary-otp", "canary-error-text", "canary-stack", "canaryTokenValue1"} {
		if strings.Contains(wire, canary) {
			t.Errorf("collector received %q", canary)
		}
	}
}

func TestExportErrorsLeaveOutTheText(t *testing.T) {
	var out bytes.Buffer
	stdlog.SetOutput(&out)
	t.Cleanup(func() { stdlog.SetOutput(os.Stderr) })
	start(t, Settings{})

	secret := "dial collector.example.org:4317 Authorization=canary"
	otel.Handle(errors.New(secret))
	otel.Handle(status.Error(codes.Unavailable, secret))

	line := out.String()
	if strings.Count(line, "\n") != 1 {
		t.Fatalf("want 1 line inside one window, got %q", line)
	}
	if strings.Contains(line, "canary") || strings.Contains(line, "collector.example.org") {
		t.Fatalf("leaked: %s", line)
	}
}
