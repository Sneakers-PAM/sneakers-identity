// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/server"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/baggage"
	"go.opentelemetry.io/otel/metric"
	colmetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	coltracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/types/known/emptypb"
)

const getUser = "sneakers.identity.v1.IdentityService/GetUser"

type wire struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *wire) add(s string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.WriteString(s)
}

func (w *wire) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

type traceCollector struct {
	coltracepb.UnimplementedTraceServiceServer
	w *wire
}

func (c traceCollector) Export(_ context.Context, r *coltracepb.ExportTraceServiceRequest) (*coltracepb.ExportTraceServiceResponse, error) {
	c.w.add(prototext.Format(r))
	return &coltracepb.ExportTraceServiceResponse{}, nil
}

type metricCollector struct {
	colmetricspb.UnimplementedMetricsServiceServer
	w *wire
}

func (c metricCollector) Export(_ context.Context, r *colmetricspb.ExportMetricsServiceRequest) (*colmetricspb.ExportMetricsServiceResponse, error) {
	c.w.add(prototext.Format(r))
	return &colmetricspb.ExportMetricsServiceResponse{}, nil
}

func startFullCollector(t *testing.T) (string, *wire) {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	w := &wire{}
	s := grpc.NewServer()
	coltracepb.RegisterTraceServiceServer(s, traceCollector{w: w})
	colmetricspb.RegisterMetricsServiceServer(s, metricCollector{w: w})
	go func() { _ = s.Serve(lis) }()
	t.Cleanup(s.Stop)
	return "http://" + lis.Addr().String(), w
}

type canaryIdentity struct {
	identityv1.UnimplementedIdentityServiceServer
	baggageMembers chan int
}

func (s *canaryIdentity) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	s.baggageMembers <- baggage.FromContext(ctx).Len()
	if req.GetId() == "panic" {
		panic(errors.New("canary-panic"))
	}
	return nil, status.Error(codes.NotFound, "canary-status")
}

func dialIdentity(t *testing.T, register func(*grpc.Server)) *grpc.ClientConn {
	t.Helper()
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := lis.Addr().(*net.TCPAddr)
	_ = lis.Close()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = server.RunWithLogger(ctx, strconv.Itoa(addr.Port), log.Nop(), register)
	}()
	t.Cleanup(func() { cancel(); <-done })
	conn, err := grpc.NewClient(addr.String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Real calls through the service's own gRPC server, with a canary on every path
// the SDK and otelgrpc copy text from.
func TestCanariesNeverReachTheCollector(t *testing.T) {
	t.Setenv("OTEL_RESOURCE_ATTRIBUTES", "canary.resource=canary-resource")
	endpoint, got := startFullCollector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	shutdown, err := Start(ctx, "identity-test", Settings{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}

	svc := &canaryIdentity{baggageMembers: make(chan int, 2)}
	conn := dialIdentity(t, func(s *grpc.Server) { identityv1.RegisterIdentityServiceServer(s, svc) })
	client := identityv1.NewIdentityServiceClient(conn)

	callCtx := metadata.AppendToOutgoingContext(ctx,
		"traceparent", "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01",
		"tracestate", "vendor=canary-tracestate",
		"baggage", "member=canary-baggage")
	for _, id := range []string{"missing", "panic"} {
		if _, err := client.GetUser(callCtx, &identityv1.GetUserRequest{Id: id}, grpc.WaitForReady(true)); status.Code(err) == codes.OK {
			t.Fatalf("GetUser(%s) succeeded", id)
		}
	}
	for range 2 {
		if n := <-svc.baggageMembers; n != 0 {
			t.Errorf("handler saw %d baggage members", n)
		}
	}
	if err := conn.Invoke(ctx, "/canary-method.Service/Canary", &emptypb.Empty{}, &emptypb.Empty{}); status.Code(err) != codes.Unimplemented {
		t.Fatalf("unknown method: %v", err)
	}

	_, span := otel.Tracer("canary").Start(ctx, "SELECT canary-span-name")
	span.End()

	counter, err := otel.Meter("canary").Int64Counter("canary.count")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(ctx, 1, metric.WithAttributes(
		attribute.String("rpc.method", "canary-metric-value"),
		attribute.String("canary.attr", "canary-metric-attr")))

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	exported := got.String()
	for _, want := range []string{getUser, `"rpc.method"`, `"rpc.response.status_code"`, "identity-test", "[span]"} {
		if !strings.Contains(exported, want) {
			t.Errorf("export is missing %q", want)
		}
	}
	for _, leak := range []string{"canary-", "exception", "server.address", "network.peer"} {
		if strings.Contains(exported, leak) {
			t.Errorf("collector received %q", leak)
		}
	}
	if t.Failed() {
		t.Logf("export: %s", exported)
	}
}

func TestLibraryErrorTextStaysOffTheLogs(t *testing.T) {
	c := &collector{}
	start(t, Settings{Endpoint: startCollector(t, c), Logs: true})

	lg := NewLogger("identity-test", true)
	lg.Info("line", log.F("user_id", "usr-allowed"),
		log.F("outcome", "canary-outcome"), log.F("reason", "canary-reason"))

	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(c.received(), "usr-allowed") {
		time.Sleep(100 * time.Millisecond)
	}
	wire := c.received()
	if !strings.Contains(wire, "usr-allowed") {
		t.Fatalf("allowed field missing from export: %q", wire)
	}
	for _, canary := range []string{"canary-outcome", "canary-reason"} {
		if strings.Contains(wire, canary) {
			t.Errorf("collector received %q", canary)
		}
	}
}

func TestQueriesExportOnlyTheirOperation(t *testing.T) {
	dsn := os.Getenv("IDENTITY_PG_DSN")
	if dsn == "" {
		t.Skip("IDENTITY_PG_DSN not set")
	}
	endpoint, got := startFullCollector(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	shutdown, err := Start(ctx, "identity-test", Settings{Endpoint: endpoint})
	if err != nil {
		t.Fatal(err)
	}
	db, err := postgres.New(ctx, dsn, PostgresTracing())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	spanCtx, span := otel.Tracer("test").Start(ctx, "parent")
	if _, err := db.Querier().Exec(spanCtx, "SELECT 'canary-sql'"); err != nil {
		t.Fatal(err)
	}
	_, _ = db.Querier().Exec(spanCtx, "SELECT 'canary-sql'::int")
	span.End()

	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	exported := got.String()
	if !strings.Contains(exported, `"query SELECT"`) {
		t.Errorf("no query span: %s", exported)
	}
	if strings.Contains(exported, "canary-sql") {
		t.Errorf("collector received the statement: %s", exported)
	}
}
