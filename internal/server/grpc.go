// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package server provides a Run helper that boots a gRPC server with the
// health and reflection services and graceful shutdown on context
// cancellation. Health service "" is readiness, which follows the
// dependencies a health.Checker watches; service "liveness" is the process
// only.
package server

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/Bugs5382/go-buildinfo/grpcbuildinfo"
	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	"go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc"
	"google.golang.org/grpc"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"
)

// gracefulStopTimeout bounds how long Run will wait for in-flight RPCs to
// drain before forcibly stopping the server. Without it, a hung peer could
// keep GracefulStop blocked indefinitely.
const gracefulStopTimeout = 10 * time.Second

// Run boots a gRPC server listening on :port, registers the health and
// reflection services, calls register to attach caller-owned services, then
// serves until ctx is cancelled. On cancellation it performs a graceful stop
// and returns nil. A non-nil error indicates a fatal startup or serve failure.
//
// Optional grpc.ServerOptions (e.g. interceptors) are passed through to
// grpc.NewServer; callers that pass none get the previous behaviour.
func Run(ctx context.Context, port string, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithLogger(ctx, port, log.Nop(), register, opts...)
}

// RunWithLogger is Run with lg logging the panics the recovery interceptors
// catch. Run itself discards them.
func RunWithLogger(ctx context.Context, port string, lg log.Logger, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealth(ctx, port, lg, nil, register, opts...)
}

// RunWithHealth is RunWithLogger with readiness following checker's
// dependencies. A nil checker is always ready.
func RunWithHealth(ctx context.Context, port string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	return RunWithHealthPort(ctx, port, "", lg, checker, register, opts...)
}

// RunWithHealthPort is RunWithHealth that also serves the health service,
// alone and without transport security, on healthPort when it is not empty.
// With mutual TLS in opts the kubelet's gRPC probe cannot reach the main
// port, so it probes this one. It carries the same readiness report and
// liveness service as the main port and nothing else.
func RunWithHealthPort(ctx context.Context, port, healthPort string, lg log.Logger, checker *health.Checker, register func(*grpc.Server), opts ...grpc.ServerOption) error {
	hs, bi, err := newHealth(checker)
	if err != nil {
		return fmt.Errorf("health: %w", err)
	}
	lis, err := net.Listen("tcp", ":"+port)
	if err != nil {
		return fmt.Errorf("listen: %w", err)
	}

	// Build the default ServerOptions, prepended before caller-supplied opts.
	//
	//   - StatsHandler(otelgrpc): traces every service by default. Prepended so
	//     a caller StatsHandler (gRPC applies the last one) can still override.
	//   - ChainUnaryInterceptor(recovery) / StreamInterceptor(recovery): make
	//     panic recovery the OUTERMOST interceptor. grpc.ChainUnaryInterceptor
	//     is additive across ServerOptions (v1.81.x appends, no "last wins"),
	//     and the chain executes first-added-outermost. Prepending our
	//     ChainUnaryInterceptor before caller opts means recovery runs before
	//     any caller-supplied interceptor (e.g. an auth interceptor) and before the
	//     handler, so it catches panics from all of them. The otelgrpc
	//     StatsHandler still creates the server span first, so the recovery
	//     interceptor can record the panic on a live span.
	//
	// ChainStreamInterceptor is additive (like the unary chain), so a caller
	// that later supplies its own stream interceptor composes with recovery
	// rather than panicking (plain grpc.StreamInterceptor allows only one and
	// panics on a second).
	defaults := []grpc.ServerOption{
		grpc.StatsHandler(otelgrpc.NewServerHandler()),
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(lg), bi.UnaryServerInterceptor(), reportUnaryInterceptor(checker)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(lg), bi.StreamServerInterceptor()),
	}
	opts = append(defaults, opts...)

	s := grpc.NewServer(opts...)
	healthpb.RegisterHealthServer(s, hs)
	reflection.Register(s)
	if register != nil {
		register(s)
	}

	hsrv, hlis, err := newHealthOnly(healthPort, lg, hs, bi, checker)
	if err != nil {
		_ = lis.Close()
		return err
	}

	biCtx, stopBI := context.WithCancel(ctx)
	defer stopBI()
	go bi.Run(biCtx)
	if checker != nil {
		go checker.Run(biCtx)
	}

	errCh := make(chan error, 2)
	go func() {
		if err := s.Serve(lis); err != nil {
			errCh <- err
			return
		}
		errCh <- nil
	}()
	serveHealthOnly(hsrv, hlis, s, errCh)
	stopHealth := func(graceful bool) {
		if hsrv == nil {
			return
		}
		if graceful {
			hsrv.GracefulStop()
			return
		}
		hsrv.Stop()
	}

	select {
	case <-ctx.Done():
		hs.Shutdown()
		stopped := make(chan struct{})
		go func() {
			s.GracefulStop()
			stopHealth(true)
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-time.After(gracefulStopTimeout):
			s.Stop()
			stopHealth(false)
		}
		if err := <-errCh; err != nil {
			lg.Warn("server stopped with an error while shutting down", log.F("error", err.Error()))
		}
		return nil
	case err := <-errCh:
		stopHealth(false)
		return err
	}
}

// newHealthOnly builds the plain server that serves only the health service on
// healthPort, with the same readiness report and liveness as the main port. An
// empty healthPort returns nils: there is no such server.
func newHealthOnly(healthPort string, lg log.Logger, hs healthpb.HealthServer, bi *grpcbuildinfo.Server, checker *health.Checker) (*grpc.Server, net.Listener, error) {
	if healthPort == "" {
		return nil, nil, nil
	}
	lis, err := net.Listen("tcp", ":"+healthPort)
	if err != nil {
		return nil, nil, fmt.Errorf("listen health: %w", err)
	}
	srv := grpc.NewServer(
		grpc.ChainUnaryInterceptor(RecoveryUnaryInterceptor(lg), bi.UnaryServerInterceptor(), reportUnaryInterceptor(checker)),
		grpc.ChainStreamInterceptor(RecoveryStreamInterceptor(lg), bi.StreamServerInterceptor()),
	)
	healthpb.RegisterHealthServer(srv, hs)
	lg.Info("health-only port serving without TLS", log.F("port", healthPort))
	return srv, lis, nil
}

// serveHealthOnly serves hsrv on lis in the background. A failure is sent on
// errCh and takes the main server down with it. A nil hsrv is a no-op.
func serveHealthOnly(hsrv *grpc.Server, lis net.Listener, main *grpc.Server, errCh chan<- error) {
	if hsrv == nil {
		return
	}
	go func() {
		if err := hsrv.Serve(lis); err != nil {
			errCh <- err
			main.Stop()
		}
	}()
}
