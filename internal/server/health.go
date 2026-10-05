// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"context"
	"encoding/json"

	"github.com/Sneakers-PAM/sneakers-identity/internal/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// HeaderHealth carries the readiness report (health.Report as JSON) on a
// readiness check's response.
const HeaderHealth = "sneakers-health"

// LivenessService is the health service name the liveness probe asks for. It
// answers SERVING while the process does, whatever its dependencies.
const LivenessService = "liveness"

// healthServer answers grpc.health.v1: service "" is readiness, which follows
// the checker; LivenessService is the process only; anything else is
// NotFound. Watch is unimplemented.
type healthServer struct {
	healthpb.UnimplementedHealthServer
	checker *health.Checker
}

func (h *healthServer) Check(ctx context.Context, req *healthpb.HealthCheckRequest) (*healthpb.HealthCheckResponse, error) {
	switch req.GetService() {
	case LivenessService:
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
	case "":
	default:
		return nil, status.Error(codes.NotFound, "unknown service")
	}
	r := health.Report{Status: health.OK, Dependencies: []health.DepStatus{}}
	if h.checker != nil {
		r = h.checker.Report(ctx)
	}
	for i := range r.Dependencies {
		if v, ok := dependencies.Load(r.Dependencies[i].Name); ok {
			r.Dependencies[i].Version = v.(string)
		}
	}
	if b, err := json.Marshal(r); err == nil {
		_ = grpc.SetHeader(ctx, metadata.Pairs(HeaderHealth, string(b)))
	}
	if !r.Ready() {
		return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_NOT_SERVING}, nil
	}
	return &healthpb.HealthCheckResponse{Status: healthpb.HealthCheckResponse_SERVING}, nil
}
