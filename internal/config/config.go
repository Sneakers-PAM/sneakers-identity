// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"os"
)

type Config struct {
	DatabaseDSN  string
	GRPCPort     string
	OTLPEndpoint string
	// OTLPInsecureSkipVerify keeps TLS to the collector but stops checking its
	// certificate. go-otel then keeps logs off.
	OTLPInsecureSkipVerify bool
	// OTLPLogsEnabled exports filtered logs next to traces and metrics.
	OTLPLogsEnabled bool
	// AuditAddr is the audit service's gRPC address. Empty records no events.
	AuditAddr string
}

func Load() (Config, error) {
	c := Config{
		DatabaseDSN: os.Getenv("DATABASE_DSN"),
		GRPCPort:    getOr("GRPC_PORT", "9090"),
		// Empty means no collector: otel.Init runs without an exporter instead
		// of retrying a default localhost address that is rarely there.
		OTLPEndpoint:           getOr("OTEL_EXPORTER_OTLP_ENDPOINT", ""),
		OTLPInsecureSkipVerify: os.Getenv("OTLP_INSECURE_SKIP_VERIFY") == "true",
		OTLPLogsEnabled:        OTLPLogsEnabled(),
		AuditAddr:              os.Getenv("AUDIT_ADDR"),
	}
	if c.DatabaseDSN == "" {
		return c, fmt.Errorf("DATABASE_DSN is required")
	}
	return c, nil
}

// OTLPLogsEnabled reports OTLP_LOGS_ENABLED on its own, because the logger is
// built before Load so that Load's failure can be logged.
func OTLPLogsEnabled() bool {
	return os.Getenv("OTLP_LOGS_ENABLED") == "true"
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
