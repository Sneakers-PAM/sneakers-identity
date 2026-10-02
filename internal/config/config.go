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
}

func Load() (Config, error) {
	c := Config{
		DatabaseDSN:  os.Getenv("DATABASE_DSN"),
		GRPCPort:     getOr("GRPC_PORT", "9090"),
		OTLPEndpoint: getOr("OTEL_EXPORTER_OTLP_ENDPOINT", "localhost:4317"),
	}
	if c.DatabaseDSN == "" {
		return c, fmt.Errorf("DATABASE_DSN is required")
	}
	if err := checkAuthBackend(os.Getenv("AUTH_BACKEND")); err != nil {
		return c, err
	}
	return c, nil
}

// checkAuthBackend refuses any AUTH_BACKEND other than kratos (or unset), so a
// leftover setting fails at start instead of being ignored.
func checkAuthBackend(v string) error {
	switch v {
	case "", "kratos":
		return nil
	case "keycloak":
		return fmt.Errorf("AUTH_BACKEND=keycloak: Keycloak is not supported; Sneakers signs in with Ory Kratos (set AUTH_BACKEND=kratos or leave it unset)")
	default:
		return fmt.Errorf("AUTH_BACKEND=%q is not a known backend; the only backend is kratos", v)
	}
}

func getOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
