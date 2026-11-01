// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry wires go-otel for the service: the export settings, the
// telemetry and log filters and the optional otlp health dependency. Unset settings leave traces and metrics as they were and export
// no logs.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	"github.com/exaring/otelpgx"
)

var errExportFailing = errors.New("otlp export failing")

// allowedLogFields is the only log field data that leaves the process. It holds
// ids, counts, durations, classes, states and short enums. Addresses, URLs,
// names, emails, group references, error text, panic values and stacks stay
// off, as does client_kind, which RevokeTokensByClientKind logs unchecked. So
// do outcome and reason: go-workload-identity fills both with error text.
var allowedLogFields = []string{
	"access", "acting_admin", "acting_user_id", "action", "attempt", "attempts", "auth",
	"code", "component", "custom_ca", "dependencies", "dependency", "disabled", "duration_ms",
	"error_class", "force", "from", "granted", "groups", "kept_keys", "keys", "method",
	"orphans", "port", "required", "retry_in", "retry_in_ms", "revoked",
	"service_account_id", "tls_mode", "to", "token_id", "user_id", "verify",
}

// rpcMethod is the shape of this service's gRPC methods and of the ones it calls.
var rpcMethod = regexp.MustCompile(`^sneakers\.[a-z]+\.v1\.[A-Za-z]+/[A-Za-z]+$`)

// postgresSpan is a query span from PostgresTracing.
var postgresSpan = regexp.MustCompile(`^query [A-Z]+$`)

// otelgrpc is the only instrumentation here: no HTTP metric attributes exist.
var (
	allowedTraceAttributes  = []string{"rpc.method", "rpc.response.status_code"}
	allowedMetricAttributes = []string{"rpc.method", "rpc.response.status_code"}
)

var tokenShape = regexp.MustCompile(`\bsnk_[A-Za-z0-9_\-]+`)

// Settings is the export configuration from config.Config.
type Settings struct {
	Endpoint           string
	InsecureSkipVerify bool
	Logs               bool
}

// NewLogger returns the service logger. With logs on it also writes to go-otel,
// which discards lines until Start and filters them after it.
func NewLogger(service string, logs bool) log.TraceLogger {
	if !logs {
		return log.NewLoggerWithOptions(service)
	}
	return log.NewLoggerWithOptions(service, log.WithOutput(io.MultiWriter(os.Stdout, gootel.LogWriter())))
}

// Start initialises go-otel.
func Start(ctx context.Context, service string, s Settings) (func(context.Context) error, error) {
	return gootel.InitWithOptions(ctx, service, s.Endpoint,
		gootel.WithInsecureSkipVerify(s.InsecureSkipVerify),
		gootel.WithLogs(s.Logs),
		gootel.WithLogAllowFields(allowedLogFields...),
		gootel.WithLogRedactPatterns(tokenShape),
		gootel.WithTelemetryFilter(true),
		gootel.WithBaggage(false),
		gootel.WithRedactedErrors(true),
		gootel.WithTraceAllowSpanNames(rpcMethod, postgresSpan),
		gootel.WithTraceAllowAttributes(allowedTraceAttributes...),
		gootel.WithMetricAllowAttributes(allowedMetricAttributes...),
		gootel.WithAttributeValuePattern("rpc.method", rpcMethod),
	)
}

// PostgresTracing traces queries under their operation only, with no statement
// text, so the span names fit postgresSpan.
func PostgresTracing() postgres.Option {
	return otelpg.WithTracing(otelpgx.WithTrimSQLInSpanName(), otelpgx.WithDisableSQLStatementInAttributes())
}

// Dependencies returns the optional otlp health dependency, or nothing when no
// endpoint is set.
func Dependencies(s Settings) []health.Dependency {
	if s.Endpoint == "" {
		return nil
	}
	return []health.Dependency{{
		Name: "otlp",
		Check: func(context.Context) error {
			return exportCheck(gootel.ExportState(), s.Logs)
		},
	}}
}

func exportCheck(st gootel.ExportStatus, logs bool) error {
	if failing(st.Traces) || failing(st.Metrics) || (logs && failing(st.Logs)) {
		return errExportFailing
	}
	return nil
}

func failing(s gootel.SignalStatus) bool {
	return s.LastErrorAt.After(s.LastSuccess)
}
