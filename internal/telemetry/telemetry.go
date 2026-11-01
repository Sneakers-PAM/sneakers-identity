// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package telemetry wires go-otel for the service: the export settings, the
// log filters, the export error handler and the optional otlp health
// dependency. Unset settings leave traces and metrics as they were and export
// no logs.
package telemetry

import (
	"context"
	"errors"
	"io"
	"os"
	"regexp"
	"sync/atomic"
	"time"

	"github.com/Bugs5382/go-buildinfo/health"
	log "github.com/Bugs5382/go-log"
	gootel "github.com/Bugs5382/go-otel"
	"go.opentelemetry.io/otel"
	"google.golang.org/grpc/status"
)

// errorLogInterval limits export failure logging: each failed line would
// itself queue for export, so a collector outage must not feed on itself.
const errorLogInterval = 30 * time.Second

var errExportFailing = errors.New("otlp export failing")

// allowedLogFields is the only log field data that leaves the process. It holds
// ids, counts, durations, classes, states and short enums. Addresses, URLs,
// names, emails, group references, error text, panic values and stacks stay
// off, as does client_kind, which RevokeTokensByClientKind logs unchecked.
var allowedLogFields = []string{
	"access", "acting_admin", "acting_user_id", "action", "attempt", "attempts", "auth",
	"code", "component", "custom_ca", "dependencies", "dependency", "disabled", "duration_ms",
	"error_class", "force", "from", "granted", "groups", "kept_keys", "keys", "method",
	"orphans", "outcome", "port", "reason", "required", "retry_in", "retry_in_ms", "revoked",
	"service_account_id", "tls_mode", "to", "token_id", "user_id", "verify",
}

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

// Start routes export errors to lg and initialises go-otel.
func Start(ctx context.Context, service string, s Settings, lg log.Logger) (func(context.Context) error, error) {
	otel.SetErrorHandler(newErrorHandler(lg))
	return gootel.InitWithOptions(ctx, service, s.Endpoint,
		gootel.WithInsecureSkipVerify(s.InsecureSkipVerify),
		gootel.WithLogs(s.Logs),
		gootel.WithLogAllowFields(allowedLogFields...),
		gootel.WithLogRedactPatterns(tokenShape),
	)
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

// errorHandler logs only the gRPC code: export error text can carry the
// endpoint and header values.
type errorHandler struct {
	lg   log.Logger
	next atomic.Int64
}

func newErrorHandler(lg log.Logger) otel.ErrorHandler {
	return &errorHandler{lg: lg}
}

func (h *errorHandler) Handle(err error) {
	now := time.Now()
	next := h.next.Load()
	if now.UnixNano() < next || !h.next.CompareAndSwap(next, now.Add(errorLogInterval).UnixNano()) {
		return
	}
	h.lg.Warn("otlp export failed", log.F("code", status.Code(err).String()))
}
