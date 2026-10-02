// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"slices"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
)

// auditRecordTimeout bounds one RecordEvent call.
const auditRecordTimeout = 5 * time.Second

// WithAudit wires the audit trail. nil records nothing.
func (s *Server) WithAudit(r audit.Recorder) *Server {
	s.audit = r
	return s
}

// record sends an event to the audit trail after the change it describes has
// been made. A failed send is logged and never fails the change, the same as
// the vault's routine events.
func (s *Server) record(ctx context.Context, ev audit.Event) {
	if s.audit == nil {
		return
	}
	lg := s.lg(ctx)
	// The change is already made, so a caller that hangs up must not lose its
	// record; a stuck audit service must not hold the RPC open either.
	rctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), auditRecordTimeout)
	defer cancel()
	start := time.Now()
	if err := s.audit.Record(rctx, ev); err != nil {
		lg.Error(err, "audit: event not recorded", log.F("action", ev.Action), log.F("subject", ev.Subject),
			log.F("duration_ms", time.Since(start).Milliseconds()))
		return
	}
	lg.Debug("audit: event recorded", log.F("action", ev.Action), log.F("subject", ev.Subject),
		log.F("duration_ms", time.Since(start).Milliseconds()))
}

// actorOr is the acting user when the gateway named one, otherwise fallback
// (the user the request names, for a user's own change).
func actorOr(acting, fallback string) string {
	if a := strings.TrimSpace(acting); a != "" {
		return a
	}
	return fallback
}

func outcome(ok bool) string {
	if ok {
		return audit.OutcomeOK
	}
	return audit.OutcomeFail
}

// roleDiff returns the roles in after that aren't in before, and the reverse.
func roleDiff(before, after []string) (added, removed []string) {
	for _, r := range after {
		if !slices.Contains(before, r) && !slices.Contains(added, r) {
			added = append(added, r)
		}
	}
	for _, r := range before {
		if !slices.Contains(after, r) && !slices.Contains(removed, r) {
			removed = append(removed, r)
		}
	}
	return added, removed
}

func joinSorted(v []string) string {
	c := slices.Clone(v)
	slices.Sort(c)
	return strings.Join(c, ",")
}
