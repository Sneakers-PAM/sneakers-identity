// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	"github.com/jackc/pgx/v5"
)

// Group source of truth
//
// lldap is the source of truth for which directory groups EXIST and what they
// are CALLED. The identity `groups` table is the maintained mirror that every
// reader uses (ListGroups/GetGroup, AddGroupMember, ResolveUserContext, and
// the machine-scope resolution), keyed by the lldap group ID as a decimal
// string (the same ID CreateGroup returns). Group MEMBERSHIP is NOT mirrored:
// it lives only in identity's group_membership table.
//
// Two writers keep the mirror current:
//
//   - CreateGroup writes lldap first, then the groups row; if the row cannot
//     be written it deletes the lldap group again (compensation).
//   - SyncGroups reconciles lldap into the table at startup and on a timer,
//     catching groups made outside Sneakers (lldap's own UI) and renames.
//
// SyncGroups never deletes: a row whose lldap group is gone is reported as an
// orphan (a warning when a service account still references it) and left for
// an operator, because deleting it would cascade memberships and silently
// narrow machine grants. It also skips (with a warning) any lldap group whose
// name would collide case-insensitively with another group, since vault RACI
// cannot tell such groups apart (the groups_name_lower_idx index enforces the same rule).

// lldapBuiltinPrefix marks lldap's own system groups (lldap_admin,
// lldap_password_manager, lldap_strict_readonly). They govern the directory
// itself, are never RACI groups, and are neither mirrored nor creatable.
const lldapBuiltinPrefix = "lldap_"

// groupSyncLockKey serializes concurrent syncs across identity replicas.
const groupSyncLockKey = "sneakers.identity.group_sync"

func isLldapBuiltinGroup(name string) bool {
	return strings.HasPrefix(strings.ToLower(name), lldapBuiltinPrefix)
}

// GroupSyncSkip is one lldap group SyncGroups refused to mirror.
type GroupSyncSkip struct {
	ID     string
	Name   string
	Reason string
}

// GroupSyncReport summarizes one SyncGroups run. ID lists are sorted.
type GroupSyncReport struct {
	Inserted       []string // lldap groups newly added to the table
	Renamed        []string // rows whose name was updated to lldap's
	Unchanged      int      // rows already matching lldap
	IgnoredBuiltin int      // lldap system groups (lldap_*) not mirrored
	Skipped        []GroupSyncSkip
	// Orphans are table rows with no lldap group of the same ID (dev seed
	// groups, or groups deleted in lldap). They are never deleted.
	Orphans []string
	// ReferencedOrphans are the orphans a service account still names in
	// oidc_allowed_groups or a live API token scope.
	ReferencedOrphans []string
}

// SyncGroups reconciles the lldap directory's groups into the identity groups
// table: insert new, rename changed (by ID), never delete. Idempotent; runs in
// one transaction under an advisory lock so replicas never interleave.
func (s *Server) SyncGroups(ctx context.Context) (GroupSyncReport, error) {
	var rep GroupSyncReport
	if s.lldap == nil {
		return rep, errors.New("group sync: lldap admin not configured")
	}
	dir, err := s.lldap.ListGroups(ctx)
	if err != nil {
		return rep, fmt.Errorf("group sync: list lldap groups: %w", err)
	}
	desired := make(map[string]string, len(dir))
	for _, g := range dir {
		if isLldapBuiltinGroup(g.Name) {
			rep.IgnoredBuiltin++
			continue
		}
		desired[strconv.Itoa(g.ID)] = g.Name
	}

	tx, err := s.db.Begin(ctx)
	if err != nil {
		return rep, fmt.Errorf("group sync: begin: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, groupSyncLockKey); err != nil {
		return rep, fmt.Errorf("group sync: lock: %w", err)
	}
	current, err := readGroups(ctx, tx)
	if err != nil {
		return rep, fmt.Errorf("group sync: read groups: %w", err)
	}

	accepted := planGroupSync(current, desired, &rep)
	if err := applyGroupSync(ctx, tx, current, desired, accepted, &rep); err != nil {
		return rep, err
	}

	for id := range current {
		if _, ok := desired[id]; !ok {
			rep.Orphans = append(rep.Orphans, id)
		}
	}
	sort.Strings(rep.Orphans)
	if len(rep.Orphans) > 0 {
		if rep.ReferencedOrphans, err = referencedGroups(ctx, tx, rep.Orphans); err != nil {
			return rep, fmt.Errorf("group sync: orphan references: %w", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return rep, fmt.Errorf("group sync: commit: %w", err)
	}
	return rep, nil
}

// applyGroupSync writes the accepted plan inside tx. Renames go through a
// placeholder first so a swap ("A"<->"B") never trips the case-insensitive
// unique index mid-transaction.
func applyGroupSync(ctx context.Context, tx pgx.Tx, current, desired map[string]string, accepted map[string]struct{}, rep *GroupSyncReport) error {
	var renames, inserts []string
	for id := range accepted {
		cur, exists := current[id]
		switch {
		case !exists:
			inserts = append(inserts, id)
		case cur != desired[id]:
			renames = append(renames, id)
		default:
			rep.Unchanged++
		}
	}
	sort.Strings(renames)
	sort.Strings(inserts)
	for _, id := range renames {
		if _, err := tx.Exec(ctx, `UPDATE groups SET name=$2 WHERE id=$1`, id, "groupsync-pending:"+id); err != nil {
			return fmt.Errorf("group sync: stage rename %s: %w", id, err)
		}
	}
	for _, id := range renames {
		if _, err := tx.Exec(ctx, `UPDATE groups SET name=$2 WHERE id=$1`, id, desired[id]); err != nil {
			return fmt.Errorf("group sync: rename %s: %w", id, err)
		}
	}
	for _, id := range inserts {
		if _, err := tx.Exec(ctx, `INSERT INTO groups (id, name) VALUES ($1,$2)`, id, desired[id]); err != nil {
			return fmt.Errorf("group sync: insert %s: %w", id, err)
		}
	}
	rep.Inserted, rep.Renamed = nonNil(inserts), nonNil(renames)
	return nil
}

// planGroupSync returns the lldap group IDs that can be applied without any
// case-insensitive name collision in the resulting table, recording the rest
// in rep.Skipped. A skipped group that already has a row keeps its old name,
// which can in turn collide, so this iterates to a fixed point. Every party
// to a collision is skipped (fail closed): no arbitrary winner.
func planGroupSync(current, desired map[string]string, rep *GroupSyncReport) map[string]struct{} {
	accepted := make(map[string]struct{}, len(desired))
	for id := range desired {
		accepted[id] = struct{}{}
	}
	reasons := map[string]string{}
	for {
		owners := map[string][]string{} // lower(final name) -> ids
		for id, name := range current {
			if _, ok := accepted[id]; !ok {
				owners[strings.ToLower(name)] = append(owners[strings.ToLower(name)], id)
			}
		}
		for id := range accepted {
			k := strings.ToLower(desired[id])
			owners[k] = append(owners[k], id)
		}
		changed := false
		for id := range accepted {
			if others := owners[strings.ToLower(desired[id])]; len(others) > 1 {
				sort.Strings(others)
				reasons[id] = "name collides case-insensitively with group(s) " + strings.Join(others, ",")
				delete(accepted, id)
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	for id, why := range reasons {
		rep.Skipped = append(rep.Skipped, GroupSyncSkip{ID: id, Name: desired[id], Reason: why})
	}
	sort.Slice(rep.Skipped, func(i, j int) bool { return rep.Skipped[i].ID < rep.Skipped[j].ID })
	return accepted
}

func readGroups(ctx context.Context, q pgx.Tx) (map[string]string, error) {
	rows, err := q.Query(ctx, `SELECT id, name FROM groups`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var id, name string
		if err := rows.Scan(&id, &name); err != nil {
			return nil, err
		}
		out[id] = name
	}
	return out, rows.Err()
}

// referencedGroups returns which of ids a service account still points at: by
// ID or (legacy) exact name in oidc_allowed_groups, or by ID in the scope of
// a non-revoked API token.
func referencedGroups(ctx context.Context, q pgx.Tx, ids []string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT g.id FROM groups g
		 WHERE g.id = ANY($1)
		   AND (EXISTS (SELECT 1 FROM service_accounts sa
		                 WHERE g.id = ANY(sa.oidc_allowed_groups) OR g.name = ANY(sa.oidc_allowed_groups))
		     OR EXISTS (SELECT 1 FROM api_tokens t
		                 WHERE t.revoked_at IS NULL AND g.id = ANY(string_to_array(t.scope, ' '))))
		 ORDER BY g.id`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func nonNil(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

// RunGroupSync re-runs SyncGroups every interval until ctx is done
// (interval <= 0 returns at once). Call SyncGroupsAndLog first for the startup
// pass. Failures are logged, never fatal: an lldap outage must not take
// identity down, and the next tick retries.
func (s *Server) RunGroupSync(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.SyncGroupsAndLog(ctx)
		}
	}
}

// SyncGroupsAndLog runs one SyncGroups pass (30s budget) and logs the report:
// Info for the summary, Warn for skipped groups and referenced orphans.
func (s *Server) SyncGroupsAndLog(ctx context.Context) {
	lg := log.Ctx(ctx)
	runCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	rep, err := s.SyncGroups(runCtx)
	if err != nil {
		lg.Warn().Err(err).Msg("group sync: failed; will retry on the next tick")
		return
	}
	for _, sk := range rep.Skipped {
		lg.Warn().Str("group_id", sk.ID).Str("group_name", sk.Name).Str("reason", sk.Reason).
			Msg("group sync: lldap group NOT mirrored; rename it in lldap to resolve")
	}
	if len(rep.ReferencedOrphans) > 0 {
		lg.Warn().Strs("group_ids", rep.ReferencedOrphans).
			Msg("group sync: groups missing from lldap are still referenced by service accounts; kept, review by hand")
	}
	lg.Info().Strs("inserted", rep.Inserted).Strs("renamed", rep.Renamed).
		Int("unchanged", rep.Unchanged).Int("skipped", len(rep.Skipped)).
		Int("ignored_builtin", rep.IgnoredBuiltin).Strs("orphans", rep.Orphans).
		Msg("group sync: complete")
}
