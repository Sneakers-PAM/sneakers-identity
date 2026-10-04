// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// An orphan group is a groups row with no group_membership rows. Service
// accounts aren't members: they hold groups through their OIDC bound and their
// tokens' scopes, so an orphan can still be in use, and pruning one that is
// referenced needs force, which strips exactly the referencing entries.
//
// An entry refers to a group when it is the group's ID, or, unless it is some
// other group's ID, the group's exact name or slug. That is a superset of what
// the scope resolver grants, so the check only errs towards refusing, and a
// forced prune never re-points an entry at a different group.

const orphanRACIWarning = "Vault RACI rules name groups, and identity can't see them. " +
	"A RACI rule naming a pruned group matches nothing afterwards (fail closed); " +
	"review the vault's rules for these group names."

const pruneWhat = "list or prune orphan groups"

type orphanSA struct {
	id, name string
	allowed  []string
}

type orphanToken struct {
	id, saID string
	scope    []string
}

// orphanSnapshot is the directory state an orphan decision is made against.
type orphanSnapshot struct {
	groups  []dirGroup // ordered by name, then id
	byID    map[string]dirGroup
	members map[string]int64
	sas     []*orphanSA
	tokens  []*orphanToken
}

// loadOrphanSnapshot reads every group, the membership counts, the
// service-account bounds and the live tokens' scopes. lock takes row locks on
// the groups, service accounts and live tokens it reads (FOR UPDATE), so a
// prune can't race a new membership (the membership foreign key waits on the
// group row) or a change to a bound or scope.
func loadOrphanSnapshot(ctx context.Context, q postgres.Querier, lock bool) (*orphanSnapshot, error) {
	forUpdate := ""
	if lock {
		forUpdate = " FOR UPDATE"
	}
	snap := &orphanSnapshot{byID: map[string]dirGroup{}, members: map[string]int64{}}
	if err := eachRow(ctx, q, `SELECT id, name FROM groups ORDER BY name, id`+forUpdate, func(r postgres.Rows) error {
		var g dirGroup
		if err := r.Scan(&g.ID, &g.Name); err != nil {
			return err
		}
		snap.groups = append(snap.groups, g)
		snap.byID[g.ID] = g
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read groups: %w", err)
	}
	if err := eachRow(ctx, q, `SELECT group_id, count(*) FROM group_membership GROUP BY group_id`, func(r postgres.Rows) error {
		var id string
		var n int64
		if err := r.Scan(&id, &n); err != nil {
			return err
		}
		snap.members[id] = n
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read memberships: %w", err)
	}
	if err := eachRow(ctx, q, `SELECT id, name, oidc_allowed_groups FROM service_accounts ORDER BY id`+forUpdate, func(r postgres.Rows) error {
		sa := &orphanSA{}
		if err := r.Scan(&sa.id, &sa.name, &sa.allowed); err != nil {
			return err
		}
		snap.sas = append(snap.sas, sa)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read service accounts: %w", err)
	}
	if err := eachRow(ctx, q, `SELECT id, service_account_id, scope FROM api_tokens WHERE revoked_at IS NULL ORDER BY id`+forUpdate, func(r postgres.Rows) error {
		t := &orphanToken{}
		var scope string
		if err := r.Scan(&t.id, &t.saID, &scope); err != nil {
			return err
		}
		t.scope = strings.Fields(scope)
		snap.tokens = append(snap.tokens, t)
		return nil
	}); err != nil {
		return nil, fmt.Errorf("read api tokens: %w", err)
	}
	return snap, nil
}

func eachRow(ctx context.Context, q postgres.Querier, sql string, scan func(postgres.Rows) error) error {
	rows, err := q.Query(ctx, sql)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		if err := scan(rows); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (snap *orphanSnapshot) isOrphan(id string) bool {
	_, ok := snap.byID[id]
	return ok && snap.members[id] == 0
}

func (snap *orphanSnapshot) refersTo(entry string, g dirGroup) bool {
	entry = strings.TrimSpace(entry)
	switch entry {
	case "":
		return false
	case g.ID:
		return true
	}
	if _, otherID := snap.byID[entry]; otherID {
		return false
	}
	if entry == g.Name {
		return true
	}
	slug, ok := groupSlug(g.Name)
	return ok && asciiLower(entry) == slug
}

func (snap *orphanSnapshot) refersToAny(entries []string, g dirGroup) bool {
	return slices.ContainsFunc(entries, func(e string) bool { return snap.refersTo(e, g) })
}

func (snap *orphanSnapshot) describe(g dirGroup) *identityv1.OrphanGroup {
	og := &identityv1.OrphanGroup{Id: g.ID, Name: g.Name}
	for _, sa := range snap.sas {
		if snap.refersToAny(sa.allowed, g) {
			og.ServiceAccounts = append(og.ServiceAccounts, &identityv1.OrphanGroupServiceAccountRef{Id: sa.id, Name: sa.name})
		}
	}
	for _, t := range snap.tokens {
		if snap.refersToAny(t.scope, g) {
			og.ApiTokens = append(og.ApiTokens, &identityv1.OrphanGroupTokenRef{Id: t.id, ServiceAccountId: t.saID})
		}
	}
	return og
}

// ListOrphanGroups reports every group with no members, with the service
// accounts and live tokens that still reference it. Site admin only.
func (s *Server) ListOrphanGroups(ctx context.Context, req *identityv1.ListOrphanGroupsRequest) (*identityv1.ListOrphanGroupsResponse, error) {
	lg := s.lg(ctx)
	actor := strings.TrimSpace(req.GetActingUserId())
	if err := requireSiteAdminTo(ctx, s.db, actor, pruneWhat); err != nil {
		lg.Warn("list orphan groups refused", log.F("acting_user_id", actor))
		return nil, err
	}
	snap, err := loadOrphanSnapshot(ctx, s.db, false)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "orphan groups: %v", err)
	}
	resp := &identityv1.ListOrphanGroupsResponse{Warning: orphanRACIWarning}
	for _, g := range snap.groups {
		if snap.isOrphan(g.ID) {
			resp.Groups = append(resp.Groups, snap.describe(g))
		}
	}
	lg.Debug("listed orphan groups", log.F("acting_user_id", actor), log.F("groups", len(snap.groups)), log.F("orphans", len(resp.GetGroups())))
	return resp, nil
}

// normalizeIDs trims, drops blanks and dedupes, keeping first-seen order.
func normalizeIDs(ids []string) []string {
	var out []string
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if id != "" && !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out
}

// checkPrunable is FailedPrecondition naming every id that may not be pruned.
func (snap *orphanSnapshot) checkPrunable(ids []string, force bool) error {
	var unknown, members, referenced []string
	for _, id := range ids {
		g, ok := snap.byID[id]
		switch {
		case !ok:
			unknown = append(unknown, id)
		case !snap.isOrphan(id):
			members = append(members, id)
		case !force:
			if og := snap.describe(g); len(og.GetServiceAccounts())+len(og.GetApiTokens()) > 0 {
				referenced = append(referenced, id)
			}
		}
	}
	var why []string
	if len(unknown) > 0 {
		why = append(why, "unknown group ids: "+strings.Join(unknown, ", "))
	}
	if len(members) > 0 {
		why = append(why, "still have members (not orphans): "+strings.Join(members, ", "))
	}
	if len(referenced) > 0 {
		why = append(why, "referenced by service accounts or live API tokens (retry with force to remove those references): "+strings.Join(referenced, ", "))
	}
	if len(why) == 0 {
		return nil
	}
	return status.Error(codes.FailedPrecondition, "nothing pruned; "+strings.Join(why, "; "))
}

// prune strips g from every bound and live token scope that refers to it
// (there are none unless force is on), then deletes the group. The snapshot
// is updated too, so later groups in the same call see the stripped entries.
func (snap *orphanSnapshot) prune(ctx context.Context, tx postgres.Querier, g dirGroup) (*identityv1.PrunedGroup, error) {
	p := &identityv1.PrunedGroup{Id: g.ID, Name: g.Name}
	keep := func(e string) bool { return !snap.refersTo(e, g) }
	for _, sa := range snap.sas {
		kept := slices.DeleteFunc(slices.Clone(sa.allowed), func(e string) bool { return !keep(e) })
		if len(kept) == len(sa.allowed) {
			continue
		}
		if kept == nil {
			kept = []string{}
		}
		if _, err := tx.Exec(ctx, `UPDATE service_accounts SET oidc_allowed_groups=$2 WHERE id=$1`, sa.id, kept); err != nil {
			return nil, fmt.Errorf("update service account %s: %w", sa.id, err)
		}
		sa.allowed = kept
		p.ServiceAccountsUpdated = append(p.ServiceAccountsUpdated, &identityv1.OrphanGroupServiceAccountRef{Id: sa.id, Name: sa.name})
	}
	for _, t := range snap.tokens {
		kept := slices.DeleteFunc(slices.Clone(t.scope), func(e string) bool { return !keep(e) })
		if len(kept) == len(t.scope) {
			continue
		}
		if _, err := tx.Exec(ctx, `UPDATE api_tokens SET scope=$2 WHERE id=$1`, t.id, strings.Join(kept, " ")); err != nil {
			return nil, fmt.Errorf("update api token %s: %w", t.id, err)
		}
		t.scope = kept
		p.ApiTokensUpdated = append(p.ApiTokensUpdated, &identityv1.OrphanGroupTokenRef{Id: t.id, ServiceAccountId: t.saID})
	}
	if _, err := tx.Exec(ctx, `DELETE FROM groups WHERE id=$1`, g.ID); err != nil {
		return nil, fmt.Errorf("delete group: %w", err)
	}
	return p, nil
}

// PruneOrphanGroups deletes the named orphan groups in one transaction, all or
// nothing, re-checking at call time under row locks. With force it first
// removes the groups from service-account bounds and live token scopes. Site
// admin only; each pruned group is audited as group.prune.
func (s *Server) PruneOrphanGroups(ctx context.Context, req *identityv1.PruneOrphanGroupsRequest) (*identityv1.PruneOrphanGroupsResponse, error) {
	lg := s.lg(ctx)
	actor := strings.TrimSpace(req.GetActingUserId())
	if err := requireSiteAdminTo(ctx, s.db, actor, pruneWhat); err != nil {
		lg.Warn("prune orphan groups refused", log.F("acting_user_id", actor))
		return nil, err
	}
	ids := normalizeIDs(req.GetIds())
	if len(ids) == 0 {
		return nil, status.Error(codes.InvalidArgument, "ids is required")
	}
	resp := &identityv1.PruneOrphanGroupsResponse{Warning: orphanRACIWarning}
	err := s.pg.RunInTxQuerier(ctx, func(tx postgres.Querier) error {
		snap, err := loadOrphanSnapshot(ctx, tx, true)
		if err != nil {
			return status.Errorf(codes.Internal, "orphan groups: %v", err)
		}
		if err := snap.checkPrunable(ids, req.GetForce()); err != nil {
			return err
		}
		for _, id := range ids {
			p, err := snap.prune(ctx, tx, snap.byID[id])
			if err != nil {
				return status.Errorf(codes.Internal, "prune %s: %v", id, err)
			}
			resp.Pruned = append(resp.Pruned, p)
		}
		return nil
	})
	if err != nil {
		lg.Warn("prune orphan groups failed", log.F("acting_user_id", actor), log.F("ids", strings.Join(ids, ",")), log.F("force", req.GetForce()), log.F("error", err.Error()))
		if _, ok := status.FromError(err); ok {
			return nil, err
		}
		return nil, status.Errorf(codes.Internal, "prune orphan groups: %v", err)
	}
	for _, p := range resp.GetPruned() {
		s.recordPrune(ctx, actor, req.GetForce(), p)
	}
	lg.Info("pruned orphan groups", log.F("acting_user_id", actor), log.F("ids", strings.Join(ids, ",")), log.F("force", req.GetForce()))
	return resp, nil
}

func (s *Server) recordPrune(ctx context.Context, actor string, force bool, p *identityv1.PrunedGroup) {
	sas := make([]string, 0, len(p.GetServiceAccountsUpdated()))
	for _, r := range p.GetServiceAccountsUpdated() {
		sas = append(sas, r.GetId())
	}
	toks := make([]string, 0, len(p.GetApiTokensUpdated()))
	for _, r := range p.GetApiTokensUpdated() {
		toks = append(toks, r.GetId())
	}
	s.record(ctx, audit.Event{
		Action: audit.ActionGroupPrune, ActorUserID: actor, Subject: p.GetId(), GroupID: p.GetId(),
		Attributes: map[string]string{
			"name":                     p.GetName(),
			"force":                    strconv.FormatBool(force),
			"service_accounts_updated": strings.Join(sas, ","),
			"api_tokens_updated":       strings.Join(toks, ","),
		},
	})
}
