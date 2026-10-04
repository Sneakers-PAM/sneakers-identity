// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"slices"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// RoleRecovery grants access to a secret's prior versions in the vault's
// recovery view (a fresh second factor is still required there). An old
// password may still work on a target that wasn't rotated, so only a site
// admin or root may grant or revoke it, and every grant and revoke is
// recorded at high severity.
const RoleRecovery = "recovery"

// The roles that make a user a site admin; the gateway treats them alike.
var siteAdminRoles = []string{"site-admin", "admin"}

// requireSiteAdmin refuses unless actingUserID names an enabled user who is
// root or holds a site-admin role. Only the recovery role is gated here: the
// gateway gates the other role changes.
func requireSiteAdmin(ctx context.Context, q postgres.Querier, actingUserID string) error {
	return requireSiteAdminTo(ctx, q, actingUserID, "grant or revoke the recovery role")
}

// requireSiteAdminTo is requireSiteAdmin for any site-admin-only action; what
// completes the refusal "only a site admin can ...".
func requireSiteAdminTo(ctx context.Context, q postgres.Querier, actingUserID, what string) error {
	refused := status.Error(codes.PermissionDenied, "only a site admin can "+what)
	if actingUserID == "" {
		return refused
	}
	var (
		roles  []string
		isRoot bool
	)
	err := q.QueryRow(ctx, `SELECT roles, is_root FROM users WHERE id=$1 AND disabled_at IS NULL`, actingUserID).Scan(&roles, &isRoot)
	if errors.Is(err, postgres.ErrNoRows) {
		return refused
	}
	if err != nil {
		return status.Errorf(codes.Internal, "load acting user: %v", err)
	}
	if isRoot || slices.ContainsFunc(roles, func(r string) bool { return slices.Contains(siteAdminRoles, r) }) {
		return nil
	}
	return refused
}

// recordRecoveryRoleChange records a recovery-role grant or revoke as its own
// high-severity event, alongside the general role change.
func (s *Server) recordRecoveryRoleChange(ctx context.Context, actor, userID string, granted bool) {
	action := audit.ActionRecoveryRoleRevoke
	if granted {
		action = audit.ActionRecoveryRoleGrant
	}
	lg := s.lg(ctx)
	lg.Info("recovery role changed", log.F("user_id", userID), log.F("acting_user_id", actor), log.F("granted", granted))
	s.record(ctx, audit.Event{
		Action: action, ActorUserID: actor, Subject: userID,
		Attributes: map[string]string{"role": RoleRecovery, "severity": "high"},
	})
}
