// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package audit holds the events identity records in the audit service and
// the client that sends them. An event never carries a password, a code, a
// token or a secret: only ids, kinds and outcomes.
package audit

import (
	"context"

	auditv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/thirdparty/audit/v1"
)

// The actions identity records. The audit page's action filter lists them
// from the chain itself, so a new action needs no change there.
const (
	ActionSignIn                = "auth.signin"
	ActionPasswordReset         = "auth.password_reset"
	ActionMfaVerify             = "mfa.verify"
	ActionMfaEnroll             = "mfa.enroll"
	ActionMfaRemove             = "mfa.remove"
	ActionUserCreate            = "user.create"
	ActionUserUpdate            = "user.update"
	ActionUserRolesSet          = "user.roles.set"
	ActionRecoveryRoleGrant     = "role.recovery.grant"
	ActionRecoveryRoleRevoke    = "role.recovery.revoke"
	ActionUserDisable           = "user.disable"
	ActionUserEnable            = "user.enable"
	ActionGroupCreate           = "group.create"
	ActionGroupMemberAdd        = "group.member.add"
	ActionGroupMemberRemove     = "group.member.remove"
	ActionGroupPrune            = "group.prune"
	ActionServiceAccountCreate  = "service_account.create"
	ActionServiceAccountDisable = "service_account.disable"
	ActionOidcClientLink        = "service_account.oidc.link"
	ActionOidcClientUnlink      = "service_account.oidc.unlink"
	ActionAPITokenMint          = "api_token.mint" // #nosec G101 -- an audit action name, not a credential
	ActionAPITokenRevoke        = "api_token.revoke"
	ActionUserTokenMint         = "user_token.mint"
	ActionUserTokenRevoke       = "user_token.revoke"         // #nosec G101 -- an audit action name, not a credential
	ActionUserTokenRevokeByKind = "user_token.revoke_by_kind" // #nosec G101 -- an audit action name, not a credential
	ActionWorkloadCallRefused   = "workload.call_refused"
)

// Outcomes, for the "outcome" attribute of checks that can fail.
const (
	OutcomeOK   = "ok"
	OutcomeFail = "fail"
)

// Event is one audit record. Subject is the id of the thing acted on (a user,
// group, service account or token); GroupID is set for group events.
type Event struct {
	Action      string
	ActorUserID string
	Subject     string
	GroupID     string
	Attributes  map[string]string
}

// Recorder records an event in the audit trail.
type Recorder interface {
	Record(ctx context.Context, ev Event) error
}

type client struct{ c auditv1.AuditServiceClient }

// NewClient returns a Recorder backed by the audit service. Identity's events
// are all security events, so they go to the tamper-evident tier.
func NewClient(c auditv1.AuditServiceClient) Recorder { return &client{c: c} }

func (a *client) Record(ctx context.Context, ev Event) error {
	_, err := a.c.RecordEvent(ctx, &auditv1.RecordEventRequest{
		Tier:        auditv1.Tier_TIER_AUDIT,
		Action:      ev.Action,
		ActorUserId: ev.ActorUserID,
		Subject:     ev.Subject,
		GroupId:     ev.GroupID,
		Attributes:  ev.Attributes,
	})
	return err
}
