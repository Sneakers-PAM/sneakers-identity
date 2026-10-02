// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/Sneakers-PAM/sneakers-identity/internal/workloadauth"
)

// Caller names, from the service accounts sneakers-<name>.
const (
	CallerGateway = "gateway"
	CallerNotify  = "notify"
)

// notifyMethods are the directory reads notify makes as itself to fan an
// event out to a group's members.
var notifyMethods = []string{
	identityv1.IdentityService_ListGroups_FullMethodName,
	identityv1.IdentityService_ListGroupMembers_FullMethodName,
	identityv1.IdentityService_ListUsersByAdGroups_FullMethodName, //nolint:staticcheck // SA1019: notify still calls the retired RPC.
	identityv1.IdentityService_ResolveUserLabels_FullMethodName,
}

// CallerPolicy is identity's per-method allow-list. The gateway calls every
// method on behalf of the signed-in user; notify calls its directory reads as
// itself. Anything else is refused.
func CallerPolicy() workloadauth.Policy {
	p := workloadauth.Policy{}
	desc := identityv1.IdentityService_ServiceDesc
	for _, md := range desc.Methods {
		p["/"+desc.ServiceName+"/"+md.MethodName] = map[string]workloadauth.Access{CallerGateway: workloadauth.OnBehalf}
	}
	for _, m := range notifyMethods {
		p[m][CallerNotify] = workloadauth.Self
	}
	return p
}

// AuditDenial records a refused service-to-service call. It is the
// interceptors' deny hook; the token is never recorded.
func (s *Server) AuditDenial(ctx context.Context, d workloadauth.Denial) {
	s.record(ctx, audit.Event{
		Action:  audit.ActionWorkloadCallRefused,
		Subject: d.Method,
		Attributes: map[string]string{
			"caller":          d.Caller.Name,
			"service_account": d.Caller.ServiceAccount,
			"code":            d.Code.String(),
			"reason":          d.Reason,
		},
	})
}
