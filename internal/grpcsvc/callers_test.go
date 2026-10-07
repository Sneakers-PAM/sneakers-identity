// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"maps"
	"net"
	"testing"

	workloadauth "github.com/Bugs5382/go-workload-identity"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

// TestCallerPolicyPerMethod pins the allow-list of every identity method: the
// gateway may call each one on behalf of the signed-in user, except
// RevokeTokensByClientKind, which only the appliance may call, as itself;
// notify may call its four directory reads as itself, and nobody else may
// call anything.
func TestCallerPolicyPerMethod(t *testing.T) {
	gw := workloadauth.OnBehalf
	self := workloadauth.Self
	notify := map[string]bool{"ListGroups": true, "ListGroupMembers": true, "ListUsersByAdGroups": true, "ResolveUserLabels": true}
	p := CallerPolicy()
	desc := identityv1.IdentityService_ServiceDesc
	if len(desc.Streams) != 0 {
		t.Fatalf("identity has streaming methods now; give them an allow-list: %v", desc.Streams)
	}
	if len(p) != len(desc.Methods) {
		t.Fatalf("policy covers %d methods, the service has %d", len(p), len(desc.Methods))
	}
	for _, md := range desc.Methods {
		full := "/" + desc.ServiceName + "/" + md.MethodName
		want := map[string]workloadauth.Access{CallerGateway: gw}
		if md.MethodName == "RevokeTokensByClientKind" {
			want = map[string]workloadauth.Access{CallerAppliance: self}
		}
		if notify[md.MethodName] {
			want[CallerNotify] = self
		}
		if got := p[full]; !maps.Equal(got, want) {
			t.Errorf("%s: allow-list %v, want %v", md.MethodName, got, want)
		}
		for _, c := range []string{"mcp", "vault", "workflow", "sshbroker", "connector", "audit", "identity"} {
			if _, ok := p.Lookup(full, c); ok {
				t.Errorf("%s: %s must not be allowed", md.MethodName, c)
			}
		}
	}
}

// fakeVerifier accepts any token naming one of its callers; the token is the
// caller name. The real verifier is covered in go-workload-identity.
type fakeVerifier struct{}

func (fakeVerifier) Verify(token string) (workloadauth.Caller, error) {
	switch token {
	case "gateway", "notify", "mcp", "appliance":
		return workloadauth.Caller{Name: token, ServiceAccount: "sneakers/sneakers-" + token}, nil
	}
	return workloadauth.Caller{}, errors.New("rejected")
}

// TestWorkloadAuthOnTheServer runs the identity server behind the workload
// interceptors over a real gRPC connection: an unlisted caller with a valid
// token is refused and the refusal is audited; listed callers get through.
func TestWorkloadAuthOnTheServer(t *testing.T) {
	rec := &recordingAuditor{}
	s := New(nil).WithAudit(rec)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(fakeVerifier{}, CallerPolicy(), nil, workloadauth.WithDenyHook(s.AuditDenial))),
		grpc.ChainStreamInterceptor(workloadauth.StreamServerInterceptor(fakeVerifier{}, CallerPolicy(), nil, workloadauth.WithDenyHook(s.AuditDenial))),
	)
	s.RegisterOn(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := identityv1.NewIdentityServiceClient(conn)
	as := func(caller string) context.Context {
		return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+caller)
	}
	// SetUserAdGroups is retired (Unimplemented) and touches no database, so
	// a call that passes the check comes back Unimplemented.
	//nolint:staticcheck // SA1019: the retired RPC is the one call that needs no database.
	call := func(ctx context.Context) error {
		_, err := c.SetUserAdGroups(ctx, &identityv1.SetUserAdGroupsRequest{})
		return err
	}

	if err := call(as("mcp")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("mcp with a valid token: %v, want PermissionDenied", err)
	}
	ev := rec.only(t)
	wantEvent(t, ev, audit.ActionWorkloadCallRefused, "", identityv1.IdentityService_SetUserAdGroups_FullMethodName,
		map[string]string{"caller": "mcp", "service_account": "sneakers/sneakers-mcp", "code": "PermissionDenied"})
	assertNoSecretIn(t, []audit.Event{ev}, "Bearer")

	if err := call(as("notify")); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("notify on a method it isn't listed for: %v, want PermissionDenied", err)
	}
	rec.take()
	if err := call(context.Background()); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("no token: %v, want Unauthenticated", err)
	}
	rec.take()
	if err := call(as("forged")); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("bad token: %v, want Unauthenticated", err)
	}
	rec.take()
	if err := call(as("gateway")); status.Code(err) != codes.Unimplemented {
		t.Fatalf("gateway: %v, want the handler's Unimplemented", err)
	}
	rec.none(t)
}

// TestRevokeTokensByClientKindIsApplianceOnly runs the allow-list through the
// interceptors: only the appliance reaches the handler, and it reaches no
// other method. An empty kind fails in the handler before any database call.
func TestRevokeTokensByClientKindIsApplianceOnly(t *testing.T) {
	rec := &recordingAuditor{}
	s := New(nil).WithAudit(rec)
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer(
		grpc.ChainUnaryInterceptor(workloadauth.UnaryServerInterceptor(fakeVerifier{}, CallerPolicy(), nil, workloadauth.WithDenyHook(s.AuditDenial))),
	)
	s.RegisterOn(gs)
	go func() { _ = gs.Serve(lis) }()
	t.Cleanup(gs.Stop)
	conn, err := grpc.NewClient("passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return lis.DialContext(ctx) }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	c := identityv1.NewIdentityServiceClient(conn)
	as := func(caller string) context.Context {
		return metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer "+caller)
	}
	revoke := func(ctx context.Context) error {
		_, err := c.RevokeTokensByClientKind(ctx, &identityv1.RevokeTokensByClientKindRequest{})
		return err
	}

	for _, caller := range []string{"gateway", "notify", "mcp"} {
		if err := revoke(as(caller)); status.Code(err) != codes.PermissionDenied {
			t.Fatalf("%s: %v, want PermissionDenied", caller, err)
		}
		wantEvent(t, rec.only(t), audit.ActionWorkloadCallRefused, "", identityv1.IdentityService_RevokeTokensByClientKind_FullMethodName,
			map[string]string{"caller": caller, "code": "PermissionDenied"})
	}
	if err := revoke(as("appliance")); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("appliance: %v, want the handler's InvalidArgument", err)
	}
	rec.none(t)
	//nolint:staticcheck // SA1019: the retired RPC is the one call that needs no database.
	if _, err := c.SetUserAdGroups(as("appliance"), &identityv1.SetUserAdGroupsRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("appliance on another method: %v, want PermissionDenied", err)
	}
	rec.take()
}
