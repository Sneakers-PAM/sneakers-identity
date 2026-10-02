// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"testing"

	auditv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/thirdparty/audit/v1"
	"google.golang.org/grpc"
)

type fakeAuditService struct {
	auditv1.AuditServiceClient
	got *auditv1.RecordEventRequest
	err error
}

func (f *fakeAuditService) RecordEvent(_ context.Context, in *auditv1.RecordEventRequest, _ ...grpc.CallOption) (*auditv1.RecordEventResponse, error) {
	f.got = in
	return &auditv1.RecordEventResponse{}, f.err
}

func TestClientSendsEventToAuditTier(t *testing.T) {
	svc := &fakeAuditService{}
	err := NewClient(svc).Record(context.Background(), Event{
		Action:      ActionGroupMemberAdd,
		ActorUserID: "u-admin",
		Subject:     "u-ada",
		GroupID:     "group-security",
		Attributes:  map[string]string{"user_id": "u-ada"},
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	got := svc.got
	if got.GetTier() != auditv1.Tier_TIER_AUDIT || got.GetAction() != ActionGroupMemberAdd ||
		got.GetActorUserId() != "u-admin" || got.GetSubject() != "u-ada" || got.GetGroupId() != "group-security" ||
		got.GetAttributes()["user_id"] != "u-ada" || got.GetSensitive() {
		t.Fatalf("request = %+v", got)
	}
}

func TestClientReturnsTheAuditServiceError(t *testing.T) {
	want := errors.New("audit down")
	if err := NewClient(&fakeAuditService{err: want}).Record(context.Background(), Event{Action: ActionSignIn}); !errors.Is(err, want) {
		t.Fatalf("err = %v, want %v", err, want)
	}
}
