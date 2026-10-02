// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeSender struct {
	to, subject, body string
	err               error
}

func (f *fakeSender) Send(to, subject, body string) error {
	f.to, f.subject, f.body = to, subject, body
	return f.err
}

func TestSendTransactionalEmail_Sends(t *testing.T) {
	fs := &fakeSender{}
	s := New(nil).WithEmail(fs, false)
	_, err := s.SendTransactionalEmail(context.Background(), &identityv1.SendTransactionalEmailRequest{
		To: "ada@example.org", Subject: "Reset your Sneakers password", Body: "code: 483920",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fs.to != "ada@example.org" || fs.subject != "Reset your Sneakers password" || fs.body != "code: 483920" {
		t.Fatalf("sender not called with request fields: %+v", fs)
	}
}

func TestSendTransactionalEmail_NoSenderConfigured(t *testing.T) {
	s := New(nil)
	_, err := s.SendTransactionalEmail(context.Background(), &identityv1.SendTransactionalEmailRequest{
		To: "ada@example.org", Subject: "s", Body: "b",
	})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("expected Unavailable, got %v", err)
	}
}

func TestSendTransactionalEmail_MissingFields(t *testing.T) {
	s := New(nil).WithEmail(&fakeSender{}, false)
	_, err := s.SendTransactionalEmail(context.Background(), &identityv1.SendTransactionalEmailRequest{To: "ada@example.org"})
	if status.Code(err) != codes.InvalidArgument {
		t.Fatalf("expected InvalidArgument, got %v", err)
	}
}

func TestSendTransactionalEmail_SendFailure(t *testing.T) {
	fs := &fakeSender{err: errors.New("smtp down")}
	s := New(nil).WithEmail(fs, false)
	_, err := s.SendTransactionalEmail(context.Background(), &identityv1.SendTransactionalEmailRequest{
		To: "ada@example.org", Subject: "s", Body: "b",
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("expected Internal, got %v", err)
	}
}
