// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// SendTransactionalEmail delivers an operator-supplied email through the
// already-configured SMTP sender (see WithEmail). It performs NO templating —
// the caller (the gateway, under AUTH_BACKEND=kratos) supplies the final
// subject/body — added so the gateway's Kratos-admin recovery flow can
// deliver a mint-out-of-band recovery code without Sneakers needing a
// separate notification/jobs-exchange service. Unavailable when no sender is
// configured; this RPC has no dev-echo fallback (it carries operator-supplied
// content, not a code to log, unlike the OTP flows).
func (s *Server) SendTransactionalEmail(ctx context.Context, req *identityv1.SendTransactionalEmailRequest) (*identityv1.SendTransactionalEmailResponse, error) {
	if req.GetTo() == "" || req.GetSubject() == "" || req.GetBody() == "" {
		return nil, status.Error(codes.InvalidArgument, "to, subject, and body are required")
	}
	if s.sender == nil {
		return nil, status.Error(codes.Unavailable, "email sender not configured")
	}
	if err := s.sender.Send(req.GetTo(), req.GetSubject(), req.GetBody()); err != nil {
		return nil, status.Errorf(codes.Internal, "send email: %v", err)
	}
	return &identityv1.SendTransactionalEmailResponse{}, nil
}
