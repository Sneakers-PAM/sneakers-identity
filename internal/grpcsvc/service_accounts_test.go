// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"testing"

	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestCreateServiceAccountInputValidation covers the argument check that
// short-circuits before any DB access, so it runs without a Postgres
// (unit-safe) — mirrors TestResolveUserByEmailInputValidation.
func TestCreateServiceAccountInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty name: want InvalidArgument, got %v", err)
	}
	if _, err := s.CreateServiceAccount(ctx, &identityv1.CreateServiceAccountRequest{Name: "   "}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("blank name: want InvalidArgument, got %v", err)
	}
}

// TestMintApiTokenInputValidation covers the argument check that short-circuits
// before any DB access (unit-safe).
func TestMintApiTokenInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.MintApiToken(ctx, &identityv1.MintApiTokenRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty service_account_id: want InvalidArgument, got %v", err)
	}
}

// TestDisableServiceAccountInputValidation covers the argument check that
// short-circuits before any DB access (unit-safe).
func TestDisableServiceAccountInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.DisableServiceAccount(ctx, &identityv1.DisableServiceAccountRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty id: want InvalidArgument, got %v", err)
	}
}

// TestRevokeApiTokenInputValidation covers the argument check that
// short-circuits before any DB access (unit-safe).
func TestRevokeApiTokenInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.RevokeApiToken(ctx, &identityv1.RevokeApiTokenRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty id: want InvalidArgument, got %v", err)
	}
}

// TestVerifyApiTokenInputValidation covers the argument check that
// short-circuits before any DB access (unit-safe). An empty token must never
// reach the hash/lookup path.
func TestVerifyApiTokenInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	resp, err := s.VerifyApiToken(ctx, &identityv1.VerifyApiTokenRequest{})
	if err != nil {
		t.Fatalf("empty token should not error, got %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("empty token must never be valid")
	}
}

// TestLinkOidcClientInputValidation covers the argument checks that
// short-circuit before any DB access (unit-safe).
func TestLinkOidcClientInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty service_account_id: want InvalidArgument, got %v", err)
	}
	if _, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
		ServiceAccountId: "sa-1", OidcSubject: "client-1",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty oidc_issuer: want InvalidArgument, got %v", err)
	}
	if _, err := s.LinkOidcClient(ctx, &identityv1.LinkOidcClientRequest{
		ServiceAccountId: "sa-1", OidcIssuer: "https://hydra.example/",
	}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty oidc_subject: want InvalidArgument, got %v", err)
	}
}

// TestUnlinkOidcClientInputValidation covers the argument check that
// short-circuits before any DB access (unit-safe).
func TestUnlinkOidcClientInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	if _, err := s.UnlinkOidcClient(ctx, &identityv1.UnlinkOidcClientRequest{}); status.Code(err) != codes.InvalidArgument {
		t.Errorf("empty service_account_id: want InvalidArgument, got %v", err)
	}
}

// TestResolveServiceAccountByOidcInputValidation covers the argument check
// that short-circuits before any DB access (unit-safe): an empty issuer or
// subject can never match a real linkage, so it resolves valid=false without
// touching the store — mirrors TestVerifyApiTokenInputValidation.
func TestResolveServiceAccountByOidcInputValidation(t *testing.T) {
	s := &Server{}
	ctx := context.Background()

	resp, err := s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{})
	if err != nil {
		t.Fatalf("empty issuer+subject should not error, got %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("empty issuer+subject must never be valid")
	}

	resp, err = s.ResolveServiceAccountByOidc(ctx, &identityv1.ResolveServiceAccountByOidcRequest{OidcIssuer: "https://hydra.example/"})
	if err != nil {
		t.Fatalf("empty subject should not error, got %v", err)
	}
	if resp.GetValid() {
		t.Fatalf("empty subject must never be valid")
	}
}
