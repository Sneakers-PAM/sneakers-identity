// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// userTokenPrefix lets callers route a bearer to the right verifier without a
// database probe, and lets secret scanners recognise a leaked token.
const userTokenPrefix = "snk_u_"

const userTokenCols = `id, user_id, label, client_name, created_at, last_used_at, revoked_at, expires_at` // #nosec G101 -- a column list, not a credential

func scanUserToken(row interface{ Scan(...any) error }) (*identityv1.UserToken, error) {
	var (
		t                          identityv1.UserToken
		created                    time.Time
		lastUsed, revoked, expires *time.Time
	)
	if err := row.Scan(&t.Id, &t.UserId, &t.Label, &t.ClientName, &created, &lastUsed, &revoked, &expires); err != nil {
		return nil, err
	}
	t.CreatedAtUnix = created.Unix()
	t.LastUsedAtUnix = unixOrZero(lastUsed)
	t.RevokedAtUnix = unixOrZero(revoked)
	t.ExpiresAtUnix = unixOrZero(expires)
	return &t, nil
}

func (s *Server) MintUserToken(ctx context.Context, req *identityv1.MintUserTokenRequest) (*identityv1.MintUserTokenResponse, error) {
	userID := strings.TrimSpace(req.GetUserId())
	if userID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "mint user token: %v", err)
	}
	if u.GetDisabledAtUnix() != 0 {
		return nil, status.Error(codes.FailedPrecondition, "user is disabled")
	}
	raw, err := randomToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate token: %v", err)
	}
	token := userTokenPrefix + raw
	var expiresAt *time.Time
	if u := req.GetExpiresAtUnix(); u > 0 {
		t := time.Unix(u, 0).UTC()
		expiresAt = &t
	}
	meta, err := scanUserToken(s.db.QueryRow(ctx,
		`INSERT INTO user_tokens (id, user_id, token_hash, label, client_name, expires_at)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING `+userTokenCols,
		"utok-"+uuid.NewString(), userID, hashToken(token), strings.TrimSpace(req.GetLabel()), strings.TrimSpace(req.GetClientName()), expiresAt))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "mint user token: %v", err)
	}
	lg := s.lg(ctx)
	lg.Info("user token minted", log.F("token_id", meta.GetId()), log.F("user_id", userID))
	return &identityv1.MintUserTokenResponse{Token: token, Meta: meta}, nil
}

func (s *Server) ListUserTokens(ctx context.Context, req *identityv1.ListUserTokensRequest) (*identityv1.ListUserTokensResponse, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userTokenCols+` FROM user_tokens WHERE user_id=$1 ORDER BY created_at DESC`, req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list user tokens: %v", err)
	}
	defer rows.Close()
	out := []*identityv1.UserToken{}
	for rows.Next() {
		t, err := scanUserToken(rows)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "list user tokens: %v", err)
		}
		out = append(out, t)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "list user tokens: %v", err)
	}
	return &identityv1.ListUserTokensResponse{Tokens: out}, nil
}

func (s *Server) RevokeUserToken(ctx context.Context, req *identityv1.RevokeUserTokenRequest) (*identityv1.RevokeUserTokenResponse, error) {
	meta, err := scanUserToken(s.db.QueryRow(ctx,
		`UPDATE user_tokens SET revoked_at = COALESCE(revoked_at, now())
		  WHERE id=$1 AND user_id=$2
		 RETURNING `+userTokenCols, req.GetId(), req.GetUserId()))
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "token not found")
		}
		return nil, status.Errorf(codes.Internal, "revoke user token: %v", err)
	}
	lg := s.lg(ctx)
	lg.Info("user token revoked", log.F("token_id", meta.GetId()), log.F("user_id", meta.GetUserId()))
	return &identityv1.RevokeUserTokenResponse{Meta: meta}, nil
}

// VerifyUserToken answers valid=false identically for every failure so a
// caller can't probe which tokens exist or why one stopped working.
func (s *Server) VerifyUserToken(ctx context.Context, req *identityv1.VerifyUserTokenRequest) (*identityv1.VerifyUserTokenResponse, error) {
	token := req.GetToken()
	if !strings.HasPrefix(token, userTokenPrefix) {
		return &identityv1.VerifyUserTokenResponse{}, nil
	}
	var tokenID, userID string
	err := s.db.QueryRow(ctx,
		`UPDATE user_tokens t SET last_used_at = now()
		   FROM users u
		  WHERE t.token_hash=$1 AND t.revoked_at IS NULL AND (t.expires_at IS NULL OR t.expires_at > now())
		    AND u.id = t.user_id AND u.disabled_at IS NULL
		 RETURNING t.id, t.user_id`, hashToken(token)).Scan(&tokenID, &userID)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return &identityv1.VerifyUserTokenResponse{}, nil
		}
		return nil, status.Errorf(codes.Internal, "verify user token: %v", err)
	}
	u, err := s.getUserByID(ctx, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "verify user token: %v", err)
	}
	groups, err := s.userGroupNames(ctx, userID)
	if err != nil {
		return nil, err
	}
	return &identityv1.VerifyUserTokenResponse{Valid: true, TokenId: tokenID, User: u, GroupNames: groups}, nil
}

func (s *Server) SetUserDisabled(ctx context.Context, req *identityv1.SetUserDisabledRequest) (*identityv1.SetUserDisabledResponse, error) {
	u, err := scanUser(s.db.QueryRow(ctx,
		`UPDATE users SET disabled_at = CASE WHEN $2 THEN COALESCE(disabled_at, now()) END
		  WHERE id=$1
		 RETURNING `+userCols, req.GetUserId(), req.GetDisabled()))
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "set user disabled: %v", err)
	}
	lg := s.lg(ctx)
	lg.Info("user disabled state changed", log.F("user_id", u.GetId()), log.F("disabled", req.GetDisabled()))
	return &identityv1.SetUserDisabledResponse{User: u}, nil
}
