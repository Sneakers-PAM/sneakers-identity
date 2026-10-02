// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Governed machine access: service-account CRUD + API-token
// mint/verify/revoke over the service_accounts/api_tokens store. Mirrors the
// emailotp.go token-secrecy pattern: crypto/rand for entropy, sha256-hex for
// at-rest storage, and a plaintext value that is returned exactly once (at
// mint) and never logged, never returned by list, never re-derivable from the
// hash. Authorization for the mutating RPCs (create/mint/revoke/disable) is
// enforced at the gateway (admin), like the other mutating identity RPCs
// (CreateGroup, SetUserRoles, ...); VerifyApiToken is the one RPC every
// unauthenticated machine request calls, by design.

// apiTokenEntropyBytes is the raw entropy of a minted token before base64url
// encoding — 32 bytes (256 bits), full entropy (unlike the numeric MFA OTP,
// which trades entropy for human typability).
const apiTokenEntropyBytes = 32

// saStore returns the service_accounts/api_tokens store bound to this server's
// pool.
func (s *Server) saStore() *serviceAccountStore {
	return newServiceAccountStore(s.db)
}

// randomToken mints an opaque, high-entropy API token: crypto/rand bytes,
// base64url (no padding) encoded.
func randomToken() (string, error) {
	buf := make([]byte, apiTokenEntropyBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// hashToken returns the hex sha256 of a plaintext token (what we store at
// rest) — mirrors hashOTPCode.
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// toServiceAccountProto projects a store row onto the wire message.
func toServiceAccountProto(sa *serviceAccountRow) *identityv1.ServiceAccount {
	return &identityv1.ServiceAccount{
		Id:                sa.ID,
		Name:              sa.Name,
		Description:       sa.Description,
		Disabled:          sa.Disabled,
		CreatedBy:         sa.CreatedBy,
		CreatedAtUnix:     sa.CreatedAt.Unix(),
		OidcIssuer:        sa.OidcIssuer,
		OidcSubject:       sa.OidcSubject,
		OidcAllowedGroups: sa.OidcAllowedGroups,
	}
}

// normalizeAllowedGroups tidies the site-admin-supplied OIDC allowed-groups
// references before canonicalAllowedGroups resolves them to group IDs: trims
// whitespace, drops blanks, and de-duplicates exact repeats (first occurrence
// wins, order preserved). Always returns a non-nil slice so an empty bound is
// stored as '{}' — "no groups", never "all".
func normalizeAllowedGroups(in []string) []string {
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, g := range in {
		g = strings.TrimSpace(g)
		if g == "" {
			continue
		}
		if _, dup := seen[g]; dup {
			continue
		}
		seen[g] = struct{}{}
		out = append(out, g)
	}
	return out
}

// toApiTokenProto projects a store row onto the wire message. NEVER carries a
// token value — the row itself only ever holds the hash, and this only reads
// metadata columns.
func toApiTokenProto(t *apiTokenRow) *identityv1.ApiToken {
	return &identityv1.ApiToken{
		Id:               t.ID,
		ServiceAccountId: t.ServiceAccountID,
		Scope:            t.Scope,
		ExpiresAtUnix:    unixOrZero(t.ExpiresAt),
		RevokedAtUnix:    unixOrZero(t.RevokedAt),
		LastUsedAtUnix:   unixOrZero(t.LastUsedAt),
		CreatedBy:        t.CreatedBy,
	}
}

// unixOrZero converts an optional timestamp to unix seconds, or 0 when unset.
func unixOrZero(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.Unix()
}

// CreateServiceAccount provisions a new machine principal. Admin-gated at the
// gateway, like CreateGroup. A duplicate (case-insensitive) name surfaces as
// AlreadyExists.
func (s *Server) CreateServiceAccount(ctx context.Context, req *identityv1.CreateServiceAccountRequest) (*identityv1.CreateServiceAccountResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	row, err := s.saStore().CreateSA(ctx, name, req.GetDescription(), req.GetCreatedBy())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "a service account with that name already exists")
		}
		return nil, status.Errorf(codes.Internal, "create service account: %v", err)
	}
	return &identityv1.CreateServiceAccountResponse{ServiceAccount: toServiceAccountProto(row)}, nil
}

// ListServiceAccounts returns every service account (including disabled ones —
// the admin UI needs to see and re-enable them).
func (s *Server) ListServiceAccounts(ctx context.Context, _ *identityv1.ListServiceAccountsRequest) (*identityv1.ListServiceAccountsResponse, error) {
	rows, err := s.saStore().ListSA(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list service accounts: %v", err)
	}
	out := make([]*identityv1.ServiceAccount, 0, len(rows))
	for _, r := range rows {
		out = append(out, toServiceAccountProto(r))
	}
	return &identityv1.ListServiceAccountsResponse{ServiceAccounts: out}, nil
}

// DisableServiceAccount soft-disables a service account (no delete); its
// already-minted tokens keep their own independent expiry/revocation state.
// Admin-gated at the gateway.
func (s *Server) DisableServiceAccount(ctx context.Context, req *identityv1.DisableServiceAccountRequest) (*identityv1.DisableServiceAccountResponse, error) {
	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	row, err := s.saStore().DisableSA(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "service account not found")
		}
		return nil, status.Errorf(codes.Internal, "disable service account: %v", err)
	}
	return &identityv1.DisableServiceAccountResponse{ServiceAccount: toServiceAccountProto(row)}, nil
}

// MintApiToken is the ONLY RPC that ever returns a token value: it generates a
// fresh high-entropy token, persists only its hash, and returns the plaintext
// exactly once alongside its metadata. Admin-gated at the gateway. Rejects
// minting for a disabled service account (FailedPrecondition) BEFORE
// generating or persisting anything — a disabled SA must not gain new
// credentials, mirroring how TokenByHash fails its already-minted ones
// closed. The scope is validated and canonicalized to group IDs
// (canonicalMintScope) before anything is generated. Logs only the minted
// token's id + service account id — NEVER the token.
func (s *Server) MintApiToken(ctx context.Context, req *identityv1.MintApiTokenRequest) (*identityv1.MintApiTokenResponse, error) {
	saID := strings.TrimSpace(req.GetServiceAccountId())
	if saID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id is required")
	}
	sa, err := s.saStore().GetSA(ctx, saID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "service account not found")
		}
		return nil, status.Errorf(codes.Internal, "mint api token: %v", err)
	}
	if sa.Disabled {
		return nil, status.Error(codes.FailedPrecondition, "service account is disabled")
	}
	scope, err := s.canonicalMintScope(ctx, req.GetScope())
	if err != nil {
		return nil, err
	}
	token, err := randomToken()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "generate token: %v", err)
	}
	var expiresAt *time.Time
	if u := req.GetExpiresAtUnix(); u > 0 {
		t := time.Unix(u, 0).UTC()
		expiresAt = &t
	}
	row, err := s.saStore().InsertToken(ctx, saID, hashToken(token), scope, expiresAt, req.GetCreatedBy())
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return nil, status.Error(codes.NotFound, "service account not found")
		}
		return nil, status.Errorf(codes.Internal, "mint api token: %v", err)
	}
	lg := log.Ctx(ctx)
	lg.Info().Str("token_id", row.ID).Str("service_account_id", saID).Msg("api token minted")
	return &identityv1.MintApiTokenResponse{Token: token, Meta: toApiTokenProto(row)}, nil
}

// ListApiTokens returns token METADATA for a service account — never a token
// value (the store's projection has no such column to leak).
func (s *Server) ListApiTokens(ctx context.Context, req *identityv1.ListApiTokensRequest) (*identityv1.ListApiTokensResponse, error) {
	saID := strings.TrimSpace(req.GetServiceAccountId())
	if saID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id is required")
	}
	rows, err := s.saStore().ListTokens(ctx, saID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list api tokens: %v", err)
	}
	out := make([]*identityv1.ApiToken, 0, len(rows))
	for _, r := range rows {
		out = append(out, toApiTokenProto(r))
	}
	return &identityv1.ListApiTokensResponse{Tokens: out}, nil
}

// RevokeApiToken immediately invalidates a token. Admin-gated at the gateway.
func (s *Server) RevokeApiToken(ctx context.Context, req *identityv1.RevokeApiTokenRequest) (*identityv1.RevokeApiTokenResponse, error) {
	id := strings.TrimSpace(req.GetId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "id is required")
	}
	row, err := s.saStore().RevokeToken(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "token not found")
		}
		return nil, status.Errorf(codes.Internal, "revoke api token: %v", err)
	}
	lg := log.Ctx(ctx)
	lg.Info().Str("token_id", id).Msg("api token revoked")
	return &identityv1.RevokeApiTokenResponse{Meta: toApiTokenProto(row)}, nil
}

// LinkOidcClient binds an Ory Hydra OAuth2 client (issuer, subject=client_id)
// to a service account, so it can authenticate via
// ResolveServiceAccountByOidc alongside the existing opaque-token path.
// allowed_groups (replaced wholesale on every call) is the admin-controlled
// bound intersected with the JWT's scope groups; each entry (ID, exact name,
// or slug) must resolve to exactly one directory group or the call is
// rejected, and the list is stored as canonical group IDs
// (canonicalAllowedGroups). An empty list links the client but grants it no
// groups. Admin-gated at the gateway, like the other mutating service-account RPCs. A
// second service account linking the SAME (issuer, subject) surfaces as
// AlreadyExists. Logs only the service account id + acting admin — never a
// secret, since (issuer, subject) is not one.
func (s *Server) LinkOidcClient(ctx context.Context, req *identityv1.LinkOidcClientRequest) (*identityv1.LinkOidcClientResponse, error) {
	saID := strings.TrimSpace(req.GetServiceAccountId())
	if saID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id is required")
	}
	issuer := strings.TrimSpace(req.GetOidcIssuer())
	if issuer == "" {
		return nil, status.Error(codes.InvalidArgument, "oidc_issuer is required")
	}
	subject := strings.TrimSpace(req.GetOidcSubject())
	if subject == "" {
		return nil, status.Error(codes.InvalidArgument, "oidc_subject is required")
	}
	allowed, err := s.canonicalAllowedGroups(ctx, req.GetAllowedGroups())
	if err != nil {
		return nil, err
	}
	row, err := s.saStore().LinkOidc(ctx, saID, issuer, subject, allowed)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "service account not found")
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "that OIDC client is already linked to a service account")
		}
		return nil, status.Errorf(codes.Internal, "link oidc client: %v", err)
	}
	lg := log.Ctx(ctx)
	lg.Info().Str("service_account_id", saID).Str("acting_admin", req.GetActingAdmin()).
		Strs("allowed_groups", allowed).Msg("oidc client linked")
	return &identityv1.LinkOidcClientResponse{ServiceAccount: toServiceAccountProto(row)}, nil
}

// UnlinkOidcClient clears a service account's OIDC client linkage.
// Admin-gated at the gateway.
func (s *Server) UnlinkOidcClient(ctx context.Context, req *identityv1.UnlinkOidcClientRequest) (*identityv1.UnlinkOidcClientResponse, error) {
	saID := strings.TrimSpace(req.GetServiceAccountId())
	if saID == "" {
		return nil, status.Error(codes.InvalidArgument, "service_account_id is required")
	}
	row, err := s.saStore().UnlinkOidc(ctx, saID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "service account not found")
		}
		return nil, status.Errorf(codes.Internal, "unlink oidc client: %v", err)
	}
	lg := log.Ctx(ctx)
	lg.Info().Str("service_account_id", saID).Str("acting_admin", req.GetActingAdmin()).Msg("oidc client unlinked")
	return &identityv1.UnlinkOidcClientResponse{ServiceAccount: toServiceAccountProto(row)}, nil
}

// ResolveServiceAccountByOidc is the gateway's OIDC machine-auth check: hash-
// free equivalent of VerifyApiToken. valid=false covers unknown and disabled
// ALIKE — the caller must never be able to tell which (fail-closed, no leak).
// An empty issuer or subject short-circuits before any DB access (neither can
// ever match a real linkage).
//
// The response's scope field (4) is deliberately left unset here, always —
// this is intentional, not an oversight. service_accounts has no scope
// column: scope lives on api_tokens, and an OIDC-linked client has no
// api_token row to read one from. The gateway (bff.oidcVerifier) knows this
// and deliberately ignores this response's Scope, sourcing RACI scope from
// the verified JWT's own scope/scp claim instead. If this ever starts being
// populated, the gateway will silently keep ignoring it — coordinate any
// such change with the gateway's bff package first, or the two will
// silently diverge on what actually grants access.
//
// The gateway passes the verified JWT's scope claim in the request; the
// response's group_names is that scope resolved by the scope grammar
// (group_scope.go) INTERSECT the linkage's allowed_groups. Empty allowed
// groups or empty scope yields no groups (fail closed).
func (s *Server) ResolveServiceAccountByOidc(ctx context.Context, req *identityv1.ResolveServiceAccountByOidcRequest) (*identityv1.ResolveServiceAccountByOidcResponse, error) {
	issuer := req.GetOidcIssuer()
	subject := req.GetOidcSubject()
	if issuer == "" || subject == "" {
		return &identityv1.ResolveServiceAccountByOidcResponse{Valid: false}, nil
	}
	row, err := s.saStore().ResolveByOidc(ctx, issuer, subject)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &identityv1.ResolveServiceAccountByOidcResponse{Valid: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "resolve service account by oidc: %v", err)
	}
	var names []string
	if len(row.OidcAllowedGroups) > 0 && strings.TrimSpace(req.GetScope()) != "" {
		ix, err := s.loadGroupIndex(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "resolve service account by oidc: load groups: %v", err)
		}
		gs, blocked := ix.resolveScope(req.GetScope())
		logBlockedScope(ctx, row.ID, blocked)
		names = groupNames(ix.bound(gs, row.OidcAllowedGroups))
	}
	return &identityv1.ResolveServiceAccountByOidcResponse{
		ServiceAccountId: row.ID,
		Name:             row.Name,
		Valid:            true,
		// The admin-set bound, informational for the gateway.
		AllowedGroups: row.OidcAllowedGroups,
		// JWT scope groups INTERSECT allowed_groups: the ONLY grant.
		GroupNames: names,
	}, nil
}

// VerifyApiToken is the gateway's machine bearer-auth check: hash the
// presented token and look it up. valid=false covers unknown, expired, and
// revoked tokens ALIKE — the caller must never be able to tell which (fail-
// closed, no leak). An empty token short-circuits before any DB access (it can
// never match a real token's hash).
func (s *Server) VerifyApiToken(ctx context.Context, req *identityv1.VerifyApiTokenRequest) (*identityv1.VerifyApiTokenResponse, error) {
	token := req.GetToken()
	if token == "" {
		return &identityv1.VerifyApiTokenResponse{Valid: false}, nil
	}
	row, err := s.saStore().TokenByHash(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return &identityv1.VerifyApiTokenResponse{Valid: false}, nil
		}
		return nil, status.Errorf(codes.Internal, "verify api token: %v", err)
	}
	var names []string
	if strings.TrimSpace(row.Scope) != "" {
		ix, err := s.loadGroupIndex(ctx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "verify api token: load groups: %v", err)
		}
		gs, blocked := ix.resolveScope(row.Scope)
		logBlockedScope(ctx, row.ServiceAccountID, blocked)
		names = groupNames(gs)
	}
	return &identityv1.VerifyApiTokenResponse{
		ServiceAccountId: row.ServiceAccountID,
		Name:             row.ServiceAccountName,
		Scope:            row.Scope,
		Valid:            true,
		// The mint-time scope (the admin's bound for this path) resolved by
		// the scope grammar: the ONLY grant.
		GroupNames: names,
	}, nil
}

// canonicalMintScope validates a MintApiToken scope and rewrites it to
// space-separated canonical group IDs. Every whitespace-separated entry must
// resolve (resolveAdminRef) to exactly one usable directory group; an unknown,
// colliding or ambiguous entry rejects the mint (InvalidArgument), so an admin
// can never mint a token whose scope silently grants nothing. An empty scope
// is allowed: the token then grants no groups, only the service account's own
// principal-id RACI grants. IDs are immune to renames, which is why the
// stored form is IDs rather than the names or slugs the admin typed.
func (s *Server) canonicalMintScope(ctx context.Context, scope string) (string, error) {
	toks := strings.Fields(scope)
	if len(toks) == 0 {
		return "", nil
	}
	ix, err := s.loadGroupIndex(ctx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "mint api token: load groups: %v", err)
	}
	ids := make([]string, 0, len(toks))
	seen := make(map[string]struct{}, len(toks))
	for _, tok := range toks {
		g, ok := ix.resolveAdminRef(tok)
		if !ok || !validScopeToken(g.ID) {
			return "", status.Errorf(codes.InvalidArgument,
				"scope entry %q does not resolve to exactly one group (use a group ID or a unique group slug)", tok)
		}
		if _, dup := seen[g.ID]; dup {
			continue
		}
		seen[g.ID] = struct{}{}
		ids = append(ids, g.ID)
	}
	return strings.Join(ids, " "), nil
}

// canonicalAllowedGroups validates a LinkOidcClient allowed_groups list and
// rewrites it to canonical group IDs (trimmed, de-duplicated, order kept).
// Every entry must resolve (resolveAdminRef: ID, unique exact name, or slug)
// to exactly one usable directory group, else InvalidArgument. Always returns
// a non-nil slice so an empty bound is stored as '{}' ("no groups").
func (s *Server) canonicalAllowedGroups(ctx context.Context, in []string) ([]string, error) {
	refs := normalizeAllowedGroups(in)
	ids := make([]string, 0, len(refs))
	if len(refs) == 0 {
		return ids, nil
	}
	ix, err := s.loadGroupIndex(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "link oidc client: load groups: %v", err)
	}
	seen := make(map[string]struct{}, len(refs))
	for _, ref := range refs {
		g, ok := ix.resolveAdminRef(ref)
		if !ok {
			return nil, status.Errorf(codes.InvalidArgument,
				"allowed_groups entry %q does not resolve to exactly one group", ref)
		}
		if _, dup := seen[g.ID]; dup {
			continue
		}
		seen[g.ID] = struct{}{}
		ids = append(ids, g.ID)
	}
	return ids, nil
}

// logBlockedScope warns when a machine scope token hit a fail-closed rule
// (slug collision, ID shadow, duplicate group name). It logs only the service
// account id and the directory-derived keys, never the token or the rest of
// the caller's scope, so an operator can see which groups to rename or which
// scope entries to switch to the ID form.
func logBlockedScope(ctx context.Context, saID string, blocked []string) {
	if len(blocked) == 0 {
		return
	}
	lg := log.Ctx(ctx)
	lg.Warn().Str("service_account_id", saID).Strs("ambiguous_group_refs", blocked).
		Msg("machine scope entries match more than one group and grant nothing; use the group ID form")
}
