// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Governed machine access: service_accounts + api_tokens store.
// Mirrors the emailotp hash-at-rest pattern — api_tokens.token_hash is the
// ONLY thing persisted for a token; the plaintext never touches the database
// and this store never returns it. TokenByHash's WHERE clause is the single
// source of truth for "is this token currently usable" (not revoked, not
// expired): a revoked or expired token simply does not match a row, so
// callers cannot distinguish unknown/expired/revoked (fail-closed, no leak).

// serviceAccountRow is a database projection of a service account.
type serviceAccountRow struct {
	ID          string
	Name        string
	Description string
	Disabled    bool
	CreatedBy   string
	CreatedAt   time.Time
	OidcIssuer  string
	OidcSubject string
	// OidcAllowedGroups is the admin-set bound on the RACI groups a linked
	// OIDC client may hold. Never nil after a scan; empty means
	// no groups (fail closed).
	OidcAllowedGroups []string
}

// apiTokenRow is a database projection of API token METADATA — never the
// plaintext token value (which is never stored) nor its hash. ServiceAccountName
// is only populated by TokenByHash's join to identify the caller.
type apiTokenRow struct {
	ID                 string
	ServiceAccountID   string
	ServiceAccountName string
	Scope              string
	ExpiresAt          *time.Time
	RevokedAt          *time.Time
	LastUsedAt         *time.Time
	CreatedBy          string
	CreatedAt          time.Time
}

// serviceAccountStore is the pgxpool-backed store for service accounts and
// their API tokens.
type serviceAccountStore struct {
	db *pgxpool.Pool
}

func newServiceAccountStore(db *pgxpool.Pool) *serviceAccountStore {
	return &serviceAccountStore{db: db}
}

const serviceAccountCols = `id, name, description, disabled, created_by, created_at, oidc_issuer, oidc_subject, oidc_allowed_groups`

// scanServiceAccount scans a row projected with serviceAccountCols.
// oidc_issuer/oidc_subject are nullable (unset until LinkOidc is called), so
// they scan through *string and collapse NULL to "". oidc_allowed_groups is
// NOT NULL DEFAULT '{}'; it is still normalized to a non-nil slice.
func scanServiceAccount(row interface{ Scan(...any) error }) (*serviceAccountRow, error) {
	sa := &serviceAccountRow{}
	var oidcIssuer, oidcSubject *string
	if err := row.Scan(&sa.ID, &sa.Name, &sa.Description, &sa.Disabled, &sa.CreatedBy, &sa.CreatedAt, &oidcIssuer, &oidcSubject, &sa.OidcAllowedGroups); err != nil {
		return nil, err
	}
	if oidcIssuer != nil {
		sa.OidcIssuer = *oidcIssuer
	}
	if oidcSubject != nil {
		sa.OidcSubject = *oidcSubject
	}
	if sa.OidcAllowedGroups == nil {
		sa.OidcAllowedGroups = []string{}
	}
	return sa, nil
}

// CreateSA inserts a new service account, generating its id.
func (st *serviceAccountStore) CreateSA(ctx context.Context, name, description, createdBy string) (*serviceAccountRow, error) {
	id := "sa-" + uuid.NewString()
	row := st.db.QueryRow(ctx,
		`INSERT INTO service_accounts (id, name, description, created_by)
		 VALUES ($1, $2, $3, $4)
		 RETURNING `+serviceAccountCols,
		id, name, description, createdBy)
	return scanServiceAccount(row)
}

// ListSA returns all service accounts, oldest first.
func (st *serviceAccountStore) ListSA(ctx context.Context) ([]*serviceAccountRow, error) {
	rows, err := st.db.Query(ctx, `SELECT `+serviceAccountCols+` FROM service_accounts ORDER BY created_at`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*serviceAccountRow{}
	for rows.Next() {
		sa, err := scanServiceAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, sa)
	}
	return out, rows.Err()
}

// DisableSA soft-disables a service account (no delete). Returns pgx.ErrNoRows
// if the id does not exist.
func (st *serviceAccountStore) DisableSA(ctx context.Context, id string) (*serviceAccountRow, error) {
	row := st.db.QueryRow(ctx,
		`UPDATE service_accounts SET disabled = true WHERE id = $1
		 RETURNING `+serviceAccountCols,
		id)
	return scanServiceAccount(row)
}

// GetSA looks up a single service account by id. Returns pgx.ErrNoRows if it
// does not exist. Used by MintApiToken to reject minting for a disabled SA
// before any token is generated or persisted.
func (st *serviceAccountStore) GetSA(ctx context.Context, id string) (*serviceAccountRow, error) {
	row := st.db.QueryRow(ctx, `SELECT `+serviceAccountCols+` FROM service_accounts WHERE id = $1`, id)
	return scanServiceAccount(row)
}

// LinkOidc binds an Ory Hydra OAuth2 client (issuer, subject=client_id) to a
// service account, so it can authenticate via
// ResolveByOidc/ResolveServiceAccountByOidc alongside the opaque-token path.
// Returns pgx.ErrNoRows if the id does not exist. A second service account
// linking the SAME (issuer, subject) hits the service_accounts_oidc_idx
// unique index and surfaces as a 23505 pg error to the caller.
// allowedGroups REPLACES the stored bound wholesale; callers must pass a
// normalized, non-nil slice (an empty slice stores '{}' = no groups).
func (st *serviceAccountStore) LinkOidc(ctx context.Context, id, issuer, subject string, allowedGroups []string) (*serviceAccountRow, error) {
	if allowedGroups == nil {
		allowedGroups = []string{}
	}
	row := st.db.QueryRow(ctx,
		`UPDATE service_accounts SET oidc_issuer = $2, oidc_subject = $3, oidc_allowed_groups = $4 WHERE id = $1
		 RETURNING `+serviceAccountCols,
		id, issuer, subject, allowedGroups)
	return scanServiceAccount(row)
}

// UnlinkOidc clears a service account's OIDC client linkage (both columns
// back to NULL, allowed groups back to '{}'). Returns pgx.ErrNoRows if the id
// does not exist.
func (st *serviceAccountStore) UnlinkOidc(ctx context.Context, id string) (*serviceAccountRow, error) {
	row := st.db.QueryRow(ctx,
		`UPDATE service_accounts SET oidc_issuer = NULL, oidc_subject = NULL, oidc_allowed_groups = '{}' WHERE id = $1
		 RETURNING `+serviceAccountCols,
		id)
	return scanServiceAccount(row)
}

// ResolveByOidc looks up the service account linked to the given
// (issuer, subject), mirroring TokenByHash's fail-closed WHERE clause: an
// unknown pair and a pair belonging to a disabled service account both
// return pgx.ErrNoRows alike, so the caller cannot distinguish unlinked from
// disabled.
func (st *serviceAccountStore) ResolveByOidc(ctx context.Context, issuer, subject string) (*serviceAccountRow, error) {
	row := st.db.QueryRow(ctx,
		`SELECT `+serviceAccountCols+` FROM service_accounts
		  WHERE oidc_issuer = $1 AND oidc_subject = $2 AND NOT disabled`,
		issuer, subject)
	return scanServiceAccount(row)
}

// InsertToken persists a newly-minted token's metadata + hash (never the
// plaintext), generating the token's id. expiresAt=nil means no expiry.
func (st *serviceAccountStore) InsertToken(ctx context.Context, saID, tokenHash, scope string, expiresAt *time.Time, createdBy string) (*apiTokenRow, error) {
	id := "tok-" + uuid.NewString()
	row := st.db.QueryRow(ctx,
		`INSERT INTO api_tokens (id, service_account_id, token_hash, scope, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6)
		 RETURNING id, service_account_id, scope, expires_at, revoked_at, last_used_at, created_by, created_at`,
		id, saID, tokenHash, scope, expiresAt, createdBy)
	t := &apiTokenRow{}
	if err := row.Scan(&t.ID, &t.ServiceAccountID, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

// TokenByHash resolves a currently-usable token by its sha256 hash: not
// revoked, not expired (no expiry, or not yet past it), and belonging to a
// service account that is NOT disabled. A revoked/expired/unknown/disabled-SA
// hash all return pgx.ErrNoRows alike — the WHERE clause is the sole arbiter
// of validity so the caller cannot leak *why* a token failed. On a hit, bumps
// last_used_at to now() in the same statement (RETURNING the post-update row
// plus the joined service account name).
func (st *serviceAccountStore) TokenByHash(ctx context.Context, hash string) (*apiTokenRow, error) {
	row := st.db.QueryRow(ctx,
		`UPDATE api_tokens SET last_used_at = now()
		  FROM service_accounts sa
		  WHERE api_tokens.token_hash = $1
		    AND api_tokens.service_account_id = sa.id
		    AND api_tokens.revoked_at IS NULL
		    AND (api_tokens.expires_at IS NULL OR api_tokens.expires_at > now())
		    AND NOT sa.disabled
		 RETURNING api_tokens.id, api_tokens.service_account_id, sa.name,
		           api_tokens.scope, api_tokens.expires_at, api_tokens.revoked_at,
		           api_tokens.last_used_at, api_tokens.created_by, api_tokens.created_at`,
		hash)
	t := &apiTokenRow{}
	if err := row.Scan(&t.ID, &t.ServiceAccountID, &t.ServiceAccountName, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}

// ListTokens returns all token metadata for a service account, oldest first —
// never the hash, never a plaintext value (there is none to return).
func (st *serviceAccountStore) ListTokens(ctx context.Context, saID string) ([]*apiTokenRow, error) {
	rows, err := st.db.Query(ctx,
		`SELECT id, service_account_id, scope, expires_at, revoked_at, last_used_at, created_by, created_at
		   FROM api_tokens WHERE service_account_id = $1 ORDER BY created_at`,
		saID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []*apiTokenRow{}
	for rows.Next() {
		t := &apiTokenRow{}
		if err := rows.Scan(&t.ID, &t.ServiceAccountID, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// RevokeToken sets revoked_at=now() (idempotent: revoking an already-revoked
// token preserves the original revoked_at rather than re-stamping it — the
// audit trail must record when the token was FIRST revoked). Returns
// pgx.ErrNoRows if the id does not exist.
func (st *serviceAccountStore) RevokeToken(ctx context.Context, tokenID string) (*apiTokenRow, error) {
	row := st.db.QueryRow(ctx,
		`UPDATE api_tokens SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1
		 RETURNING id, service_account_id, scope, expires_at, revoked_at, last_used_at, created_by, created_at`,
		tokenID)
	t := &apiTokenRow{}
	if err := row.Scan(&t.ID, &t.ServiceAccountID, &t.Scope, &t.ExpiresAt, &t.RevokedAt, &t.LastUsedAt, &t.CreatedBy, &t.CreatedAt); err != nil {
		return nil, err
	}
	return t, nil
}
