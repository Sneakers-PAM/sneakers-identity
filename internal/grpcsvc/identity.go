// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Package grpcsvc implements the sneakers.identity.v1.IdentityService over
// Postgres. It stands in for the lldap/Keycloak-backed directory (plus a future
// orgs/RBAC service); the gRPC surface stays the same when that arrives.
// User provisioning lives upstream; groups are created in lldap and mirrored
// into the identity groups table (see group_sync.go). Dev/qa demo data is
// installed out-of-band by the go-seed `cmd/seed` tool, not by the service.
package grpcsvc

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/email"
	"github.com/Sneakers-PAM/sneakers-identity/internal/lldap"
	"github.com/Sneakers-PAM/sneakers-identity/internal/secrets"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Server struct {
	identityv1.UnimplementedIdentityServiceServer
	// db runs single statements on the pool; pg owns the pool and runs the
	// multi-statement transactions.
	db postgres.Querier
	pg *postgres.DB
	// log is the service logger; nil discards (tests that build a bare Server).
	log log.Logger
	// cipher seals/opens the TOTP shared secret at rest. nil = TOTP not
	// configured (no TOTP_ENC_KEY): the TOTP RPCs then return Unavailable.
	cipher *secrets.Cipher
	// sender delivers MFA email OTP codes. nil = no relay configured (dev): the
	// code is still minted (and dev-echoed when devEcho is on) so local testing
	// works without SMTP.
	sender email.Sender
	// devEcho logs freshly-minted OTP codes for dev ergonomics. Never enable in
	// prod (OTP_DEV_ECHO).
	devEcho bool
	// lldap is the directory write client used by the first-run /setup bootstrap
	// (BootstrapRoot) to create the very first admin in lldap so Keycloak
	// federation can log them in. nil = not configured: BootstrapRoot returns
	// Unavailable (fail closed). Identity is otherwise read-mostly.
	lldap  lldap.Admin
	kratos kratosAdmin
	// totpIssuer is the authenticator-app issuer label baked into enrollment QRs
	// (TOTP_ISSUER). Per-environment so entries don't collide across stacks —
	// e.g. "Sneakers (local)" in dev, plain "Sneakers" in prod. Empty → default.
	totpIssuer string
	// webauthn is the passkey Relying Party. nil = not configured
	// (WEBAUTHN_RP_ID unset/"-"): the ceremony RPCs return Unavailable, but
	// list/remove (plain store reads) still work.
	webauthn *webauthn.WebAuthn
}

func New(db *postgres.DB) *Server {
	s := &Server{pg: db}
	if db != nil {
		s.db = db.Querier()
	}
	return s
}

// WithLogger sets the logger the RPCs write through. Returns the receiver for
// chaining.
func (s *Server) WithLogger(l log.Logger) *Server {
	s.log = l
	return s
}

// lg returns the service logger correlated with the span in ctx.
func (s *Server) lg(ctx context.Context) log.Logger {
	if s.log == nil {
		return log.Nop()
	}
	return s.log.Ctx(ctx)
}

// WithCipher wires the at-rest cipher for the TOTP secret. Returns the receiver
// for chaining; cipher=nil leaves the TOTP RPCs disabled (Unavailable).
func (s *Server) WithCipher(c *secrets.Cipher) *Server {
	s.cipher = c
	return s
}

// WithEmail wires the MFA email-OTP sender and dev-echo. sender=nil leaves email
// OTP to dev-echo alone (fine for local testing); devEcho logs minted codes.
func (s *Server) WithEmail(sender email.Sender, devEcho bool) *Server {
	s.sender = sender
	s.devEcho = devEcho
	return s
}

// WithLldap wires the lldap directory write client for the first-run /setup
// bootstrap. admin=nil leaves BootstrapRoot disabled (Unavailable).
func (s *Server) WithLldap(admin lldap.Admin) *Server {
	s.lldap = admin
	return s
}

// WithTotpIssuer sets the authenticator-app issuer label for enrollment QRs.
// Empty keeps the default (see effectiveTotpIssuer).
func (s *Server) WithTotpIssuer(issuer string) *Server {
	s.totpIssuer = issuer
	return s
}

// WithWebauthn wires the passkey Relying Party. nil leaves the ceremony RPCs
// disabled (Unavailable).
func (s *Server) WithWebauthn(wa *webauthn.WebAuthn) *Server {
	s.webauthn = wa
	return s
}

// RegisterOn registers the receiver as the IdentityService on gs.
func (s *Server) RegisterOn(gs *grpc.Server) {
	identityv1.RegisterIdentityServiceServer(gs, s)
}

// userCols is the canonical user projection scanned by scanUser; keep the two
// in lock-step.
const userCols = `id, name, email, roles, is_root, keycloak_subject, username, email_verified, disabled_at`

// scanUser hydrates a User from a row selected with userCols.
func scanUser(row interface{ Scan(...any) error }) (*identityv1.User, error) {
	u := &identityv1.User{}
	var disabledAt *time.Time
	if err := row.Scan(&u.Id, &u.Name, &u.Email, &u.Roles, &u.IsRoot, &u.KeycloakSubject, &u.Username, &u.EmailVerified, &disabledAt); err != nil {
		return nil, err
	}
	u.DisabledAtUnix = unixOrZero(disabledAt)
	return u, nil
}

func (s *Server) ListUsers(ctx context.Context, _ *identityv1.ListUsersRequest) (*identityv1.ListUsersResponse, error) {
	rows, err := s.db.Query(ctx, `SELECT `+userCols+` FROM users ORDER BY name`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list users: %v", err)
	}
	defer rows.Close()
	var out []*identityv1.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "scan user: %v", err)
		}
		out = append(out, u)
	}
	return &identityv1.ListUsersResponse{Users: out}, rows.Err()
}

func (s *Server) GetUser(ctx context.Context, req *identityv1.GetUserRequest) (*identityv1.GetUserResponse, error) {
	u, err := scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, req.GetId()))
	if err != nil {
		return nil, status.Error(codes.NotFound, "user not found")
	}
	return &identityv1.GetUserResponse{User: u}, nil
}

func (s *Server) ListGroups(ctx context.Context, _ *identityv1.ListGroupsRequest) (*identityv1.ListGroupsResponse, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name FROM groups ORDER BY name`)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list groups: %v", err)
	}
	defer rows.Close()
	var out []*identityv1.Group
	for rows.Next() {
		g := &identityv1.Group{}
		if err := rows.Scan(&g.Id, &g.Name); err != nil {
			return nil, status.Errorf(codes.Internal, "scan group: %v", err)
		}
		out = append(out, g)
	}
	return &identityv1.ListGroupsResponse{Groups: out}, rows.Err()
}

func (s *Server) GetGroup(ctx context.Context, req *identityv1.GetGroupRequest) (*identityv1.GetGroupResponse, error) {
	g := &identityv1.Group{}
	err := s.db.QueryRow(ctx, `SELECT id, name FROM groups WHERE id=$1`, req.GetId()).Scan(&g.Id, &g.Name)
	if err != nil {
		return nil, status.Error(codes.NotFound, "group not found")
	}
	return &identityv1.GetGroupResponse{Group: g}, nil
}

// CreateGroup provisions a new directory group in lldap AND in the identity
// groups table (the mirror every reader uses; see group_sync.go for the source
// of truth), and returns it. Authorization is enforced at the gateway (admin),
// like the other mutating RPCs. A name that already exists (in identity,
// case-insensitively, or in lldap) surfaces as AlreadyExists.
//
// Order: identity pre-check, lldap create, identity insert. If the insert
// fails the lldap group is deleted again so the stores do not diverge; if that
// compensation fails too, the periodic sync reconciles (and reports) it.
func (s *Server) CreateGroup(ctx context.Context, req *identityv1.CreateGroupRequest) (*identityv1.CreateGroupResponse, error) {
	name := strings.TrimSpace(req.GetName())
	if name == "" {
		return nil, status.Error(codes.InvalidArgument, "name is required")
	}
	if isLldapBuiltinGroup(name) {
		return nil, status.Errorf(codes.InvalidArgument, "group names starting with %q are reserved for the directory", lldapBuiltinPrefix)
	}
	if s.lldap == nil && s.kratos == nil {
		return nil, status.Error(codes.Unavailable, "lldap admin not configured")
	}
	var taken bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM groups WHERE lower(name)=lower($1))`, name).Scan(&taken); err != nil {
		return nil, status.Errorf(codes.Internal, "group name check: %v", err)
	}
	if taken {
		return nil, status.Error(codes.AlreadyExists, "a group with that name already exists")
	}
	if s.lldap == nil {
		return s.createIdentityGroup(ctx, name)
	}
	g, err := s.lldap.CreateGroup(ctx, name)
	if err != nil {
		if isDuplicateErr(err) {
			return nil, status.Error(codes.AlreadyExists, "a group with that name already exists")
		}
		return nil, status.Errorf(codes.Internal, "lldap create group: %v", err)
	}
	id := strconv.Itoa(g.ID)
	// ON CONFLICT (id): lldap owns the ID, so a stale row under it (a group
	// deleted in lldap whose ID was reused) takes the new name.
	if _, err := s.db.Exec(ctx,
		`INSERT INTO groups (id, name) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
		id, g.Name); err != nil {
		if derr := s.lldap.DeleteGroup(ctx, g.ID); derr != nil {
			lg := s.lg(ctx)
			lg.Error(derr, "create group: identity insert failed and lldap rollback failed; group sync will report it", log.F("group_id", id))
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "a group with that name already exists")
		}
		return nil, status.Errorf(codes.Internal, "store group: %v", err)
	}
	return &identityv1.CreateGroupResponse{
		Group: &identityv1.Group{Id: id, Name: g.Name},
	}, nil
}

// isDuplicateErr reports whether err is lldap's uniqueness-violation error (the
// group/user name already exists). lldap's unique-violation phrasing varies by
// version, so match a few case-insensitively; the lldap client's own detector is
// unexported, so we keep this narrow copy here.
func isDuplicateErr(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	for _, sub := range []string{"uniqueness violation", "already exists", "duplicate", "unique constraint failed"} {
		if strings.Contains(msg, sub) {
			return true
		}
	}
	return false
}

// SearchUsers backs the search-as-you-type user picker: substring match on
// name/email, case-insensitive, capped and ordered for predictable UI paging.
func (s *Server) SearchUsers(ctx context.Context, req *identityv1.SearchUsersRequest) (*identityv1.SearchUsersResponse, error) {
	query := strings.TrimSpace(req.GetQuery())
	if query == "" {
		return &identityv1.SearchUsersResponse{}, nil
	}
	limit := req.GetLimit()
	if limit <= 0 {
		limit = 20
	}
	if limit > 50 {
		limit = 50
	}
	rows, err := s.db.Query(ctx,
		`SELECT `+userCols+` FROM users WHERE name ILIKE '%'||$1||'%' OR email ILIKE '%'||$1||'%' ORDER BY name LIMIT $2`,
		query, limit)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "search users: %v", err)
	}
	defer rows.Close()
	var out []*identityv1.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "scan user: %v", err)
		}
		out = append(out, u)
	}
	return &identityv1.SearchUsersResponse{Users: out}, rows.Err()
}

// ResolveUserLabels batch-resolves user ids to display labels; ids with no
// matching user are simply omitted, and the UI falls back to the raw id.
func (s *Server) ResolveUserLabels(ctx context.Context, req *identityv1.ResolveUserLabelsRequest) (*identityv1.ResolveUserLabelsResponse, error) {
	ids := req.GetIds()
	if len(ids) == 0 {
		return &identityv1.ResolveUserLabelsResponse{}, nil
	}
	rows, err := s.db.Query(ctx, `SELECT id, name FROM users WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve user labels: %v", err)
	}
	defer rows.Close()
	var out []*identityv1.UserLabel
	for rows.Next() {
		l := &identityv1.UserLabel{}
		if err := rows.Scan(&l.Id, &l.Name); err != nil {
			return nil, status.Errorf(codes.Internal, "scan user label: %v", err)
		}
		out = append(out, l)
	}
	return &identityv1.ResolveUserLabelsResponse{Labels: out}, rows.Err()
}

// createIdentityGroup is CreateGroup once identity is the only directory.
func (s *Server) createIdentityGroup(ctx context.Context, name string) (*identityv1.CreateGroupResponse, error) {
	id := "group-" + uuid.NewString()
	if _, err := s.db.Exec(ctx, `INSERT INTO groups (id, name) VALUES ($1,$2)`, id, name); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "a group with that name already exists")
		}
		return nil, status.Errorf(codes.Internal, "store group: %v", err)
	}
	return &identityv1.CreateGroupResponse{Group: &identityv1.Group{Id: id, Name: name}}, nil
}
