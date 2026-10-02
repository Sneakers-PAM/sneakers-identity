// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"net/mail"
	"strings"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	identityv1 "github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1"
	"github.com/Sneakers-PAM/sneakers-identity/internal/audit"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// getUserByID and getUserBySubject are internal helpers that reuse the canonical
// userCols projection (see identity.go).

func (s *Server) getUserByID(ctx context.Context, id string) (*identityv1.User, error) {
	return scanUser(s.db.QueryRow(ctx, `SELECT `+userCols+` FROM users WHERE id=$1`, id))
}

func (s *Server) getUserBySubject(ctx context.Context, sub string) (*identityv1.User, error) {
	return scanUser(s.db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE subject=$1`, sub))
}

// getUserByEmail resolves a user by case-insensitive exact email match. Mirrors
// resetUserByEmail's `lower(email)=lower($1) ORDER BY id LIMIT 1` normalization
// (reset.go) so every email-keyed lookup in the service agrees on which row wins
// if duplicates ever slip past the column's uniqueness. postgres.ErrNoRows on a miss —
// callers translate that to codes.NotFound (or, for the JIT adopt path, fall
// through to provisioning).
func (s *Server) getUserByEmail(ctx context.Context, email string) (*identityv1.User, error) {
	return scanUser(s.db.QueryRow(ctx,
		`SELECT `+userCols+` FROM users WHERE lower(email)=lower($1) ORDER BY id LIMIT 1`, email))
}

// --- Provisioning for real logins ---

// PreCreateLocalUser inserts a local account with subject=” (defaulted by the
// column) so a later login can adopt it by email match.
func (s *Server) PreCreateLocalUser(ctx context.Context, req *identityv1.PreCreateLocalUserRequest) (*identityv1.PreCreateLocalUserResponse, error) {
	email := strings.TrimSpace(req.GetEmail())
	if email == "" {
		return nil, status.Error(codes.InvalidArgument, "email is required")
	}
	roles := req.GetRoles()
	if roles == nil {
		roles = []string{}
	}
	id := "user-" + uuid.NewString()
	if _, err := s.db.Exec(ctx,
		`INSERT INTO users (id, name, email, roles, subject) VALUES ($1,$2,$3,$4,'')`,
		id, req.GetName(), email, roles); err != nil {
		return nil, status.Errorf(codes.Internal, "pre-create local user: %v", err)
	}
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load created user: %v", err)
	}
	s.record(ctx, audit.Event{
		Action: audit.ActionUserCreate, ActorUserID: actorOr(req.GetActingUserId(), ""), Subject: id,
		Attributes: map[string]string{"source": "precreate", "roles": joinSorted(roles)},
	})
	return &identityv1.PreCreateLocalUserResponse{User: u}, nil
}

// CreateLocalUser fully provisions a loginable local account: it creates the
// Kratos identity + sets the supplied password, then persists the local identity
// row with the Kratos identity id as its subject.
// Roles are left empty — a new user is an implicit reader; roles are assigned via
// the separate role flow. Authorization is enforced at the
// gateway (user.manage), like the other mutating RPCs.
func (s *Server) CreateLocalUser(ctx context.Context, req *identityv1.CreateLocalUserRequest) (*identityv1.CreateLocalUserResponse, error) {
	in, err := validateCreateLocalUser(req)
	if err != nil {
		return nil, err
	}
	if s.kratos == nil {
		return nil, status.Error(codes.Unavailable, "no user directory configured")
	}

	// Uniqueness pre-check against the identity DB before any directory side-effect,
	// so a conflict fails cleanly without leaving an orphaned directory user.
	var exists bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM users WHERE username=$1 OR lower(email)=lower($2))`,
		in.username, in.email).Scan(&exists); err != nil {
		return nil, status.Errorf(codes.Internal, "uniqueness check: %v", err)
	}
	if exists {
		return nil, status.Error(codes.AlreadyExists, "a user with that username or email already exists")
	}

	subject, rollback, err := s.provisionDirectoryUser(ctx, in.email, in.name, in.password)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "%v", err)
	}

	id := "user-" + uuid.NewString()
	if _, err := s.db.Exec(ctx,
		`INSERT INTO users (id, name, email, roles, subject, username) VALUES ($1,$2,$3,$4,$5,$6)`,
		id, in.name, in.email, []string{}, subject, in.username); err != nil {
		rollback()
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return nil, status.Error(codes.AlreadyExists, "a user with that username or email already exists")
		}
		return nil, status.Errorf(codes.Internal, "create local user row: %v", err)
	}

	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load created user: %v", err)
	}
	s.record(ctx, audit.Event{
		Action: audit.ActionUserCreate, ActorUserID: actorOr(req.GetActingUserId(), ""), Subject: id,
		Attributes: map[string]string{"source": "local", "username": in.username},
	})
	// Email the new account a verification code (username + email in the body)
	// so a misspelling is caught. Best-effort: never fail the create on a send error.
	if verr := s.sendVerificationEmail(ctx, id); verr != nil {
		lg := s.lg(ctx)
		lg.Warn("create local user: verification email not sent", log.F("error", verr.Error()), log.F("user_id", id))
	}
	return &identityv1.CreateLocalUserResponse{User: u}, nil
}

// createLocalUserInput holds the trimmed, validated inputs for CreateLocalUser.
type createLocalUserInput struct {
	username string
	email    string
	name     string
	password string
}

// validateCreateLocalUser trims and validates the request, keeping the branchy
// input checks out of CreateLocalUser (gocyclo). name defaults to username.
func validateCreateLocalUser(req *identityv1.CreateLocalUserRequest) (createLocalUserInput, error) {
	in := createLocalUserInput{
		username: strings.TrimSpace(req.GetUsername()),
		email:    strings.TrimSpace(req.GetEmail()),
		name:     strings.TrimSpace(req.GetName()),
		password: req.GetPassword(),
	}
	switch {
	case in.username == "":
		return in, status.Error(codes.InvalidArgument, "username is required")
	case strings.Contains(in.username, "@"):
		return in, status.Error(codes.InvalidArgument, "username must not be an email address")
	case in.email == "":
		return in, status.Error(codes.InvalidArgument, "email is required")
	case in.password == "":
		return in, status.Error(codes.InvalidArgument, "password is required")
	}
	if _, err := mail.ParseAddress(in.email); err != nil {
		return in, status.Error(codes.InvalidArgument, "email is not a valid address")
	}
	if in.name == "" {
		in.name = in.username
	}
	return in, nil
}

// SetUserRoles replaces a user's role set (grant/revoke e.g. the "admin" role).
// Authorization is enforced at the gateway (admin). root's admin authority is
// is_root-derived, so it is unaffected by the role set here.
func (s *Server) SetUserRoles(ctx context.Context, req *identityv1.SetUserRolesRequest) (*identityv1.SetUserRolesResponse, error) {
	id := strings.TrimSpace(req.GetUserId())
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id is required")
	}
	roles := req.GetRoles()
	if roles == nil {
		roles = []string{}
	}
	// The old set comes back from the same statement, so the recorded change
	// is exactly the one this call made.
	var before []string
	err := s.db.QueryRow(ctx,
		`UPDATE users u SET roles=$2
		   FROM (SELECT id, roles FROM users WHERE id=$1 FOR UPDATE) old
		  WHERE u.id = old.id
		 RETURNING old.roles`, id, roles).Scan(&before)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "set user roles: %v", err)
	}
	u, err := s.getUserByID(ctx, id)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load user: %v", err)
	}
	added, removed := roleDiff(before, roles)
	s.record(ctx, audit.Event{
		Action: audit.ActionUserRolesSet, ActorUserID: actorOr(req.GetActingUserId(), ""), Subject: id,
		Attributes: map[string]string{"roles": joinSorted(roles), "added": joinSorted(added), "removed": joinSorted(removed)},
	})
	return &identityv1.SetUserRolesResponse{User: u}, nil
}

// AdoptOrProvisionFederatedUser is the login path. In order:
//  1. resolve an already-adopted row by subject;
//  2. adopt a pre-created local row (subject=”) by USERNAME first, then
//     email, stamping the subject onto it;
//  3. provision a fresh user (default role "user").
//
// Username is the primary adoption key: it is the stable login handle, unlike
// email which can change or be shared. Email remains a fallback so pre-created
// rows keyed only by email still adopt.
//
// The provision insert uses ON CONFLICT on the partial subject index so
// a concurrent login racing the same subject converges on one row.
func (s *Server) AdoptOrProvisionFederatedUser(ctx context.Context, req *identityv1.AdoptOrProvisionFederatedUserRequest) (*identityv1.AdoptOrProvisionFederatedUserResponse, error) {
	sub := strings.TrimSpace(req.GetSubject())
	if sub == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	email := strings.TrimSpace(req.GetEmail())
	username := strings.TrimSpace(req.GetUsername())
	name := req.GetName()

	// 1. Already adopted.
	if u, err := s.getUserBySubject(ctx, sub); err == nil {
		s.recordSignIn(ctx, u.GetId(), "existing")
		return &identityv1.AdoptOrProvisionFederatedUserResponse{User: u}, nil
	} else if !errors.Is(err, postgres.ErrNoRows) {
		return nil, status.Errorf(codes.Internal, "lookup by subject: %v", err)
	}

	// 2. Adopt a pre-created local row (one row, deterministically) by USERNAME
	// first, then email. Only unclaimed rows (subject='') are adoptable.
	if username != "" || email != "" {
		var id string
		// Only stamp the subject; the pre-created row's username stays authoritative
		// (a match by email must not overwrite the seeded username, and the token's
		// username may legitimately differ). Username-match is preferred over email.
		err := s.db.QueryRow(ctx,
			`UPDATE users SET subject=$1
			 WHERE id = (SELECT id FROM users
			              WHERE subject=''
			                AND ( ($3 <> '' AND username=$3)
			                   OR ($2 <> '' AND lower(email)=lower($2)) )
			              ORDER BY (username=$3) DESC, id
			              LIMIT 1)
			 RETURNING id`, sub, email, username).Scan(&id)
		switch {
		case err == nil:
			u, gerr := s.getUserByID(ctx, id)
			if gerr != nil {
				return nil, status.Errorf(codes.Internal, "load adopted user: %v", gerr)
			}
			s.recordSignIn(ctx, id, "adopted")
			return &identityv1.AdoptOrProvisionFederatedUserResponse{User: u}, nil
		case errors.Is(err, postgres.ErrNoRows):
			// no adoptable row — fall through to provision
		default:
			return nil, status.Errorf(codes.Internal, "adopt by username/email: %v", err)
		}
	}

	// 3. Provision a fresh federated user.
	id := "user-" + uuid.NewString()
	var newID string
	err := s.db.QueryRow(ctx,
		`INSERT INTO users (id, name, email, roles, subject, username)
		 VALUES ($1,$2,$3,$4,$5,$6)
		 ON CONFLICT (subject) WHERE subject <> ''
		 DO UPDATE SET email=EXCLUDED.email, name=EXCLUDED.name, username=EXCLUDED.username
		 RETURNING id`,
		id, name, email, []string{"user"}, sub, username).Scan(&newID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "provision federated user: %v", err)
	}
	u, err := s.getUserByID(ctx, newID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "load provisioned user: %v", err)
	}
	if newID == id {
		s.record(ctx, audit.Event{
			Action: audit.ActionUserCreate, ActorUserID: newID, Subject: newID,
			Attributes: map[string]string{"source": "signin", "username": username},
		})
		s.recordSignIn(ctx, newID, "provisioned")
	} else {
		s.recordSignIn(ctx, newID, "existing")
	}
	return &identityv1.AdoptOrProvisionFederatedUserResponse{User: u}, nil
}

// recordSignIn records a completed first sign-in step: the gateway calls
// AdoptOrProvisionFederatedUser once Kratos has accepted the password. A
// rejected password never reaches identity, so the gateway records that one.
func (s *Server) recordSignIn(ctx context.Context, userID, result string) {
	s.record(ctx, audit.Event{
		Action: audit.ActionSignIn, ActorUserID: userID, Subject: userID,
		Attributes: map[string]string{"step": "password", "result": result, "outcome": audit.OutcomeOK},
	})
}

// GetUserBySubject fetches a user by login subject; NotFound when unmapped.
func (s *Server) GetUserBySubject(ctx context.Context, req *identityv1.GetUserBySubjectRequest) (*identityv1.GetUserBySubjectResponse, error) {
	sub := strings.TrimSpace(req.GetSubject())
	if sub == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	u, err := s.getUserBySubject(ctx, sub)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "get user by subject: %v", err)
	}
	return &identityv1.GetUserBySubjectResponse{User: u}, nil
}

// --- Group membership (identity is the source of truth) ---

// AddGroupMember creates a membership row (idempotent). Guards user/group
// existence so a foreign-key error doesn't shadow NotFound.
func (s *Server) AddGroupMember(ctx context.Context, req *identityv1.AddGroupMemberRequest) (*identityv1.AddGroupMemberResponse, error) {
	userID, groupID := req.GetUserId(), req.GetGroupId()
	if userID == "" || groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and group_id are required")
	}
	if err := s.requireExists(ctx, `users`, userID, "user_id"); err != nil {
		return nil, err
	}
	if err := s.requireExists(ctx, `groups`, groupID, "group_id"); err != nil {
		return nil, err
	}
	tag, err := s.db.Exec(ctx,
		`INSERT INTO group_membership (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
		userID, groupID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "add group member: %v", err)
	}
	if tag.RowsAffected() > 0 {
		s.record(ctx, audit.Event{
			Action: audit.ActionGroupMemberAdd, ActorUserID: actorOr(req.GetActingUserId(), ""), Subject: userID, GroupID: groupID,
			Attributes: map[string]string{"user_id": userID, "group_id": groupID},
		})
	}
	return &identityv1.AddGroupMemberResponse{UserId: userID, GroupId: groupID}, nil
}

// RemoveGroupMember deletes a membership row (idempotent).
func (s *Server) RemoveGroupMember(ctx context.Context, req *identityv1.RemoveGroupMemberRequest) (*identityv1.RemoveGroupMemberResponse, error) {
	userID, groupID := req.GetUserId(), req.GetGroupId()
	if userID == "" || groupID == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id and group_id are required")
	}
	tag, err := s.db.Exec(ctx,
		`DELETE FROM group_membership WHERE user_id=$1 AND group_id=$2`, userID, groupID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "remove group member: %v", err)
	}
	if tag.RowsAffected() > 0 {
		s.record(ctx, audit.Event{
			Action: audit.ActionGroupMemberRemove, ActorUserID: actorOr(req.GetActingUserId(), ""), Subject: userID, GroupID: groupID,
			Attributes: map[string]string{"user_id": userID, "group_id": groupID},
		})
	}
	return &identityv1.RemoveGroupMemberResponse{UserId: userID, GroupId: groupID}, nil
}

// ListGroupMembers enumerates the users in a group.
func (s *Server) ListGroupMembers(ctx context.Context, req *identityv1.ListGroupMembersRequest) (*identityv1.ListGroupMembersResponse, error) {
	rows, err := s.db.Query(ctx,
		`SELECT `+prefixCols("u")+`
		 FROM users u JOIN group_membership m ON m.user_id = u.id
		 WHERE m.group_id = $1 ORDER BY u.name`, req.GetGroupId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list group members: %v", err)
	}
	defer rows.Close()
	users, err := scanUsers(rows)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "scan group members: %v", err)
	}
	return &identityv1.ListGroupMembersResponse{Users: users}, rows.Err()
}

// ListUserGroups enumerates the directory groups a user is a direct member of.
func (s *Server) ListUserGroups(ctx context.Context, req *identityv1.ListUserGroupsRequest) (*identityv1.ListUserGroupsResponse, error) {
	rows, err := s.db.Query(ctx,
		`SELECT g.id, g.name FROM groups g
		 JOIN group_membership m ON m.group_id = g.id
		 WHERE m.user_id = $1 ORDER BY g.name`, req.GetUserId())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list user groups: %v", err)
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
	return &identityv1.ListUserGroupsResponse{Groups: out}, rows.Err()
}

// --- AD groups: RETIRED ---
//
// Group membership is managed ONLY in the Sneakers admin UI (group_membership);
// groups are never derived from federation/SAML/OIDC claims. The AD-claim sync
// path was never wired to a caller and its user_ad_groups table no longer
// exists. The RPCs stay in the contract (deprecated) until the next major.

// SetUserAdGroups is retired: there is no claim-derived group sync.
//
//nolint:staticcheck // SA1019: implements a deprecated RPC until the next contract major.
func (s *Server) SetUserAdGroups(context.Context, *identityv1.SetUserAdGroupsRequest) (*identityv1.SetUserAdGroupsResponse, error) {
	return nil, status.Error(codes.Unimplemented,
		"SetUserAdGroups is retired: group membership is managed only in the Sneakers admin UI")
}

// ListUsersByAdGroups is deprecated and always empty: AD groups no longer exist.
//
//nolint:staticcheck // SA1019: implements a deprecated RPC until the next contract major.
func (s *Server) ListUsersByAdGroups(context.Context, *identityv1.ListUsersByAdGroupsRequest) (*identityv1.ListUsersByAdGroupsResponse, error) {
	return &identityv1.ListUsersByAdGroupsResponse{}, nil
}

// UserAdGroups is deprecated and always empty: AD groups no longer exist. It
// still answers (rather than Unimplemented) because the gateway's userAdGroups
// field and the admin user page still call it.
//
//nolint:staticcheck // SA1019: implements a deprecated RPC until the next contract major.
func (s *Server) UserAdGroups(context.Context, *identityv1.UserAdGroupsRequest) (*identityv1.UserAdGroupsResponse, error) {
	return &identityv1.UserAdGroupsResponse{}, nil
}

// ResolveUserContext returns the user plus effective group names (the names of
// the directory groups in the user's group_membership, managed in the Sneakers
// admin UI) and roles, keyed by login subject. This is the projection the
// gateway consumes to build the request ActorContext. Nothing is derived from
// federation claims.
func (s *Server) ResolveUserContext(ctx context.Context, req *identityv1.ResolveUserContextRequest) (*identityv1.ResolveUserContextResponse, error) {
	sub := strings.TrimSpace(req.GetSubject())
	if sub == "" {
		return nil, status.Error(codes.InvalidArgument, "subject is required")
	}
	u, err := s.getUserBySubject(ctx, sub)
	if err != nil {
		if errors.Is(err, postgres.ErrNoRows) {
			return nil, status.Error(codes.NotFound, "user not found")
		}
		return nil, status.Errorf(codes.Internal, "resolve user: %v", err)
	}
	groupNames, err := s.userGroupNames(ctx, u.GetId())
	if err != nil {
		return nil, err
	}
	return &identityv1.ResolveUserContextResponse{
		User:       u,
		GroupNames: groupNames,
		Roles:      u.GetRoles(),
	}, nil
}

// --- helpers ---

func (s *Server) userGroupNames(ctx context.Context, userID string) ([]string, error) {
	rows, err := s.db.Query(ctx, `
		SELECT g.name FROM groups g
		  JOIN group_membership m ON m.group_id = g.id
		 WHERE m.user_id = $1
		 ORDER BY g.name`, userID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "resolve group names: %v", err)
	}
	defer rows.Close()
	var groupNames []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return nil, status.Errorf(codes.Internal, "scan group name: %v", err)
		}
		groupNames = append(groupNames, n)
	}
	if err := rows.Err(); err != nil {
		return nil, status.Errorf(codes.Internal, "group names: %v", err)
	}
	return groupNames, nil
}

// prefixCols returns userCols with each column prefixed by the given table
// alias, for use in JOIN queries.
func prefixCols(alias string) string {
	cols := strings.Split(userCols, ", ")
	for i, c := range cols {
		cols[i] = alias + "." + c
	}
	return strings.Join(cols, ", ")
}

// scanUsers drains a rows cursor selected with userCols (optionally aliased).
func scanUsers(rows postgres.Rows) ([]*identityv1.User, error) {
	var out []*identityv1.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// requireExists returns NotFound (tagged with field) when no row with the given
// id exists in table. table is a trusted internal literal, never user input.
func (s *Server) requireExists(ctx context.Context, table, id, field string) error {
	var ok bool
	if err := s.db.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM `+table+` WHERE id=$1)`, id).Scan(&ok); err != nil {
		return status.Errorf(codes.Internal, "%s check: %v", field, err)
	}
	if !ok {
		return status.Errorf(codes.NotFound, "%s not found", field)
	}
	return nil
}

// provisionDirectoryUser creates the credential-holding Kratos identity; its id
// is the row's subject. rollback undoes the directory write.
func (s *Server) provisionDirectoryUser(ctx context.Context, email, name, password string) (subject string, rollback func(), err error) {
	id, err := s.provisionKratos(ctx, email, name, password)
	if err != nil {
		return "", nil, err
	}
	return id, func() { _ = s.kratos.DeleteIdentity(ctx, id) }, nil
}
