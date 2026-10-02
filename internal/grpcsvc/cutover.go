// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"errors"
	"fmt"
	"slices"

	log "github.com/Bugs5382/go-log"
	"github.com/Sneakers-PAM/sneakers-identity/internal/email"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
)

type kratosDirectory interface {
	CreateIdentity(ctx context.Context, email, name string) (string, error)
	FindIdentityByEmail(ctx context.Context, email string) (string, error)
}

type CutoverFailure struct {
	UserID string
	Err    error
}

// CutoverOutcome is what happened (or, in a plan, would happen) to one user.
// Action is "created" or "existing", or "would create"/"would reuse" in a plan.
type CutoverOutcome struct {
	UserID   string
	Email    string
	KratosID string
	Action   string
	Emailed  bool
}

type CutoverReport struct {
	Users    int
	Emailed  int
	Failures []CutoverFailure
	Outcomes []CutoverOutcome
}

type cutoverUser struct {
	id, name, email string
	privileged      bool
	disabled        bool
}

// Cutover moves every user onto Kratos: an identity without credentials, the
// user row re-keyed to it (so the first Kratos login adopts the existing user
// instead of provisioning a duplicate), and a recovery code emailed so the
// user sets their own password. Privileged users go first and any failure
// among them halts before a regular user is touched, so the environment is
// never left without a working administrator. Safe to re-run.
func (s *Server) Cutover(ctx context.Context, dir kratosDirectory, mail email.Sender, resetURL string) (CutoverReport, error) {
	users, err := s.cutoverUsers(ctx)
	if err != nil {
		return CutoverReport{}, err
	}
	rep := CutoverReport{Users: len(users)}
	lg := log.Ctx(ctx)
	for _, u := range users {
		outcome, err := s.cutoverOne(ctx, dir, mail, resetURL, u)
		if err == nil {
			rep.Outcomes = append(rep.Outcomes, outcome)
			if outcome.Emailed {
				rep.Emailed++
			}
			lg.Info().Str("user_id", u.id).Str("kratos_id", outcome.KratosID).Str("action", outcome.Action).Bool("emailed", outcome.Emailed).Msg("cutover: user migrated")
			continue
		}
		if u.privileged {
			return rep, fmt.Errorf("cutover halted: privileged user %s: %w", u.id, err)
		}
		lg.Warn().Err(err).Str("user_id", u.id).Msg("cutover: user failed")
		rep.Failures = append(rep.Failures, CutoverFailure{UserID: u.id, Err: err})
	}
	return rep, nil
}

func (s *Server) cutoverUsers(ctx context.Context) ([]cutoverUser, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name, email, roles, is_root, disabled_at IS NOT NULL FROM users`)
	if err != nil {
		return nil, fmt.Errorf("cutover: list users: %w", err)
	}
	defer rows.Close()
	var out []cutoverUser
	for rows.Next() {
		var (
			u     cutoverUser
			roles []string
			root  bool
		)
		if err := rows.Scan(&u.id, &u.name, &u.email, &roles, &root, &u.disabled); err != nil {
			return nil, fmt.Errorf("cutover: scan user: %w", err)
		}
		u.privileged = root || slices.Contains(roles, "site-admin") || slices.Contains(roles, "admin")
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cutover: list users: %w", err)
	}
	slices.SortStableFunc(out, func(a, b cutoverUser) int {
		switch {
		case a.privileged == b.privileged:
			return 0
		case a.privileged:
			return -1
		default:
			return 1
		}
	})
	return out, nil
}

func (s *Server) cutoverOne(ctx context.Context, dir kratosDirectory, mail email.Sender, resetURL string, u cutoverUser) (CutoverOutcome, error) {
	out := CutoverOutcome{UserID: u.id, Email: u.email}
	if u.email == "" {
		return out, errors.New("user has no email address")
	}
	kid, err := dir.FindIdentityByEmail(ctx, u.email)
	out.Action = "existing"
	if errors.Is(err, kratos.ErrNotFound) {
		kid, err = dir.CreateIdentity(ctx, u.email, u.name)
		out.Action = "created"
	}
	if err != nil {
		return out, fmt.Errorf("kratos identity: %w", err)
	}
	out.KratosID = kid
	if _, err := s.db.Exec(ctx, `UPDATE users SET keycloak_subject=$2 WHERE id=$1`, u.id, kid); err != nil {
		return out, fmt.Errorf("re-key: %w", err)
	}
	if u.disabled {
		return out, nil
	}
	body := fmt.Sprintf("Sneakers sign-in has moved to a new system, so you need to set a new password once.\n\n"+
		"Open %s, choose \"Forgot password\" and enter your email (%s). We will email you a one-time code; "+
		"enter it with your new password. Your MFA settings are unchanged.", resetURL, u.email)
	if err := mail.Send(u.email, "Set your new Sneakers password", body); err != nil {
		return out, fmt.Errorf("send email: %w", err)
	}
	out.Emailed = true
	return out, nil
}

// PlanCutover reports what Cutover would do for each user without creating
// identities, re-keying rows or sending mail.
func (s *Server) PlanCutover(ctx context.Context, dir kratosDirectory) (CutoverReport, error) {
	users, err := s.cutoverUsers(ctx)
	if err != nil {
		return CutoverReport{}, err
	}
	rep := CutoverReport{Users: len(users)}
	for _, u := range users {
		out := CutoverOutcome{UserID: u.id, Email: u.email, Action: "would create"}
		if kid, err := dir.FindIdentityByEmail(ctx, u.email); err == nil {
			out.Action, out.KratosID = "would reuse", kid
		} else if !errors.Is(err, kratos.ErrNotFound) {
			rep.Failures = append(rep.Failures, CutoverFailure{UserID: u.id, Err: err})
			continue
		}
		rep.Outcomes = append(rep.Outcomes, out)
	}
	return rep, nil
}
