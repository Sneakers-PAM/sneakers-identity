// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command seed populates the identity database with the dev demo directory
// (users, groups, memberships) using go-seed: idempotent upserts, each proven
// by a row-count assertion. It is a DEV/QA-ONLY tool — it must never run against
// prod, where users arrive via federation. Run it out-of-band (local task or a
// dev/qa-gated Job), NOT from the service on boot.
//
// Requires DATABASE_DSN (same as the service). Re-running is safe.
package main

import (
	"context"
	"fmt"
	"os"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	seed "github.com/Bugs5382/go-seed"
	"github.com/Sneakers-PAM/sneakers-identity/internal/lldap"
	"github.com/jackc/pgx/v5/pgxpool"
)

// devPassword is the shared login password the seed sets for every demo user in
// lldap. Kept in step with the web UI's dev login hint. DEV/QA only — never
// used in prod (federation).
const devPassword = "dev123"

// getOr returns the env var value or a default when unset/empty.
func getOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// rowStep is a pgx-backed analogue of go-seed's SQL RowSpec (whose Executor is
// database/sql only): an idempotent Apply plus an Assert that the expected rows
// landed. Keeps the app's proven pgx array handling for the roles text[] column.
func rowStep(name, apply string, applyArgs []any, count string, countArgs []any, want int) seed.Step[*pgxpool.Pool] {
	if want < 1 {
		want = 1
	}
	return seed.Step[*pgxpool.Pool]{
		Name: name,
		Apply: func(ctx context.Context, db *pgxpool.Pool) error {
			_, err := db.Exec(ctx, apply, applyArgs...)
			return err
		},
		Assert: func(ctx context.Context, db *pgxpool.Pool) error {
			var n int
			if err := db.QueryRow(ctx, count, countArgs...).Scan(&n); err != nil {
				return err
			}
			if n < want {
				return fmt.Errorf("expected at least %d row(s), found %d", want, n)
			}
			return nil
		},
	}
}

func main() {
	ctx := context.Background()
	logger := log.New("identity-seed")

	dsn := os.Getenv("DATABASE_DSN")
	if dsn == "" {
		logger.Fatal().Msg("DATABASE_DSN is required")
	}
	db, err := postgres.New(ctx, dsn)
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()
	pool := db.Pool()

	// Root = Alan Turing (site-admin); the rest are computing/crypto pioneers.
	// Kept in step with the web UI's mock seed.
	// username = the stable login handle (matches the lldap uid / Keycloak
	// preferred_username); it is the primary key a federated login adopts on.
	users := []struct {
		id, name, email, username string
		roles                     []string
		root                      bool
	}{
		{"user-turing", "Alan Turing", "alan.turing@example.org", "alan.turing", []string{"site-admin"}, true},
		{"user-clarke", "Joan Clarke", "joan.clarke@example.org", "joan.clarke", []string{"user"}, false},
		{"user-jobs", "Steve Jobs", "steve.jobs@example.org", "steve.jobs", []string{"user"}, false},
		{"user-lovelace", "Ada Lovelace", "ada.lovelace@example.org", "ada.lovelace", []string{"user"}, false},
		{"user-hopper", "Grace Hopper", "grace.hopper@example.org", "grace.hopper", []string{"user"}, false},
	}
	groups := [][2]string{
		{"group-platform", "Platform Team"},
		{"group-security", "Security"},
		{"group-oncall", "On-Call"},
		{"group-infra", "Infrastructure"},
		{"group-helpdesk", "Help Desk"},
	}
	memberships := [][2]string{
		{"user-turing", "group-platform"},
		{"user-clarke", "group-platform"},
		{"user-turing", "group-security"},
		{"user-hopper", "group-security"},
		{"user-jobs", "group-oncall"},
		{"user-lovelace", "group-infra"},
		{"user-hopper", "group-infra"},
	}

	runner := seed.New(pool)
	for _, u := range users {
		runner.Add(rowStep(
			"user:"+u.id,
			`INSERT INTO users (id, name, email, roles, is_root, username) VALUES ($1,$2,$3,$4,$5,$6)
			 ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name, email=EXCLUDED.email, roles=EXCLUDED.roles, is_root=EXCLUDED.is_root, username=EXCLUDED.username`,
			[]any{u.id, u.name, u.email, u.roles, u.root, u.username},
			`SELECT count(*) FROM users WHERE id=$1`, []any{u.id}, 1,
		))
	}
	for _, g := range groups {
		runner.Add(rowStep(
			"group:"+g[0],
			`INSERT INTO groups (id, name) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET name=EXCLUDED.name`,
			[]any{g[0], g[1]},
			`SELECT count(*) FROM groups WHERE id=$1`, []any{g[0]}, 1,
		))
	}
	for _, m := range memberships {
		runner.Add(rowStep(
			"membership:"+m[0]+"@"+m[1],
			`INSERT INTO group_membership (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING`,
			[]any{m[0], m[1]},
			`SELECT count(*) FROM group_membership WHERE user_id=$1 AND group_id=$2`, []any{m[0], m[1]}, 1,
		))
	}

	if err := runner.Run(ctx); err != nil {
		logger.Fatal().Err(err).Msg("seed")
	}
	logger.Info().Int("users", len(users)).Int("groups", len(groups)).Int("memberships", len(memberships)).Msg("identity seed complete")

	// The rows above are the identity directory (roles/groups). Authentication,
	// though, validates the password against lldap (the credential store Keycloak
	// federates to READ_ONLY). /setup provisions lldap in qa/prod, but dev
	// auto-seeds and never runs /setup, so the demo users would exist in the DB
	// yet be unable to log in. Mirror /setup's lldap.CreateUser + SetPassword
	// here so every demo user can authenticate with devPassword. Idempotent:
	// CreateUser is create-or-exists and SetPassword (re)sets. DEV/QA only.
	url := os.Getenv("LLDAP_URL")
	if url == "" {
		logger.Warn().Msg("LLDAP_URL unset — skipping lldap demo-user provisioning; logins will fail until users exist in lldap")
		return
	}
	ldapClient := lldap.New(lldap.Config{
		AdminURL:  url,
		LDAPURL:   getOr("LLDAP_LDAP_URL", "ldap://sneakers-lldap:3890"),
		BaseDN:    getOr("LLDAP_BASE_DN", "dc=sneakers,dc=local"),
		AdminUser: getOr("LLDAP_ADMIN_USERNAME", "admin"),
		AdminPass: os.Getenv("LLDAP_ADMIN_PASSWORD"),
	})
	for _, u := range users {
		if err := ldapClient.CreateUser(ctx, u.username, u.email, u.name); err != nil {
			logger.Fatal().Err(err).Str("user", u.username).Msg("lldap create user")
		}
		if err := ldapClient.SetPassword(ctx, u.username, devPassword); err != nil {
			logger.Fatal().Err(err).Str("user", u.username).Msg("lldap set password")
		}
	}
	logger.Info().Int("lldap_users", len(users)).Msg("lldap demo users provisioned")
}
