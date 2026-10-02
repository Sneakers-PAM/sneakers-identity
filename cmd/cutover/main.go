// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

// Command cutover moves every identity user onto Kratos in one run; see
// grpcsvc.Server.Cutover. Run it once per environment in the maintenance
// window, together with switching the gateway to AUTH_BACKEND=kratos.
package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"syscall"

	log "github.com/Bugs5382/go-log"
	postgres "github.com/Bugs5382/go-postgres"
	"github.com/Sneakers-PAM/sneakers-identity/internal/config"
	"github.com/Sneakers-PAM/sneakers-identity/internal/email"
	"github.com/Sneakers-PAM/sneakers-identity/internal/grpcsvc"
	"github.com/Sneakers-PAM/sneakers-identity/internal/kratos"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	logger := log.New("identity-cutover")
	dryRun := flag.Bool("dry-run", false, "report what would happen to each user without changing anything")
	flag.Parse()

	cfg, err := config.Load()
	if err != nil {
		logger.Fatal().Err(err).Msg("config")
	}
	adminURL := os.Getenv("KRATOS_ADMIN_URL")
	resetURL := os.Getenv("CUTOVER_RESET_URL")
	if adminURL == "" || (resetURL == "" && !*dryRun) {
		logger.Fatal().Msg("KRATOS_ADMIN_URL and CUTOVER_RESET_URL are required")
	}
	if os.Getenv("SMTP_HOST") == "" && !*dryRun {
		logger.Fatal().Msg("SMTP_HOST is required: users are emailed how to set their new password")
	}

	db, err := postgres.New(ctx, cfg.DatabaseDSN)
	if err != nil {
		logger.Fatal().Err(err).Msg("db connect")
	}
	defer db.Close()

	srv := grpcsvc.New(db).WithLogger(log.NewLogger("identity-cutover"))
	if *dryRun {
		plan, err := srv.PlanCutover(ctx, kratos.NewAdmin(adminURL))
		for _, o := range plan.Outcomes {
			logger.Info().Str("user_id", o.UserID).Str("email", o.Email).Str("action", o.Action).Str("kratos_id", o.KratosID).Msg("cutover plan")
		}
		for _, f := range plan.Failures {
			logger.Error().Err(f.Err).Str("user_id", f.UserID).Msg("cutover plan: lookup failed")
		}
		if err != nil {
			logger.Fatal().Err(err).Msg("cutover plan failed")
		}
		logger.Info().Int("users", plan.Users).Int("failed", len(plan.Failures)).Msg("cutover plan finished (dry run, nothing changed)")
		return
	}
	rep, err := srv.Cutover(ctx, kratos.NewAdmin(adminURL), email.New(email.LoadConfig()), resetURL)
	for _, f := range rep.Failures {
		logger.Error().Err(f.Err).Str("user_id", f.UserID).Msg("cutover: user not migrated")
	}
	logger.Info().Int("users", rep.Users).Int("emailed", rep.Emailed).Int("failed", len(rep.Failures)).Msg("cutover finished")
	if err != nil {
		logger.Fatal().Err(err).Msg("cutover halted")
	}
	if len(rep.Failures) > 0 {
		os.Exit(1)
	}
}
