// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"

	postgres "github.com/Bugs5382/go-postgres"
	otelpg "github.com/Bugs5382/go-postgres/otel"
	"github.com/Sneakers-PAM/sneakers-identity/internal/server"
)

// openPostgres runs the migrations and connects the pool, waiting with
// backoff while PostgreSQL (or its DNS name) isn't reachable yet, so a boot
// that comes up first never exits for it. Each failed attempt is logged and
// shown in the boot health report. A non-transient error (bad credentials, a
// failing migration) and ctx ending are returned.
func openPostgres(ctx context.Context, boot *server.BootHealth, migrateDSN, migrationsDir, dsn string, wait ...postgres.WaitOption) (*postgres.DB, error) {
	wait = append([]postgres.WaitOption{postgres.WithRetryHook(boot.RetryHook("postgres"))}, wait...)
	if err := postgres.WaitFor(ctx, func(context.Context) error {
		return postgres.Migrate(migrateDSN, migrationsDir)
	}, wait...); err != nil {
		return nil, err
	}
	var db *postgres.DB
	if err := postgres.WaitFor(ctx, func(ctx context.Context) error {
		var err error
		db, err = postgres.New(ctx, dsn, otelpg.WithTracing())
		return err
	}, wait...); err != nil {
		return nil, err
	}
	boot.Up("postgres")
	return db, nil
}
