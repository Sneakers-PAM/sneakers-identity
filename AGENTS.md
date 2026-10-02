# AGENTS.md - sneakers-identity

Guide for AI agents working in this repository. Pair with `CLAUDE.md` (the working agreement and
hook-enforced rules). Keep this file current when the build, layout, or public API changes.

## What this is

Sneakers identity service: the directory of record. A gRPC service
(`sneakers.identity.v1.IdentityService`) over Postgres that holds users, groups, memberships,
second factors, service accounts and tokens. Before changing it, know that every verify path
(TOTP, email codes, API and personal tokens, OIDC links) fails closed and answers alike for every
failure, so a caller can't tell why; keep it that way. Passwords never live here: Ory Kratos
holds them.

## Layout

- `cmd/identity/` - the service entrypoint: config, migrations, optional features, the gRPC server.
- `cmd/seed/` - dev demo data.
- `internal/grpcsvc/` - the service, its Postgres queries and the tests (`*_pg_test.go` need
  Postgres).
- `internal/kratos/` - the Ory Kratos admin client; `internal/email/` - the SMTP
  sender; `internal/secrets/` - the at-rest cipher for TOTP secrets.
- `internal/config/`, `internal/server/` - the env loader and the gRPC server bootstrap.
- `proto/` - the API; `gen/go/` - the generated Go (committed, checked current in CI).
- `migrations/` - the Postgres schema, forward only.
- `test/kratos/` - the Kratos config the integration tests run against.
- `docs/` - configuration, API and runbook.

## Build, test, lint

- Build: `task build`
- Test: `task test`; set `IDENTITY_PG_DSN` (Postgres) and `KRATOS_TEST_ADMIN_URL` /
  `KRATOS_TEST_PUBLIC_URL` (a Kratos started from `test/kratos`) to run the integration tests
  (see README.md), otherwise they are skipped.
- Lint: `task lint`, plus `buf lint` for the proto.
- Generated code: `buf generate` with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`.
- License headers: `task license` (golic, the Apache-2.0 SPDX header in `.golic.yaml`).

## Logging

Follow the logging rules in `CLAUDE.md`. In short:

- Log generously: entry and exit of significant operations, decisions and branches, retries, state
  changes, external calls (target, duration, outcome), and every error with its context.
- Levels: `trace` for step-by-step detail, `debug` for flow, `info` for lifecycle, `warn` and
  `error` for problems. The environment filters the volume, so err on the side of too much.
- Environments: local dev `trace` with `LOG_FORMAT=console` (never JSON), dev cluster `debug`,
  qa/staging `info`, production `error`. Every cluster environment logs JSON. Set levels through
  `LOG_LEVEL` and `LOG_FORMAT`, never in code; local settings live in the run target or
  `.env.example`.
- Never log secrets, tokens, or personal data, not even at `trace`. Log an opaque or keyed ID.

## Conventions and gotchas

- See `CLAUDE.md` for the branch/commit/PR rules; they are enforced by the git hooks in
  `.claude/hooks` (run `bash .claude/hooks/install.sh` once per clone).
- Open every PR as a draft. CI skips drafts, so run the full checks locally, push once they pass,
  and mark the PR ready when the work is finished; see CLAUDE.md "CI and Actions minutes".
- Every commit carries a DCO sign-off (`git commit -s`); the `checks / scrub` job fails without it.
- No real identifiers anywhere: fixtures use example.org, 192.0.2.0/24, 2001:db8::/32 and invented
  names.
- A user's `subject` is their Ory Kratos identity id; `AUTH_BACKEND` accepts only `kratos`.
