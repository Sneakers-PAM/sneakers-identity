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
- `internal/audit/` - the events identity records and the audit-service client.
- `internal/kratos/` - the Ory Kratos admin client; `internal/email/` - the SMTP
  sender; `internal/secrets/` - the at-rest cipher for TOTP secrets.
- `internal/workloadauth/` - service-to-service authentication, a byte-for-byte copy of
  sneakers-vault's package at `SNEAKERS_VAULT_REF`. Never edit it here: change it in the vault,
  then copy it and bump the ref (`scripts/workloadauth-check.sh` fails CI otherwise). The
  allow-list is `internal/grpcsvc/callers.go`; a new RPC gets the gateway by default.
- `internal/config/`, `internal/server/` - the env loader and the gRPC server bootstrap, with the
  health service and readiness checks from `github.com/Bugs5382/go-buildinfo`.
- `proto/` - the API; `gen/go/` - the generated Go (committed, checked current in CI).
  `gen/go/thirdparty/` holds the audit client stubs, generated from the sneakers-audit proto at
  the commit pinned in `proto-refs.env` (pin-and-fetch, never a Go module import).
- `migrations/` - the Postgres schema, forward only.
- `test/kratos/` - the Kratos config the integration tests run against.
- `docs/` - configuration, API and runbook.

## Build, test, lint

- Build: `task build`
- Test: `task test`; set `IDENTITY_PG_DSN` (Postgres) and `KRATOS_TEST_ADMIN_URL` /
  `KRATOS_TEST_PUBLIC_URL` (a Kratos started from `test/kratos`) to run the integration tests
  (see README.md), otherwise they are skipped.
- Lint: `task lint`, plus `buf lint` for the proto.
- Generated code: `scripts/proto-generate.sh` (fetches the pinned callee protos into the
  git-ignored `.protos/`, then runs `buf generate`) with the plugin versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`.
- Vulnerabilities: `task vuln` runs govulncheck as CI does (`scripts/govulncheck.sh`): any called
  finding fails unless its ID is in `govulncheck-allow.txt`, which says why and when each entry
  goes. `scripts/govulncheck_test.sh` checks the filter itself.
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
- A user's `subject` is their Ory Kratos identity id.
- The `recovery` role (`grpcsvc.RoleRecovery`) is the one role identity gates itself: only an
  enabled site admin or root, named by `acting_user_id`, may grant or revoke it.
- Every change to a user, group, role, factor, service account or token records an audit event
  (`internal/grpcsvc/audit.go`, listed in `docs/api.md`). An event never carries a password,
  code, secret or token value; a new mutating RPC records one too.
- `go.mod` holds tagged releases only: no `replace` directive, and no pseudo-version (`@main`,
  `@<sha>`) of a `github.com/Bugs5382/*` or `github.com/Sneakers-PAM/*` module; the
  `proto-sync / check` job fails on either. To compile and test against a local package checkout,
  use a git-ignored `go.work` beside `go.mod` (`go work init . ../go-<pkg>`, which writes
  `use . ../go-<pkg>`); `go.work` and `go.work.sum` are in `.gitignore`. For local callee protos,
  point `SNEAKERS_AUDIT_PROTO_DIR` at a local `proto/` directory when running
  `scripts/proto-generate.sh`, rather than editing a pin in `proto-refs.env`. `SNEAKERS_VAULT_REF`
  pins no protos: it is the sneakers-vault commit `internal/workloadauth/` is copied from, and
  `SNEAKERS_VAULT_DIR` points `scripts/workloadauth-check.sh` at a local sneakers-vault checkout
  instead.
