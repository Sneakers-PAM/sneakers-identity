# Runbook

## Start up

At start the service:

1. reads its configuration (it exits if `DATABASE_DSN` is missing or `AUTH_BACKEND` is set to
   anything but `kratos`);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. applies the migrations in `MIGRATIONS_DIR` using `MIGRATE_DSN` (or `DATABASE_DSN`);
4. connects to Postgres;
5. sets up each optional feature and logs whether it is on: the TOTP cipher, the SMTP relay, the
   Ory Kratos admin client, and the passkey relying party;
6. serves gRPC on `GRPC_PORT`.

A failure in steps 1 to 4, a malformed `TOTP_ENC_KEY`, or a server error is logged at fatal level
and the process exits non-zero.

## Health

Use the standard gRPC health check:

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

## First-run setup

A new installation has no administrator. `GetSetupState` reports `needs_setup: true` until
`BootstrapRoot` creates the first one (the gateway's setup page calls both). After that,
`BootstrapRoot` is refused.

## Secrets

- `TOTP_ENC_KEY` encrypts every TOTP secret. Keep it in your secret store and back it up with the
  database: without it, enrolled authenticators can't be verified and users must enroll again.
- Codes, API tokens and personal tokens are stored only as SHA-256 hashes; a database copy doesn't
  reveal them. Token values are never logged.

## Demo data

`cmd/seed` loads a small demo directory (five users, five groups and their memberships) for
development and test environments. It writes identity rows only; create the matching Ory Kratos
identities to sign in as them. It is idempotent. Never run it against production; it is built
into its own image (`docker build --target seed`), not the service image.

## Shutdown

On SIGINT or SIGTERM the server stops accepting new calls and waits up to 10 seconds for in-flight
calls to finish before stopping.

## Panics

A panic in a handler is recovered: the caller gets a generic `Internal` error, and the panic value
and stack go only to the log (at error level) and to the active trace span.

## Database

The schema is one baseline migration, `migrations/0001_baseline.up.sql`, applied at every start
(it is skipped once applied). Later changes are new numbered, forward-only files starting at
`0002`. Installs from another system move over with sneakers-migrate (export and import), not by
migrating. Back the database up like any other system of record.
