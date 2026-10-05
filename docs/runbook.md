# Runbook

## Start up

At start the service:

1. reads its configuration (it exits if `DATABASE_DSN` is missing);
2. starts OpenTelemetry export to `OTEL_EXPORTER_OTLP_ENDPOINT`;
3. applies the migrations in `MIGRATIONS_DIR` using `MIGRATE_DSN` (or `DATABASE_DSN`);
4. connects to Postgres;
5. sets up each optional feature and logs whether it is on: the TOTP cipher, the SMTP relay, the
   Ory Kratos admin client, the passkey relying party, and the audit client (with or without the
   workload token);
6. sets up service-to-service authentication: it exits when `WORKLOAD_OIDC_ISSUER` is unset,
   unless `WORKLOAD_AUTH=disabled`, which it then warns about every 5 minutes;
7. serves gRPC on `GRPC_PORT`.

A refused caller is logged at warn (`call refused`, with the method, caller and reason) and
recorded as `workload.call_refused`. `Unavailable` with `workload verifier unavailable` means no
JWKS key set has loaded yet: check that the issuer or `WORKLOAD_OIDC_JWKS_URL` is reachable.

A failure in steps 1 to 4, a bad workload-auth setting, a malformed `TOTP_ENC_KEY`, or a server error is logged at fatal level
and the process exits non-zero.

## Health

Use the standard gRPC health check:

```bash
grpcurl -plaintext localhost:9090 grpc.health.v1.Health/Check
```

To see which build is running, ask for the response headers (`grpcurl -v`): the answer carries
`sneakers-version`, `sneakers-commit` and, once the database answered, `sneakers-dep-postgres`
(a `postgres version unknown` warning at start means it didn't). The image build stamps the
version and commit from its `VERSION` and `COMMIT` build arguments:

```bash
docker build --build-arg VERSION=v0.1.0 --build-arg COMMIT="$(git rev-parse HEAD)" .
```

### Readiness and liveness

Readiness (service `""`) fails while a required dependency is down, so traffic stops reaching a
pod that can't serve it; liveness (service `liveness`) never looks at a dependency, so an outage
doesn't restart every pod. The kubelet's gRPC liveness probe has to ask for service `liveness`;
that is set in the sneakers-release chart.

| Dependency | Required | Check | Why |
|---|---|---|---|
| `postgres` | yes | a ping on the pool | It holds the directory: users, groups, roles, factors and tokens. |
| `kratos` | yes | `GET /health/ready` on `KRATOS_ADMIN_URL` | It holds the credentials; sign-in and user provisioning go through it. |
| `audit` | no | its gRPC health check | Audit records are best effort: an event that can't be written is logged and the call still succeeds, so an unreachable audit service only makes identity `degraded`. Present only when `AUDIT_ADDR` is set. |

Read the report with `grpcurl -v -plaintext localhost:9090 grpc.health.v1.Health/Check` (the
`sneakers-health` header). Each change of a dependency's state is logged once: `health:
dependency down` or `degraded` at warn, `health: dependency recovered` at info, with the
dependency's name and error class.

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
