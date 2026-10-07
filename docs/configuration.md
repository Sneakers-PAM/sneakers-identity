# Configuration

The service reads its configuration from the environment. Features whose settings are missing stay
off and their RPCs answer `Unavailable`; the service still starts.

## Core

| Variable | Default | Purpose |
|---|---|---|
| `DATABASE_DSN` | (required) | Postgres connection string used at runtime. Keep the password out of it and supply it with `PGPASSWORD` or a password file (`PGPASSFILE`). |
| `MIGRATE_DSN` | `DATABASE_DSN` | Connection string for running migrations. Set it when the runtime DSN goes through a transaction-pooling proxy: migrations need a direct session (advisory locks, prepared statements). |
| `MIGRATIONS_DIR` | `migrations` | Directory holding the migration files. The container image sets `/migrations`. |
| `GRPC_PORT` | `9090` | TCP port the gRPC server listens on (all interfaces). |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | `localhost:4317` | OTLP gRPC endpoint for traces and metrics (plaintext). |
| `LOG_LEVEL` | `info` | `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic` or `disabled`. |
| `LOG_FORMAT` | `json` | `json`, `console` (or `pretty`), or `both` (JSON on stdout, console on stderr). |

## Audit

| Variable | Default | Purpose |
|---|---|---|
| `AUDIT_ADDR` | (unset) | The audit service's gRPC address, for example `sneakers-audit:9194`. Identity records sign-ins, second-factor checks and every user, group, role, service-account and token change there (see [api.md](api.md#audit-events)). When unset no events are recorded, and the service logs a warning at start. |

## Service-to-service authentication

Identity checks every caller's workload identity and presents its own when it calls the audit
service. The code is the owner's helper package
[`github.com/Bugs5382/go-workload-identity`](https://github.com/Bugs5382/go-workload-identity)
(v1.0.0), which every Sneakers service imports in place of its old private copy.
`internal/server/workloadauth.go` sets the Sneakers values the package has no default for: the
audience `sneakers` when `WORKLOAD_AUDIENCE` is unset, and the caller-name prefix `sneakers-`
(`WORKLOAD_SERVICEACCOUNT_PREFIX` is not read).

As a callee:

| Variable | Default | Purpose |
|---|---|---|
| `WORKLOAD_OIDC_ISSUER` | (required) | The cluster's ServiceAccount token issuer (`https://`). The token's `iss` must equal it. |
| `WORKLOAD_OIDC_JWKS_URL` | discovered | JWKS URL (`https://`); when unset it's read from the issuer's OpenID configuration. |
| `WORKLOAD_OIDC_CA_FILE` | system roots | Extra PEM CA bundle for discovery and the JWKS fetch. |
| `WORKLOAD_OIDC_BEARER_FILE` | (unset) | Bearer token sent on discovery and the JWKS fetch. |
| `WORKLOAD_AUDIENCE` | `sneakers` | The token's `aud` must contain it. |
| `WORKLOAD_ALLOWED_SERVICEACCOUNTS` | (required) | Comma list of `<namespace>/<serviceaccount>`: for identity, `<ns>/sneakers-gateway,<ns>/sneakers-notify`, plus `<ns>/sneakers-appliance` where the appliance's platform controller calls `RevokeTokensByClientKind`. |
| `WORKLOAD_AUTH` | (unset) | `disabled` turns the check off, for local development only: every caller that reaches the port is trusted, and a warning is logged at start and every 5 minutes. No other value is accepted. |

Without `WORKLOAD_OIDC_ISSUER` the service refuses to start, unless `WORKLOAD_AUTH=disabled`;
setting both is refused too.

As a caller (to the audit service):

| Variable | Default | Purpose |
|---|---|---|
| `WORKLOAD_TOKEN_FILE` | (unset) | Path of the projected ServiceAccount token (audience `sneakers`), normally `/var/run/secrets/sneakers/token`. Sent on every audit call and re-read each time, so a rotated token is picked up. A set path that can't be read stops the start. Unset sends no token, which only a callee with authentication off accepts. |

No caller can be checked before the issuer's key set has loaded, so readiness waits for it too:
`/readyz` and the gRPC health check answer `NOT_SERVING`, with `workload-identity` reported down
in the readiness body (`server.WorkloadIdentity`, checking `Verifier.Ready`), until then. It's
left out of the readiness body when `WORKLOAD_AUTH=disabled`. Liveness is unaffected.

## Credential directory

Sign-in uses Ory: Ory Kratos holds the passwords, never identity. Identity provisions Kratos
identities, sets and resets their passwords, and keeps their traits in step with the user row.

| Variable | Default | Purpose |
|---|---|---|
| `KRATOS_ADMIN_URL` | `http://sneakers-kratos:4434` | Ory Kratos admin API. |

## Second factors

| Variable | Default | Purpose |
|---|---|---|
| `TOTP_ENC_KEY` | (unset) | 32-byte key, as 64 hex characters or standard base64, that encrypts TOTP secrets at rest (AES-256-GCM). Without it the TOTP RPCs answer `Unavailable`. Changing it makes every stored TOTP secret unreadable. |
| `TOTP_ISSUER` | `Sneakers` | Issuer label shown in authenticator apps. Give each environment its own (for example `Sneakers (test)`) so entries don't collide. |
| `WEBAUTHN_RP_ID` | `localhost` | Passkey relying-party ID: the site's domain, for example `sneakers.example.org`. `-` turns passkeys off. |
| `WEBAUTHN_RP_ORIGINS` | `http://localhost:8095` | Comma-separated origins the browser may use, for example `https://sneakers.example.org`. |
| `WEBAUTHN_RP_NAME` | `Sneakers` | Relying-party display name. |
| `WEBAUTHN_USER_VERIFICATION` | `preferred` | `required`, `preferred` or `discouraged`. |

## Email

Email carries one-time codes (second factor, password reset, email verification) and the messages
the gateway sends through `SendTransactionalEmail`.

| Variable | Default | Purpose |
|---|---|---|
| `SMTP_HOST` | (unset) | SMTP relay. When unset no email is sent: codes are still minted, and logged only with `OTP_DEV_ECHO`. |
| `SMTP_PORT` | `1025` | SMTP port. |
| `SMTP_FROM` | `no-reply@example.org` | Sender address. Set your own. |
| `SMTP_USER`, `SMTP_PASS` | (unset) | SMTP AUTH credentials; AUTH is used only when `SMTP_USER` is set. |
| `SMTP_TLS` | `false` | Upgrade the connection with STARTTLS. |
| `SMTP_TLS_INSECURE` | `false` | Skip certificate verification on STARTTLS, for a trusted relay whose certificate has no SANs. The connection stays encrypted. |
| `OTP_DEV_ECHO` | (unset) | `1` or `true` logs every minted code. Development only; never set it in production. |

## Tools

`cmd/seed` reads `DATABASE_DSN`. See [runbook.md](runbook.md).

## Example

```bash
DATABASE_DSN='postgres://identity@db.example.org:5432/identity?sslmode=require'
PGPASSWORD=...          # from your secret store
KRATOS_ADMIN_URL=http://kratos-admin.example.org:4434
TOTP_ENC_KEY=...        # from your secret store
TOTP_ISSUER=Sneakers
WEBAUTHN_RP_ID=sneakers.example.org
WEBAUTHN_RP_ORIGINS=https://sneakers.example.org
SMTP_HOST=smtp.example.org
SMTP_PORT=587
SMTP_TLS=true
SMTP_FROM=no-reply@example.org
AUDIT_ADDR=sneakers-audit:9194
WORKLOAD_TOKEN_FILE=/var/run/secrets/sneakers/token
WORKLOAD_OIDC_ISSUER=https://kubernetes.default.svc.cluster.local
WORKLOAD_OIDC_CA_FILE=/var/run/secrets/tokens/ca.crt
WORKLOAD_OIDC_BEARER_FILE=/var/run/secrets/tokens/token
WORKLOAD_AUDIENCE=sneakers
WORKLOAD_ALLOWED_SERVICEACCOUNTS=sneakers/sneakers-gateway,sneakers/sneakers-notify
OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector.example.org:4317
LOG_LEVEL=info
```
