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
OTEL_EXPORTER_OTLP_ENDPOINT=otel-collector.example.org:4317
LOG_LEVEL=info
```
