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

Passwords live in a directory, never in identity. `AUTH_BACKEND` picks it and must match the
gateway's setting.

| Variable | Default | Purpose |
|---|---|---|
| `AUTH_BACKEND` | `keycloak` | `keycloak`: lldap holds the credentials (and a federating login provider reads them). `kratos`: Ory Kratos holds them, and lldap is not used at all. |
| `LLDAP_URL` | (unset) | lldap's admin HTTP URL, for example `http://lldap:17170`. Enables first-run setup, local-user provisioning, password reset and the group sync. Ignored under `kratos`. |
| `LLDAP_LDAP_URL` | `ldap://sneakers-lldap:3890` | lldap's LDAP URL, used to set passwords. |
| `LLDAP_BASE_DN` | `dc=sneakers,dc=local` | lldap's base DN, for example `dc=example,dc=org`. |
| `LLDAP_ADMIN_USERNAME` | `admin` | lldap admin user. |
| `LLDAP_ADMIN_PASSWORD` | (unset) | lldap admin password, from your secret store. |
| `GROUP_SYNC_INTERVAL` | `5m` | How often groups are reconciled from lldap (a Go duration; `0` syncs once at start only). |
| `KRATOS_ADMIN_URL` | `http://sneakers-kratos:4434` | Kratos admin API, used when `AUTH_BACKEND=kratos`. |

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

`cmd/cutover` reads `DATABASE_DSN`, `KRATOS_ADMIN_URL`, `CUTOVER_RESET_URL` (the sign-in page
linked from the notice email) and the `SMTP_*` settings. `cmd/seed` reads `DATABASE_DSN` and, to
create the demo users in lldap, the `LLDAP_*` settings. See [runbook.md](runbook.md).

## Example

```bash
DATABASE_DSN='postgres://identity@db.example.org:5432/identity?sslmode=require'
PGPASSWORD=...          # from your secret store
AUTH_BACKEND=kratos
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
