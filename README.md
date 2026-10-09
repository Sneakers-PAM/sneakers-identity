# Identity Service 🪪

> 👥 The Sneakers-PAM directory of record: users, groups, second factors and machine principals.

A gRPC service, `sneakers.identity.v1.IdentityService`, backed by Postgres. It holds the users,
groups and memberships that access decisions resolve against, each user's second factors, and the
service accounts and tokens machines authenticate with. It is not the login page: the gateway runs
the sign-in flow and asks identity who the user is and which factors they have.

## ✨ Highlights

- 🧑‍🤝‍🧑 **Directory:** users, groups and memberships, with search and label lookups for the UI.
- 🔐 **Second factors:** TOTP (secrets encrypted at rest), email codes and passkeys (WebAuthn).
- 🤖 **Machine access:** service accounts with scoped, expiring API tokens and OIDC client links.
- 📜 **Audit:** sign-ins, second-factor checks and every user, group, role, service-account and token change go to the audit service.
- 🔑 **Credential directory:** sign-in uses Ory: Ory Kratos holds the passwords and identity provisions them. Ory Polis (SAML SSO) and Ory Hydra (machine OAuth) sit at the gateway.

## 🚀 Run it

```bash
docker run -d --name identity-pg -e POSTGRES_USER=identity -e POSTGRES_DB=identity \
  -e POSTGRES_HOST_AUTH_METHOD=trust -p 127.0.0.1:5432:5432 postgres:17-alpine
WORKLOAD_AUTH=disabled DATABASE_DSN='postgres://identity@localhost:5432/identity?sslmode=disable' \
  go run ./cmd/identity
```

The container trusts local connections without a password, and `WORKLOAD_AUTH=disabled` lets
any local caller in without a workload token, both for development only. In a cluster identity
accepts only the gateway and notify, by their ServiceAccount tokens. The service
applies its migrations at start and listens for gRPC on port 9090. Without `TOTP_ENC_KEY` or
`SMTP_HOST` the features that need them answer `Unavailable`; provisioning and password changes
need Ory Kratos at `KRATOS_ADMIN_URL`.

Run the tests, including the Postgres and Kratos integration tests:

```bash
docker run -d --name identity-kratos -p 127.0.0.1:4433:4433 -p 127.0.0.1:4434:4434 \
  -v "$PWD/test/kratos:/etc/config/kratos:ro" oryd/kratos:v1.3.1 \
  serve -c /etc/config/kratos/kratos.yaml --dev --watch-courier=false
IDENTITY_PG_DSN='postgres://identity@localhost:5432/identity?sslmode=disable' \
  KRATOS_TEST_ADMIN_URL=http://localhost:4434 KRATOS_TEST_PUBLIC_URL=http://localhost:4433 \
  go test ./...
```

Without those variables the integration tests are skipped.

## 🛠 Develop

```bash
task build    # go build ./...
task test     # go test ./...
task lint     # tests, gofmt check, golangci-lint and yamllint
task license  # check the Apache-2.0 headers (golic)
scripts/proto-generate.sh  # regenerate gen/, with the audit client pinned in proto-refs.env
```

## 📚 Where to look

- [docs/configuration.md](docs/configuration.md): environment variables.
- [docs/api.md](docs/api.md): the gRPC API, by area.
- [docs/runbook.md](docs/runbook.md): operating the service and the seed tool.
- [proto/sneakers/identity/v1/identity.proto](proto/sneakers/identity/v1/identity.proto): the API
  definition.

## 🙏 Acknowledgements

Sneakers-PAM was originally written by [@Bugs5382](https://github.com/Bugs5382).

## 🔐 Export compliance

Sneakers-PAM is published from the United States and uses only standard, publicly available
cryptography; see [CRYPTO.md](CRYPTO.md). You are responsible for complying with applicable
export control and sanctions laws, including not using, exporting or re-exporting it in violation
of those laws or if you are on a restricted-party list.

## ⚖️ License

Apache-2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
