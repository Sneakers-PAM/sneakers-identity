# API

The service implements `sneakers.identity.v1.IdentityService`, defined in
[proto/sneakers/identity/v1/identity.proto](../proto/sneakers/identity/v1/identity.proto), which
documents every RPC and field. Go clients import the generated code from
`github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1`.

The server also registers the gRPC health service (`grpc.health.v1.Health`) and server
reflection. The health service is go-buildinfo's (`github.com/Bugs5382/go-buildinfo`) and answers
two names:

- `""` (the default) is readiness: `SERVING` unless a required dependency is down, then
  `NOT_SERVING`. Its answer carries `sneakers-health`, the readiness report as compact JSON:
  `{"status":"ok|degraded|down","ready":true,"dependencies":[{"name":"postgres","state":"ok","required":true,"checkedAt":"2026-10-05T12:00:00Z","version":"17.11"}]}`.
  A failing dependency adds `error`, a class from a fixed set (`timeout`, `refused`,
  `unavailable`, `unauthenticated`, `connection-refused`, `dns`, `network`, `canceled`, `panic`,
  `error`), never the error's text, an address or a DSN. `version` is there when the dependency
  has a version read.
- `liveness` is the process only: `SERVING` while the process answers, whatever its
  dependencies.

Any other name gets `NotFound`. `Watch` streams the serving status of either name as it changes.
Each dependency is checked with a 1-second timeout and the result is reused for 5 seconds, so
probes don't load the dependencies; readiness recovers on its own once the dependency is back and
that window has passed.

Every health check's answer carries the build in its response headers: `sneakers-version` (the
image tag, `dev` when unstamped) and `sneakers-commit` (the source commit, `unknown` when neither
the build nor Go's VCS stamp knows it). A readiness answer also carries `sneakers-dep-postgres`,
the database server's version (`SHOW server_version`, first token, at most 64 characters; re-read
every 5 minutes, `unknown` until the first read succeeds), and `sneakers-depstate-<name>` (`ok`,
`degraded` or `down`) for each dependency. The gateway's diagnostics read them.

Every call must carry the caller's workload identity: its projected Kubernetes ServiceAccount
token as `authorization: Bearer <token>` (see [configuration.md](configuration.md#service-to-service-authentication)).
Identity verifies it and checks the caller against a per-method allow-list (`grpcsvc.CallerPolicy`):

| Caller | Methods | Access |
|---|---|---|
| `gateway` | every method | on behalf of the signed-in user (`acting_user_id`) |
| `notify` | `ListGroups`, `ListGroupMembers`, `ListUsersByAdGroups`, `ResolveUserLabels` | as itself |

Any other caller, or a listed caller on a method it isn't listed for, gets `PermissionDenied`; no
or a bad token gets `Unauthenticated`. The health service is exempt. Each refusal is recorded as a
`workload.call_refused` audit event. The gateway still authenticates the end user and gates the
admin RPCs before calling identity; the recovery role is the one rule identity also checks itself.

## Users and groups

| RPCs | What they do |
|---|---|
| `ListUsers`, `GetUser`, `SearchUsers`, `ResolveUserLabels` | Read users: all, one, a case-insensitive name/email search, and id-to-label lookups for rendering. |
| `ListGroups`, `GetGroup`, `CreateGroup` | Read groups, and create one in identity's `groups` table. |
| `AddGroupMember`, `RemoveGroupMember`, `ListGroupMembers`, `ListUserGroups` | Memberships. They live only in identity. |
| `SetUserRoles`, `UpdateUser`, `SetUserDisabled` | Change a user's roles, profile (name, email, username) or disabled state. A disabled user can't sign in, and their personal tokens stop verifying. |
| `ResolveUserContext` | The user, their group names and roles, keyed by login subject, with the groups' ids in the same order (`group_ids`). The gateway builds each request's actor from it, so a rule can name a group by name or by id. |
| `SetUserAdGroups`, `ListUsersByAdGroups`, `UserAdGroups` | Retired. Kept for wire compatibility: the first returns `Unimplemented`, the others return empty results. |

Groups live only in identity, managed in the Sneakers admin console. Group names are unique
case-insensitively.

### Roles

Roles are strings in `User.roles`, set with `SetUserRoles` (or at `PreCreateLocalUser`) and read
back through `GetUser`, `ListUsers` and `ResolveUserContext`. `site-admin` and `admin` make a user a
site admin; root is a site admin whatever its roles.

`recovery` grants access to the vault's recovery view of a secret's prior versions, where a fresh
second factor is still required. An old password may still work on a target that wasn't rotated,
so identity itself refuses to grant or revoke `recovery` (`PermissionDenied`, nothing changed)
unless `acting_user_id` names an enabled site admin or root. The gateway reads the role from the
user's roles and tells the vault. Each grant and revoke is recorded as `role.recovery.grant` or
`role.recovery.revoke` at high severity, next to the usual `user.roles.set`.

## Sign-in and provisioning

| RPCs | What they do |
|---|---|
| `AdoptOrProvisionFederatedUser` | The login path. Resolves the user by login subject; else adopts a pre-created row by username, then by email; else creates a user with the `user` role. |
| `GetUserBySubject`, `ResolveUserByEmail` | Pure lookups, with no side effects. `ResolveUserByEmail` lets the gateway refuse sign-in for unknown emails. |
| `PreCreateLocalUser`, `CreateLocalUser` | Create a user ahead of their first login; `CreateLocalUser` also creates the Ory Kratos identity. |
| `GetSetupState`, `BootstrapRoot` | First-run setup: whether no administrator exists yet, and creating the first one. `BootstrapRoot` refuses once an administrator exists. |
| `RequestPasswordReset`, `ConfirmPasswordReset` | Self-service password reset by emailed code. The request always answers the same way, so it never reveals whether an account exists. |
| `RequestEmailVerification`, `ConfirmEmailVerification` | Confirm a user's email address and username spelling with an emailed code. |
| `SendTransactionalEmail` | Send a message the caller wrote through identity's SMTP relay (the gateway uses it for Kratos recovery codes). |

Sign-in uses Ory: Ory Kratos for accounts and MFA, Ory Polis for SAML SSO and Ory Hydra for
machine OAuth. A user's `subject` is their Ory Kratos identity id.

## Second factors

| RPCs | What they do |
|---|---|
| `EnrollTotp`, `ConfirmTotp`, `VerifyTotp`, `GetMfaStatus`, `DisableTotp` | TOTP: enroll (the secret is stored encrypted), confirm with a first code, verify at sign-in, report status, remove. |
| `SendEmailOtp`, `VerifyEmailOtp` | Single-use six-digit codes by email, valid for five minutes, with a resend cooldown and an attempt limit. Stored only as hashes. |
| `WebauthnRegisterBegin`, `WebauthnRegisterFinish`, `WebauthnAssertBegin`, `WebauthnAssertFinish`, `ListWebauthnCredentials`, `RemoveWebauthnCredential` | Passkeys. Identity is the relying party; options and credentials cross the API as opaque JSON. |
| `ListUserFactors`, `RemoveFactor` | The factors a user can use (`totp`, `email`, `passkey`) and removing one. |

Every verify RPC answers a plain `ok=false` for any failure, without saying why.

## Machine access

| RPCs | What they do |
|---|---|
| `CreateServiceAccount`, `ListServiceAccounts`, `DisableServiceAccount` | Non-human principals. Disabling one stops its tokens and OIDC link from resolving. |
| `MintApiToken`, `ListApiTokens`, `RevokeApiToken`, `VerifyApiToken` | Opaque bearer tokens for a service account, with an optional expiry and a scope of groups. The token value is returned once, at mint; only its SHA-256 hash is stored. `VerifyApiToken` returns the scope's groups by name and id, pair for pair (`group_names`, `group_ids`). |
| `LinkOidcClient`, `UnlinkOidcClient`, `ResolveServiceAccountByOidc` | Bind an OAuth2 client (issuer and client id) to a service account, with an allowed-groups bound. A client's groups are its token's scope intersected with that bound; an empty bound grants nothing. `ResolveServiceAccountByOidc` returns them by name and id, pair for pair. |
| `MintUserToken`, `ListUserTokens`, `RevokeUserToken`, `VerifyUserToken` | Personal tokens (prefix `snk_u_`). They prove which user is calling and carry no scope, so the user's current groups apply on every call; `VerifyUserToken` returns their names and ids, pair for pair. Each token records its `client_kind`: `mcp` for a token minted through the gateway's OAuth flow for native (MCP) clients, `cli` for one minted on the tokens page (the default when the request leaves it empty; any other value is `InvalidArgument`). `VerifyUserToken` returns it, so the gateway can tell an MCP agent token from a machine-API token. |

Scopes and allowed groups name groups by id, by exact name, or by a slug (the name lowercased, with
spaces turned into `-`). They are stored as group ids, so a rename never moves a grant to another
group. A slug two groups share, or a name two groups share, grants nothing.

## Audit events

When `AUDIT_ADDR` is set, identity records each event below in the audit service's tamper-evident
tier once the change is made. A failed send is logged at `error` and never fails the change. An
event holds ids, kinds and outcomes only: never a password, code, TOTP secret or token value.

| Action | Recorded by | Subject | Attributes |
|---|---|---|---|
| `auth.signin` | `AdoptOrProvisionFederatedUser`: the password step Kratos accepted | user | `step`, `result` (`existing`, `adopted` or `provisioned`), `outcome` |
| `auth.password_reset` | `ConfirmPasswordReset` for a known email, right or wrong code | user | `outcome` |
| `mfa.verify` | `VerifyTotp`, `VerifyEmailOtp`, `WebauthnAssertFinish`, at sign-in or at a step-up | user | `factor`, `outcome`, `purpose` (email codes) |
| `mfa.enroll` | `ConfirmTotp` (first confirmation), `WebauthnRegisterFinish` | user | `factor`, `credential_id` (passkeys) |
| `mfa.remove` | `DisableTotp`, `RemoveFactor`, `RemoveWebauthnCredential`, when a factor was removed | user | `factor`, `credential_id` (passkeys) |
| `user.create` | `CreateLocalUser`, `PreCreateLocalUser`, `BootstrapRoot`, and a first sign-in that provisions a user | user | `source` (`local`, `precreate`, `bootstrap` or `signin`), `username`, `roles`, `root` |
| `user.update` | `UpdateUser`, when a field changed | user | `changed` (`email`, `name`, `username`) |
| `user.roles.set` | `SetUserRoles` | user | `roles`, `added`, `removed` |
| `role.recovery.grant`, `role.recovery.revoke` | `SetUserRoles`, `PreCreateLocalUser`, when the recovery role is added or removed | user | `role`, `severity` (`high`) |
| `user.disable`, `user.enable` | `SetUserDisabled` | user | |
| `group.create` | `CreateGroup` | group | `name` |
| `group.member.add`, `group.member.remove` | `AddGroupMember`, `RemoveGroupMember`, when membership changed | user (the group is the event's group) | `user_id`, `group_id` |
| `service_account.create`, `service_account.disable` | `CreateServiceAccount`, `DisableServiceAccount` | service account | `name` |
| `service_account.oidc.link`, `service_account.oidc.unlink` | `LinkOidcClient`, `UnlinkOidcClient` | service account | `oidc_issuer`, `oidc_subject`, `allowed_groups` |
| `api_token.mint`, `api_token.revoke` | `MintApiToken`, `RevokeApiToken` | token id | `service_account_id`, `scope`, `expires_at_unix` |
| `workload.call_refused` | the workload-auth interceptors, for a refused call | the gRPC method | `caller`, `service_account`, `code`, `reason` |
| `user_token.mint`, `user_token.revoke` | `MintUserToken`, `RevokeUserToken` | token id | `user_id`, `label`, `client_name`, `client_kind` (mint), `expires_at_unix` |

The actor is the request's `acting_user_id` (or `created_by` and `acting_admin` where the request
already had those): the signed-in user the gateway acts for. When it is empty, a user's own change
(a second factor, a personal token, a sign-in) names that user, and an administrative change is
recorded with no actor. Role, list and lookup values come back sorted and comma-separated.

A password Kratos rejects never reaches identity, so the gateway records that failed sign-in.
