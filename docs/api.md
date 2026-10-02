# API

The service implements `sneakers.identity.v1.IdentityService`, defined in
[proto/sneakers/identity/v1/identity.proto](../proto/sneakers/identity/v1/identity.proto), which
documents every RPC and field. Go clients import the generated code from
`github.com/Sneakers-PAM/sneakers-identity/gen/go/sneakers/identity/v1`.

The server also registers the standard gRPC health service (`grpc.health.v1.Health`) and server
reflection.

Identity enforces no caller authorization itself: the gateway authenticates every request and
gates the admin RPCs before calling identity. Run identity where only the gateway (and other
trusted services) can reach it.

## Users and groups

| RPCs | What they do |
|---|---|
| `ListUsers`, `GetUser`, `SearchUsers`, `ResolveUserLabels` | Read users: all, one, a case-insensitive name/email search, and id-to-label lookups for rendering. |
| `ListGroups`, `GetGroup`, `CreateGroup` | Read groups, and create one in identity's `groups` table. |
| `AddGroupMember`, `RemoveGroupMember`, `ListGroupMembers`, `ListUserGroups` | Memberships. They live only in identity. |
| `SetUserRoles`, `UpdateUser`, `SetUserDisabled` | Change a user's roles, profile (name, email, username) or disabled state. A disabled user can't sign in, and their personal tokens stop verifying. |
| `ResolveUserContext` | The user, their group names and roles, keyed by login subject. The gateway builds each request's actor from it. |
| `SetUserAdGroups`, `ListUsersByAdGroups`, `UserAdGroups` | Retired. Kept for wire compatibility: the first returns `Unimplemented`, the others return empty results. |

Groups live only in identity, managed in the Sneakers admin console. Group names are unique
case-insensitively.

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
| `MintApiToken`, `ListApiTokens`, `RevokeApiToken`, `VerifyApiToken` | Opaque bearer tokens for a service account, with an optional expiry and a scope of groups. The token value is returned once, at mint; only its SHA-256 hash is stored. |
| `LinkOidcClient`, `UnlinkOidcClient`, `ResolveServiceAccountByOidc` | Bind an OAuth2 client (issuer and client id) to a service account, with an allowed-groups bound. A client's groups are its token's scope intersected with that bound; an empty bound grants nothing. |
| `MintUserToken`, `ListUserTokens`, `RevokeUserToken`, `VerifyUserToken` | Personal tokens (prefix `snk_u_`). They prove which user is calling and carry no scope, so the user's current groups apply on every call. |

Scopes and allowed groups name groups by id, by exact name, or by a slug (the name lowercased, with
spaces turned into `-`). They are stored as group ids, so a rename never moves a grant to another
group. A slug two groups share, or a name two groups share, grants nothing.
