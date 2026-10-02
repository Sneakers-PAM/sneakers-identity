# Contributing to sneakers-identity

This repository follows the Sneakers-PAM workflow in the org
[CONTRIBUTING.md](https://github.com/Sneakers-PAM/.github/blob/main/.github/CONTRIBUTING.md):
issues from a template, a branch per issue, Conventional Commits, squash-merged PRs, and a
[DCO](DCO) sign-off (`git commit -s`) on every commit.

## Working on this repo

- Build and test: see [README.md](README.md). Set `IDENTITY_PG_DSN`, and `KRATOS_TEST_ADMIN_URL`
  and `KRATOS_TEST_PUBLIC_URL` for a Kratos started from `test/kratos`, to run the integration
  tests; without them those tests are skipped.
- Changing the API: edit `proto/sneakers/identity/v1/identity.proto`, then run `buf generate` (with the
  `protoc-gen-go` and `protoc-gen-go-grpc` versions pinned in
  `.github/workflows/job-go-lang-ci.yaml`) and commit the result under `gen/go`. CI fails if the
  generated code is stale or the change breaks the API.
- Every `.go`, `.proto` and `.sql` file starts with the Apache-2.0 header:

  ```
  // Copyright 2026 The Sneakers-PAM Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- No real names, hosts, addresses or other identifiers in code, tests, fixtures or docs. Use
  example.org, 192.0.2.0/24, 2001:db8::/32 and invented names.
