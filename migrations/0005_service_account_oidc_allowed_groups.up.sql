-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- OIDC trust model: admin-controlled bound on the OIDC client linkage.
-- The gateway grants a linked client (JWT scope groups INTERSECT
-- oidc_allowed_groups). NOT NULL DEFAULT '{}' so every existing row (linked or
-- not) starts with NO allowed groups: fail closed, never "all".
ALTER TABLE public.service_accounts ADD COLUMN oidc_allowed_groups text[] NOT NULL DEFAULT '{}';
