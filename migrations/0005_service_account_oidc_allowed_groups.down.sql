-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.service_accounts DROP COLUMN IF EXISTS oidc_allowed_groups;
