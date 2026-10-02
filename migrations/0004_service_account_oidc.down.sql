-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

DROP INDEX IF EXISTS service_accounts_oidc_idx;
ALTER TABLE public.service_accounts DROP COLUMN IF EXISTS oidc_subject, DROP COLUMN IF EXISTS oidc_issuer;
