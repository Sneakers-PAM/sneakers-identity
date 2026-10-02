-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.service_accounts ADD COLUMN oidc_issuer text, ADD COLUMN oidc_subject text;
CREATE UNIQUE INDEX service_accounts_oidc_idx ON public.service_accounts (oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL;
