-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Governed machine access: non-human principals (external/agent/API
-- callers) that authenticate with an opaque Bearer API token instead of a
-- cookie. token_hash stores only the sha256 of the token — the plaintext is
-- returned exactly once at mint time and never persisted.
CREATE TABLE public.service_accounts (
    id text PRIMARY KEY,
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    disabled boolean NOT NULL DEFAULT false,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX service_accounts_name_idx ON public.service_accounts (lower(name));

CREATE TABLE public.api_tokens (
    id text PRIMARY KEY,
    service_account_id text NOT NULL REFERENCES public.service_accounts(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    scope text NOT NULL DEFAULT '',
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX api_tokens_sa_idx ON public.api_tokens (service_account_id);
