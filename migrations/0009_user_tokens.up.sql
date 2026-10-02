-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Personal tokens identify their owner only; no scope or group column exists
-- because permissions are resolved live on every verify.
CREATE TABLE public.user_tokens (
    id text PRIMARY KEY,
    user_id text NOT NULL REFERENCES public.users(id) ON DELETE CASCADE,
    token_hash text NOT NULL UNIQUE,
    label text NOT NULL DEFAULT '',
    client_name text NOT NULL DEFAULT '',
    expires_at timestamptz,
    revoked_at timestamptz,
    last_used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX user_tokens_user_idx ON public.user_tokens (user_id);
