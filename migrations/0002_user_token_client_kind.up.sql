-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.user_tokens
    ADD COLUMN client_kind text DEFAULT 'cli'::text NOT NULL,
    ADD CONSTRAINT user_tokens_client_kind_check CHECK (client_kind IN ('cli', 'mcp'));
