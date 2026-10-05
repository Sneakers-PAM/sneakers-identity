-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.user_tokens
    DROP CONSTRAINT user_tokens_client_kind_check,
    DROP COLUMN client_kind;
