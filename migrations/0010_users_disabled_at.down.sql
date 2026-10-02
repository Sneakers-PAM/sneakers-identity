-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.users DROP COLUMN IF EXISTS disabled_at;
