-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

ALTER TABLE public.users ADD COLUMN disabled_at timestamptz;
