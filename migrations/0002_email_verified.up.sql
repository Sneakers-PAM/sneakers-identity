-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Record whether an account's email address has been confirmed via an
-- emailed verification code. Forward-only; defaults false so every existing row
-- is simply "not yet verified" (login/admin are NOT gated on this flag).
ALTER TABLE public.users
    ADD COLUMN email_verified boolean DEFAULT false NOT NULL;
