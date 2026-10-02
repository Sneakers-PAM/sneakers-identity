-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Recreate the retired AD-group table as it was in 0001_baseline. It is
-- recreated empty; nothing reads or writes it.
CREATE TABLE IF NOT EXISTS public.user_ad_groups (
    user_id text NOT NULL,
    ad_group_name text NOT NULL,
    synced_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT user_ad_groups_pkey PRIMARY KEY (user_id, ad_group_name),
    CONSTRAINT user_ad_groups_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE
);
