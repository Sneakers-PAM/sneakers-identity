-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Group membership is managed ONLY in the Sneakers admin UI
-- (group_membership); groups are never derived from federation claims. The
-- AD-claim sync (SetUserAdGroups -> user_ad_groups) never had a caller, so the
-- table is expected to be empty in every environment.
--
-- Guarded drop: if ANY row exists this migration aborts BEFORE changing
-- anything, so no data is silently destroyed. The service then refuses to
-- start (migrate is fatal) and golang-migrate marks version 8 dirty. To recover:
-- inspect / export the rows, delete them (the data is no longer read by
-- anything), then `migrate force 7` and restart.
DO $$
BEGIN
  IF to_regclass('public.user_ad_groups') IS NULL THEN
    RETURN;
  END IF;
  IF EXISTS (SELECT 1 FROM public.user_ad_groups) THEN
    RAISE EXCEPTION 'user_ad_groups is not empty (% rows): refusing to drop the retired AD-group table; export and delete the rows, then migrate force 7',
      (SELECT count(*) FROM public.user_ad_groups);
  END IF;
  DROP TABLE public.user_ad_groups;
END
$$;
