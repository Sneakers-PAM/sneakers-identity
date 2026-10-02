-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Scope grammar: oidc_allowed_groups now stores canonical group IDs
-- instead of the earlier exact group names, so a group rename can never
-- re-point an admin's bound at a different group.
--
-- Each entry is rewritten in place (order kept, duplicates collapsed):
--   * already a group ID                          -> kept
--   * the exact name of exactly ONE group          -> that group's ID
--   * anything else (unknown or ambiguous name)    -> kept verbatim; it is
--     inert, because identity matches stored entries only against a group ID
--     or a unique exact name, never by slug
-- Idempotent: running it again changes nothing. Only rows with a non-empty
-- bound are touched.
UPDATE public.service_accounts sa
   SET oidc_allowed_groups = ARRAY(
         SELECT r.v
           FROM (
             SELECT e.ord,
                    COALESCE(
                      (SELECT g.id FROM public.groups g WHERE g.id = e.v),
                      (SELECT min(g.id) FROM public.groups g WHERE g.name = e.v HAVING count(*) = 1),
                      e.v) AS v
               FROM unnest(sa.oidc_allowed_groups) WITH ORDINALITY AS e(v, ord)
           ) r
          GROUP BY r.v
          ORDER BY min(r.ord))
 WHERE cardinality(sa.oidc_allowed_groups) > 0;
