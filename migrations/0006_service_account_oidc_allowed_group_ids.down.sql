-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Reverse of 0006: map canonical group IDs back to group names, the form the
-- legacy gateway matched scope tokens against. Entries that are not
-- a known group ID are kept verbatim.
UPDATE public.service_accounts sa
   SET oidc_allowed_groups = ARRAY(
         SELECT r.v
           FROM (
             SELECT e.ord,
                    COALESCE((SELECT g.name FROM public.groups g WHERE g.id = e.v), e.v) AS v
               FROM unnest(sa.oidc_allowed_groups) WITH ORDINALITY AS e(v, ord)
           ) r
          GROUP BY r.v
          ORDER BY min(r.ord))
 WHERE cardinality(sa.oidc_allowed_groups) > 0;
