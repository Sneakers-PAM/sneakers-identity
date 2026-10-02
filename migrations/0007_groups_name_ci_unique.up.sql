-- Copyright 2026 The Sneakers-PAM Authors
-- SPDX-License-Identifier: Apache-2.0

-- Group names must be unique case-insensitively. Vault RACI matches group
-- subjects by NAME, case-insensitively, so two groups whose names differ only
-- in case ("Ops" / "ops") are indistinguishable downstream: a grant to one
-- would silently grant the other. The scope code already fails closed on
-- duplicate exact names; this index stops the duplicate from being written in
-- the first place (CreateGroup and the lldap group sync both honor it).
--
-- Fails if the table already holds a case-insensitive duplicate; resolve any
-- duplicate by hand before migrating.
CREATE UNIQUE INDEX groups_name_lower_idx ON public.groups (lower(name));
