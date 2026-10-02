// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"context"
	"strings"
)

// Machine scope grammar: how a machine caller's scope tokens (an API
// token's stored scope, or a Hydra JWT's `scope` claim) map onto directory
// groups, and so onto the RACI group names vault evaluates.
//
// OAuth2 scope tokens are space-delimited, so a group named "Help Desk" can
// never appear verbatim in a scope. A scope token therefore matches a group
// by one of two forms:
//
//   - ID: the token equals the group's ID byte for byte (case-sensitive).
//     IDs are system-assigned and immutable, so the ID form always wins.
//   - Slug: the token, ASCII-lowercased, equals the group's slug. The slug of
//     a name is: printable ASCII only (any other byte means "no slug", so the
//     group is reachable by ID only, which rules out Unicode lookalikes),
//     trimmed, runs of whitespace collapsed to one "-", ASCII-lowercased. No
//     other rewriting: "_" is not "-", and "--" is not collapsed. A plain
//     ASCII name without spaces ("Infrastructure") is its own slug up to
//     case, so the legacy exact-name form keeps working.
//
// Fail-closed rules, all computed over the WHOLE directory (not just a
// caller's bound):
//
//   - Slug collision: two or more groups share a slug. That slug grants
//     nothing; each group stays reachable by ID.
//   - ID shadow: a slug equals (case-insensitively) another group's ID. That
//     slug grants nothing, so a case variant of an ID can never resolve to a
//     different group than the ID itself.
//   - Duplicate exact name: vault evaluates RACI by group NAME, so two groups
//     with the same name are indistinguishable downstream. Neither can be
//     granted to a machine, by ID or by slug.
//
// Case-insensitive slug matching does not widen access: a token can only
// resolve to a group whose slug is unique in the directory, and the result is
// then still bounded by the admin's allowed set (IDs) or mint-time scope.

// dirGroup is one row of the identity groups table.
type dirGroup struct {
	ID   string
	Name string
}

// refOutcome is the result of resolving one reference to a group.
type refOutcome int

const (
	refUnknown  refOutcome = iota // matches no group
	refResolved                   // matches exactly one usable group
	refBlocked                    // matches only an ambiguous slug or an unusable group
)

// groupIndex is an immutable lookup over a snapshot of the groups table.
type groupIndex struct {
	byID     map[string]dirGroup
	bySlug   map[string]dirGroup // unique, unshadowed slugs of usable groups
	blocked  map[string]struct{} // slugs that must grant nothing
	byName   map[string]dirGroup // unique exact names of usable groups
	unusable map[string]struct{} // IDs of groups whose exact name is duplicated
}

// groupSlug returns the slug of a group name, or ok=false when the name has
// none (non-ASCII, control characters, a quote or backslash, or blank).
func groupSlug(name string) (string, bool) {
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c == ' ', c == '\t', c == '\n', c == '\v', c == '\f', c == '\r':
		case c < 0x21, c > 0x7e, c == '"', c == '\\':
			return "", false
		}
	}
	fields := strings.Fields(name)
	if len(fields) == 0 {
		return "", false
	}
	return asciiLower(strings.Join(fields, "-")), true
}

// validScopeToken reports whether tok is a legal RFC 6749 scope-token that is
// also printable ASCII: 0x21, 0x23-0x5B, 0x5D-0x7E. Anything else (including
// every non-ASCII byte) can never match a group.
func validScopeToken(tok string) bool {
	if tok == "" {
		return false
	}
	for i := 0; i < len(tok); i++ {
		c := tok[i]
		if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
			return false
		}
	}
	return true
}

// asciiLower lowercases A-Z only. Deliberately not strings.ToLower, which
// folds Unicode (e.g. KELVIN SIGN U+212A to "k").
func asciiLower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'A' && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}
	return string(b)
}

func newGroupIndex(groups []dirGroup) *groupIndex {
	ix := &groupIndex{
		byID:     make(map[string]dirGroup, len(groups)),
		bySlug:   make(map[string]dirGroup, len(groups)),
		blocked:  make(map[string]struct{}),
		byName:   make(map[string]dirGroup, len(groups)),
		unusable: make(map[string]struct{}),
	}
	nameCount := make(map[string]int, len(groups))
	slugCount := make(map[string]int, len(groups))
	lowerIDs := make(map[string][]string, len(groups)) // lower(id) -> ids
	for _, g := range groups {
		ix.byID[g.ID] = g
		nameCount[g.Name]++
		lowerIDs[asciiLower(g.ID)] = append(lowerIDs[asciiLower(g.ID)], g.ID)
		if s, ok := groupSlug(g.Name); ok {
			slugCount[s]++
		}
	}
	for _, g := range groups {
		if nameCount[g.Name] > 1 {
			ix.unusable[g.ID] = struct{}{}
		} else {
			ix.byName[g.Name] = g
		}
		s, ok := groupSlug(g.Name)
		if !ok {
			continue
		}
		if slugCount[s] > 1 || shadowsOtherID(lowerIDs[s], g.ID) || nameCount[g.Name] > 1 {
			ix.blocked[s] = struct{}{}
			continue
		}
		ix.bySlug[s] = g
	}
	return ix
}

// shadowsOtherID reports whether ids (every group ID equal to a slug up to
// ASCII case) holds any ID other than self.
func shadowsOtherID(ids []string, self string) bool {
	for _, id := range ids {
		if id != self {
			return true
		}
	}
	return false
}

// resolveToken resolves one machine scope token: ID first, then slug.
func (ix *groupIndex) resolveToken(tok string) (dirGroup, refOutcome) {
	if !validScopeToken(tok) {
		return dirGroup{}, refUnknown
	}
	if g, ok := ix.byID[tok]; ok {
		if _, bad := ix.unusable[g.ID]; bad {
			return dirGroup{}, refBlocked
		}
		return g, refResolved
	}
	s := asciiLower(tok)
	if _, bad := ix.blocked[s]; bad {
		return dirGroup{}, refBlocked
	}
	if g, ok := ix.bySlug[s]; ok {
		return g, refResolved
	}
	return dirGroup{}, refUnknown
}

// resolveAdminRef resolves one admin-supplied group reference (a
// LinkOidcClient allowed_groups entry, or a MintApiToken scope token): an ID,
// a unique exact name (which may contain spaces or non-ASCII, since it never
// travels in a scope string), or a token form. ok=false means the reference
// does not name exactly one usable group, and the caller must reject it.
func (ix *groupIndex) resolveAdminRef(ref string) (dirGroup, bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return dirGroup{}, false
	}
	if g, ok := ix.byID[ref]; ok {
		_, bad := ix.unusable[g.ID]
		return g, !bad
	}
	if g, ok := ix.byName[ref]; ok {
		return g, true
	}
	g, out := ix.resolveToken(ref)
	return g, out == refResolved
}

// resolveStored resolves a stored oidc_allowed_groups entry: a canonical
// group ID, or (read-time back-compat for legacy rows) a unique exact group
// name. Stored entries are never slug-matched.
func (ix *groupIndex) resolveStored(entry string) (dirGroup, bool) {
	if g, ok := ix.byID[entry]; ok {
		_, bad := ix.unusable[g.ID]
		return g, !bad
	}
	g, ok := ix.byName[entry]
	return g, ok
}

// resolveScope resolves a whitespace-separated scope to its groups
// (de-duplicated, scope order). blocked lists, once each, the normalized
// key (the colliding slug, or the unusable group's ID) of every token that
// hit a fail-closed rule; every key is a real directory value, never raw
// caller input, so it is safe to log. Unknown tokens are silently dropped.
func (ix *groupIndex) resolveScope(scope string) (groups []dirGroup, blocked []string) {
	groups = []dirGroup{}
	seen := make(map[string]struct{})
	seenBlocked := make(map[string]struct{})
	for _, tok := range strings.Fields(scope) {
		g, out := ix.resolveToken(tok)
		switch out {
		case refResolved:
			if _, dup := seen[g.ID]; dup {
				continue
			}
			seen[g.ID] = struct{}{}
			groups = append(groups, g)
		case refBlocked:
			key := tok
			if _, isID := ix.byID[tok]; !isID {
				key = asciiLower(tok)
			}
			if _, dup := seenBlocked[key]; dup {
				continue
			}
			seenBlocked[key] = struct{}{}
			blocked = append(blocked, key)
		}
	}
	return groups, blocked
}

// bound keeps only the groups whose ID is named by a stored allowed entry.
// nil/empty allowed keeps NOTHING (fail closed, never "all").
func (ix *groupIndex) bound(groups []dirGroup, allowed []string) []dirGroup {
	out := []dirGroup{}
	if len(allowed) == 0 {
		return out
	}
	allow := make(map[string]struct{}, len(allowed))
	for _, e := range allowed {
		if g, ok := ix.resolveStored(e); ok {
			allow[g.ID] = struct{}{}
		}
	}
	for _, g := range groups {
		if _, ok := allow[g.ID]; ok {
			out = append(out, g)
		}
	}
	return out
}

// groupNames projects groups onto their RACI names (never nil).
func groupNames(gs []dirGroup) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.Name)
	}
	return out
}

// groupIDs projects groups onto their ids, in the same order as groupNames
// (never nil).
func groupIDs(gs []dirGroup) []string {
	out := make([]string, 0, len(gs))
	for _, g := range gs {
		out = append(out, g.ID)
	}
	return out
}

// loadGroupIndex snapshots the groups table. The table is small (the
// directory's groups) and this runs inside the one identity call the gateway
// already makes per machine request, so there is no extra network hop and no
// cache to go stale: a rename, delete or new collision takes effect on the
// very next request.
func (s *Server) loadGroupIndex(ctx context.Context) (*groupIndex, error) {
	rows, err := s.db.Query(ctx, `SELECT id, name FROM groups`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var gs []dirGroup
	for rows.Next() {
		var g dirGroup
		if err := rows.Scan(&g.ID, &g.Name); err != nil {
			return nil, err
		}
		gs = append(gs, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return newGroupIndex(gs), nil
}
