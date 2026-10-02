// Copyright 2026 The Sneakers-PAM Authors
// SPDX-License-Identifier: Apache-2.0

package grpcsvc

import (
	"reflect"
	"testing"
)

// fixtureGroups is a directory with every shape the scope grammar has to
// handle: plain names, names with spaces, a slug collision, a name whose slug
// shadows another group's ID, a duplicated exact name, and non-ASCII names.
var fixtureGroups = []dirGroup{
	{ID: "group-infra", Name: "Infrastructure"},
	{ID: "group-helpdesk", Name: "Help Desk"},
	{ID: "group-platform", Name: "Platform Team"},
	{ID: "group-oncall", Name: "On-Call"},
	// "Net Ops" and "net  ops" both slug to "net-ops": collision.
	{ID: "group-netops-a", Name: "Net Ops"},
	{ID: "group-netops-b", Name: "net  ops"},
	// Slug "group-infra" shadows the ID of "Infrastructure".
	{ID: "group-shadow", Name: "Group Infra"},
	// Two groups with the exact same name: vault matches RACI by name, so
	// neither may be granted to a machine, by ID or slug.
	{ID: "group-dup-1", Name: "Auditors"},
	{ID: "group-dup-2", Name: "Auditors"},
	// Non-ASCII names have no slug; reachable by ID only.
	{ID: "group-cafe", Name: "Café"},
	{ID: "group-greek", Name: "Ιnfrastructure"}, // leading GREEK CAPITAL IOTA
	{ID: "3f2b8c1e-9a4d-4e6b-8f00-1c2d3e4f5a6b", Name: "Security"},
}

func TestGroupSlug(t *testing.T) {
	cases := []struct {
		name   string
		in     string
		want   string
		wantOK bool
	}{
		{"plain", "Infrastructure", "infrastructure", true},
		{"space", "Help Desk", "help-desk", true},
		{"whitespace run collapses", "Help \t  Desk", "help-desk", true},
		{"trimmed", "  Platform Team  ", "platform-team", true},
		{"hyphen kept", "On-Call", "on-call", true},
		{"hyphen not collapsed", "Help - Desk", "help---desk", true},
		{"punctuation kept", "R&D", "r&d", true},
		{"empty", "", "", false},
		{"blank", "   ", "", false},
		{"non-ascii", "Café", "", false},
		{"greek lookalike", "Ιnfrastructure", "", false},
		{"nbsp", "Help Desk", "", false},
		{"kelvin sign", "Key", "", false},
		{"control char", "Help\x00Desk", "", false},
		{"del char", "Help\x7fDesk", "", false},
		{"quote", `Say "hi"`, "", false},
		{"backslash", `a\b`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := groupSlug(tc.in)
			if got != tc.want || ok != tc.wantOK {
				t.Fatalf("groupSlug(%q) = (%q, %v), want (%q, %v)", tc.in, got, ok, tc.want, tc.wantOK)
			}
		})
	}
}

func TestResolveToken(t *testing.T) {
	ix := newGroupIndex(fixtureGroups)
	cases := []struct {
		name    string
		tok     string
		wantID  string // "" => must not resolve
		blocked bool   // true => outcome is a (logged) collision
	}{
		{"id match", "group-helpdesk", "group-helpdesk", false},
		{"uuid id match", "3f2b8c1e-9a4d-4e6b-8f00-1c2d3e4f5a6b", "3f2b8c1e-9a4d-4e6b-8f00-1c2d3e4f5a6b", false},
		{"slug match", "help-desk", "group-helpdesk", false},
		{"slug match multiword", "platform-team", "group-platform", false},
		{"legacy exact name", "Infrastructure", "group-infra", false},
		{"legacy exact name with hyphen", "On-Call", "group-oncall", false},
		{"slug is case-insensitive", "HELP-DESK", "group-helpdesk", false},
		{"slug mixed case", "Help-Desk", "group-helpdesk", false},
		{"id wins over shadowing slug", "group-infra", "group-infra", false},
		{"id-shadowing slug is blocked for case variants", "GROUP-INFRA", "", true},
		{"id is case-sensitive", "GROUP-HELPDESK", "", false},
		{"uuid upper-case is not the id", "3F2B8C1E-9A4D-4E6B-8F00-1C2D3E4F5A6B", "", false},
		{"collision fails closed", "net-ops", "", true},
		{"collision ids still work a", "group-netops-a", "group-netops-a", false},
		{"collision ids still work b", "group-netops-b", "group-netops-b", false},
		{"duplicate exact name blocks slug", "auditors", "", true},
		{"duplicate exact name blocks id", "group-dup-1", "", true},
		{"unknown", "nope", "", false},
		{"underscore is not a hyphen", "help_desk", "", false},
		{"space form never a token", "Help Desk", "", false},
		{"empty", "", "", false},
		{"non-ascii token ignored", "café", "", false},
		{"greek lookalike token ignored", "Ιnfrastructure", "", false},
		{"kelvin lookalike token ignored", "Key", "", false},
		{"fullwidth token ignored", "ｈｅｌｐ-ｄｅｓｋ", "", false},
		{"non-ascii name reachable by id", "group-cafe", "group-cafe", false},
		{"greek name reachable by id", "group-greek", "group-greek", false},
		{"quote token ignored", `"help-desk"`, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			g, out := ix.resolveToken(tc.tok)
			if tc.wantID == "" {
				if out == refResolved {
					t.Fatalf("resolveToken(%q) resolved to %+v, want no match", tc.tok, g)
				}
				if (out == refBlocked) != tc.blocked {
					t.Fatalf("resolveToken(%q) outcome = %v, want blocked=%v", tc.tok, out, tc.blocked)
				}
				return
			}
			if out != refResolved || g.ID != tc.wantID {
				t.Fatalf("resolveToken(%q) = (%+v, %v), want %q", tc.tok, g, out, tc.wantID)
			}
		})
	}
}

// TestResolveAdminRef covers admin input (link allowed_groups / mint scope
// entries): everything a token accepts, plus a unique exact name (which may
// contain spaces or non-ASCII, since the admin API is not a scope string).
func TestResolveAdminRef(t *testing.T) {
	ix := newGroupIndex(fixtureGroups)
	cases := []struct {
		ref    string
		wantID string
	}{
		{"group-helpdesk", "group-helpdesk"},
		{"help-desk", "group-helpdesk"},
		{"Help Desk", "group-helpdesk"},
		{"  Help Desk  ", "group-helpdesk"},
		{"Café", "group-cafe"},
		{"Ιnfrastructure", "group-greek"},
		{"Infrastructure", "group-infra"},
		{"Net Ops", "group-netops-a"}, // exact name is unique even though the slug collides
		{"net-ops", ""},
		{"Auditors", ""},
		{"group-dup-2", ""},
		{"help desk", ""}, // exact name match is case-sensitive; slug path rejects the space
		{"nope", ""},
		{"", ""},
	}
	for _, tc := range cases {
		g, ok := ix.resolveAdminRef(tc.ref)
		if tc.wantID == "" {
			if ok {
				t.Errorf("resolveAdminRef(%q) = %+v, want rejection", tc.ref, g)
			}
			continue
		}
		if !ok || g.ID != tc.wantID {
			t.Errorf("resolveAdminRef(%q) = (%+v, %v), want %q", tc.ref, g, ok, tc.wantID)
		}
	}
}

// TestResolveStored covers stored allowed_groups entries: canonical IDs, plus
// legacy exact-name entries (read-time back-compat only).
func TestResolveStored(t *testing.T) {
	ix := newGroupIndex(fixtureGroups)
	cases := []struct {
		entry  string
		wantID string
	}{
		{"group-infra", "group-infra"},
		{"Infrastructure", "group-infra"}, // legacy name entry
		{"Help Desk", "group-helpdesk"},   // legacy name entry
		{"infrastructure", ""},            // stored entries are never slug-matched
		{"Auditors", ""},                  // ambiguous legacy name
		{"group-dup-1", ""},               // unusable group
		{"gone", ""},
	}
	for _, tc := range cases {
		g, ok := ix.resolveStored(tc.entry)
		if tc.wantID == "" {
			if ok {
				t.Errorf("resolveStored(%q) = %+v, want no match", tc.entry, g)
			}
			continue
		}
		if !ok || g.ID != tc.wantID {
			t.Errorf("resolveStored(%q) = (%+v, %v), want %q", tc.entry, g, ok, tc.wantID)
		}
	}
}

func TestScopeGroupNames(t *testing.T) {
	ix := newGroupIndex(fixtureGroups)
	cases := []struct {
		name        string
		scope       string
		wantNames   []string
		wantBlocked []string
	}{
		{"empty", "", []string{}, nil},
		{"id and slug", "group-infra help-desk", []string{"Infrastructure", "Help Desk"}, nil},
		{"legacy exact names", "Infrastructure On-Call", []string{"Infrastructure", "On-Call"}, nil},
		{"dedupe across forms", "help-desk group-helpdesk HELP-DESK", []string{"Help Desk"}, nil},
		{"unknown ignored", "nope help-desk", []string{"Help Desk"}, nil},
		{"collision fails closed, others survive", "net-ops platform-team", []string{"Platform Team"}, []string{"net-ops"}},
		{"collision reported once", "net-ops NET-OPS", []string{}, []string{"net-ops"}},
		{"whitespace tricks", "\thelp-desk\n  platform-team ", []string{"Help Desk", "Platform Team"}, nil},
		{"lookalikes ignored", "Ιnfrastructure café", []string{}, nil},
		{"non-ascii by id", "group-cafe", []string{"Café"}, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gs, blocked := ix.resolveScope(tc.scope)
			names := groupNames(gs)
			if !reflect.DeepEqual(names, tc.wantNames) {
				t.Fatalf("resolveScope(%q) names = %q, want %q", tc.scope, names, tc.wantNames)
			}
			if !reflect.DeepEqual(blocked, tc.wantBlocked) {
				t.Fatalf("resolveScope(%q) blocked = %q, want %q", tc.scope, blocked, tc.wantBlocked)
			}
		})
	}
}

func TestBoundedGroupNames(t *testing.T) {
	ix := newGroupIndex(fixtureGroups)
	cases := []struct {
		name    string
		scope   string
		allowed []string
		want    []string
	}{
		{"nil allowed grants nothing", "help-desk", nil, []string{}},
		{"empty allowed grants nothing", "help-desk group-infra", []string{}, []string{}},
		{"slug inside bound", "help-desk", []string{"group-helpdesk"}, []string{"Help Desk"}},
		{"id inside bound", "group-helpdesk", []string{"group-helpdesk"}, []string{"Help Desk"}},
		{"outside bound dropped", "help-desk platform-team", []string{"group-platform"}, []string{"Platform Team"}},
		{"legacy name bound", "Infrastructure", []string{"Infrastructure"}, []string{"Infrastructure"}},
		{"legacy name bound, slug token", "infrastructure", []string{"Infrastructure"}, []string{"Infrastructure"}},
		{"collision in bound still fails closed", "net-ops", []string{"group-netops-a", "group-netops-b"}, []string{}},
		{"collision ids in bound work", "group-netops-a", []string{"group-netops-a"}, []string{"Net Ops"}},
		{"unknown bound entry inert", "nope", []string{"nope"}, []string{}},
		{"bound entry is not slug-matched", "help-desk", []string{"help-desk"}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gs, _ := ix.resolveScope(tc.scope)
			got := groupNames(ix.bound(gs, tc.allowed))
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("bound(%q, %q) = %q, want %q", tc.scope, tc.allowed, got, tc.want)
			}
		})
	}
}
