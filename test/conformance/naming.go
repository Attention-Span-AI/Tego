// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"slices"
	"strings"
)

// The rule a generated cell's ledger line names is held to compile --test's column for the axis, except where the two
// differ in one of the known naming classes below, each found by the first guest runs of the fs grid with every
// verdict agreeing (ADR 0017's 2026-10-19 note). A class is open work for its owner, not an accepted answer: the
// decide core and the supervisor's naming, and a refusal's line naming an entry that refused nothing
// (an ADR 0016 rule-accuracy question). Fixing one removes its class here, and any other difference, a new
// one or a known pair of names on another axis, op or verdict, is a ledger disagreement the ratchet reports.

// NamingClass names a known difference between a generated cell's ledger rule and compile --test's.
type NamingClass string

const (
	// NamingRenameNamesGrant: an allowed rename whose line names the write entry that grants it, where compile names
	// the nearer watch or deny_read beneath that entry (every axis).
	NamingRenameNamesGrant NamingClass = "rename-names-grant"
	// NamingRefusalNamesWatch: a refusal whose line names the nearest entry, a watch, which refuses nothing, where
	// compile names the entry that refuses (the deny_read above it, or no entry): any action on the lsm plane, a read
	// on tier cgroup's listener.
	NamingRefusalNamesWatch NamingClass = "refusal-names-watch"
	// NamingPlaneRename: a rename the lsm plane refused, whose line and compile name different entries among those
	// covering its two names (the plane often the destination's, compile the source's).
	NamingPlaneRename NamingClass = "plane-rename"
	// NamingReadNamesWrite: an allowed read at tier landlock whose line names the nearest entry, a write entry, where
	// compile names the deny_read above it that the tier leaves unenforced.
	NamingReadNamesWrite NamingClass = "landlock-read-names-write"
	// NamingReadNamesWatch: an allowed read at tier landlock whose line names the nearest entry, a watch, where compile
	// names the write entry above it.
	NamingReadNamesWatch NamingClass = "landlock-read-names-watch"
)

// NamingAxis is what decides on an axis: its tier and the plane mode that decides ("" where none does).
type NamingAxis struct {
	Tier  Tier
	Plane string
}

// gridEntries is a grid fixture's assignment of entry kinds (the contract's keys, "" for none) to gridDepths.
type gridEntries [3]string

// gridOf reads a space 1 fixture's assignment back from its name, which gridFixture writes; ok is false for any
// other fixture.
func gridOf(fx *Fixture) (g gridEntries, ok bool) {
	names, found := strings.CutPrefix(fx.Name, "grid-")
	parts := strings.Split(names, ".")
	if !found || len(parts) != len(g) {
		return g, false
	}
	for i, n := range parts {
		known := false
		for _, k := range gridKinds {
			if k.name == n {
				g[i], known = k.key, true
			}
		}
		if !known {
			return g, false
		}
	}
	return g, true
}

// fallback is the rule a decision with no entry above it names: "unmatched" beside a write entry, the implicit
// entry where the contract has none.
func (g gridEntries) fallback() string {
	for _, k := range g {
		if k == "write" {
			return "unmatched"
		}
	}
	return "fs.implicit[/]"
}

// nearest is the rule of the deepest entry at or above path whose key is one of keys (any key when none is given),
// else the fallback.
func (g gridEntries) nearest(path string, keys ...string) string {
	out := g.fallback()
	for i, k := range g {
		if k == "" || !under(gridDepths[i], path) || (len(keys) > 0 && !slices.Contains(keys, k)) {
			continue
		}
		out = fmt.Sprintf("fs.%s[./%s/]", k, gridDepths[i])
	}
	return out
}

// covers says whether rule is the fallback or an entry at or above one of paths.
func (g gridEntries) covers(rule string, paths ...string) bool {
	if rule == g.fallback() {
		return true
	}
	for i, k := range g {
		if k == "" || rule != fmt.Sprintf("fs.%s[./%s/]", k, gridDepths[i]) {
			continue
		}
		for _, p := range paths {
			if under(gridDepths[i], p) {
				return true
			}
		}
	}
	return false
}

// KnownRuleNaming is the known class of a generated cell whose ledger line, with verdict, names ledger where compile
// --test's column for the axis names compile; "" when the difference is in no class (or the cell is not the fs
// grid's).
func KnownRuleNaming(fx *Fixture, c *Cell, ax NamingAxis, verdict, ledger, compile string) NamingClass {
	g, ok := gridOf(fx)
	if !ok || !c.Generated || ledger == compile {
		return ""
	}
	p := c.canon()
	nearest := g.nearest(p)
	refusing := g.nearest(p, "write", "deny_read")
	lsm := ax.Plane == string(ModeLSM)
	switch {
	case verdict == Allow && c.Op == OpRename && ledger == g.nearest(p, "write") && compile == nearest:
		return NamingRenameNamesGrant
	case verdict == Refused && strings.HasPrefix(ledger, "fs.watch[") && ledger == nearest && compile == refusing &&
		(lsm || (ax.Tier == TierCgroup && ax.Plane == "" && c.Op == OpRead)):
		return NamingRefusalNamesWatch
	case verdict == Refused && c.Op == OpRename && lsm && g.covers(ledger, p, c.Dest) && g.covers(compile, p, c.Dest):
		return NamingPlaneRename
	case verdict == Allow && c.Op == OpRead && ax.Tier == TierLandlock && strings.HasPrefix(nearest, "fs.write[") && ledger == nearest &&
		compile == g.nearest(p, "deny_read")+" (unenforced: parent writable)":
		return NamingReadNamesWrite
	case verdict == Allow && c.Op == OpRead && ax.Tier == TierLandlock && strings.HasPrefix(ledger, "fs.watch[") && ledger == nearest &&
		compile == g.nearest(p, "write"):
		return NamingReadNamesWatch
	}
	return ""
}
