// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"path/filepath"
	"slices"
)

// DenyWriteTarget returns the deny_write rule (RuleTable.DenyWrite: a built-in target, R20, or an fs.deny_write
// entry, ADR 0071) a modification of p reaches: p is the target, lies beneath it, or, when ancestors is set, is a
// directory the target lies beneath. Each target is matched at its path and at its symlink-resolved path, since a spelling of either
// reaches the same file. ancestors is for a rename, the one modification that moves a target without
// naming it: renaming `.git` away, writing a hook into the moved directory and renaming it back puts the
// hook in place, and RENAME_EXCHANGE swaps a prepared directory into `.git` in one call.
//
// It is the one predicate Evaluate and internal/runtime/supervisor both ask, so compile --test and the
// ledger answer one write the same way (SEMANTICS §2, R20 (b)); the supervisor asks it through
// decide.FSIndex, which gives this scan's answer in lookups per level of p.
//
// An fs.deny_write entry (IsDeclaredDenyWrite, ADR 0071) is matched by nearest wins: a write entry strictly beneath it
// reopens its own subtree, so a p that lies at or beneath one of the entry's reopen spellings (DenyWriteReopens)
// strictly beneath the spelling it matched at reaches no target there. A rename of a directory above the entry
// (ancestors) still reaches it, since it moves the entry whatever lies inside, and so does a rename of the reopen
// spelling itself, at either end: the write entry's own name in the entry's directory is the entry's,
// as the plane keys it (the name's row refuses a rename at depth 0). A built-in target is never reopened: a write entry
// inside one grants nothing beneath it (R20; only a write entry at the target's own path lifts it).
func (rt *RuleTable) DenyWriteTarget(p string, ancestors bool) (FSRule, bool) {
	return rt.denyWriteTargetAt(p, ancestors, ancestors)
}

// DenyWriteNameTarget is DenyWriteTarget for a modification that makes the name p: a mkdir, a mknod, a symlink, an
// exclusive create, a hard link's new name. It differs only at a reopen spelling itself, which it
// reaches: the write entry's own name is the fs.deny_write entry's, so the agent cannot make an object of its own
// there once the write entry's is gone, as the plane refuses a create there (its walk starts at the entry's
// directory). A removal of the name, a write of what it names and an open that may create it are DenyWriteTarget's
// question: the plane decides them on the object's own row, the write entry's.
func (rt *RuleTable) DenyWriteNameTarget(p string) (FSRule, bool) {
	return rt.denyWriteTargetAt(p, false, true)
}

// denyWriteTargetAt is DenyWriteTarget, with name set when the reopen spellings shadow an entry only strictly above p.
func (rt *RuleTable) denyWriteTargetAt(p string, ancestors, name bool) (FSRule, bool) {
	if rt == nil || p == "" {
		return FSRule{}, false
	}
	p = filepath.Clean(p)
	if rule := rt.Builtins.WriteRule(p, ancestors); rule != "" {
		return FSRule{Path: p, Resolved: p, Kind: FSDenyWrite, BuiltIn: true, BuiltinRule: rule}, true
	}
	for j := range rt.DenyWrite {
		if r := &rt.DenyWrite[j]; rt.denyWriteReaches(r, p, ancestors, name) {
			return *r, true
		}
	}
	return FSRule{}, false
}

// IsDeclaredDenyWrite reports whether r is an fs.deny_write entry (ADR 0071) rather than a built-in target (R20): a
// deny_write rule its author declared, so it carries the declared text and not BuiltIn. A deny_write rule with neither
// (a hand-built table's) reads as built in, the stricter of the two: no write entry reopens it.
func (r FSRule) IsDeclaredDenyWrite() bool { return r.Kind == FSDenyWrite && !r.BuiltIn && r.Raw != "" }

// denyWriteReaches is moveReaches with nearest wins for an fs.deny_write entry (DenyWriteTarget). p is clean; name is
// denyWriteTargetAt's.
func (rt *RuleTable) denyWriteReaches(r *FSRule, p string, ancestors, name bool) bool {
	if r.BuiltinRule != "" && rt.Builtins != nil && rt.Builtins.OwnPath(p) && !(ancestors && Covers(p, rt.Builtins.OwnRuntime)) {
		return false
	}
	var reopens []string
	asked := false
	for _, t := range [2]string{r.Path, r.Resolved} {
		if t == "" {
			continue
		}
		if ancestors && Covers(p, t) {
			return true
		}
		if !Covers(t, p) {
			continue
		}
		if !r.IsDeclaredDenyWrite() {
			return true
		}
		if !asked {
			reopens, asked = rt.DenyWriteReopens(r), true
		}
		if !reopenedAt(reopens, filepath.Clean(t), p, name) {
			return true
		}
	}
	return false
}

// reopenedAt reports whether one of reopens lies strictly beneath t and at or above p (strictly above p with name): a
// write entry nearer to p than the entry spelled t.
func reopenedAt(reopens []string, t, p string, name bool) bool {
	for _, s := range reopens {
		if s != t && Covers(t, s) && Covers(s, p) && !(name && s == p) {
			return true
		}
	}
	return false
}

// DenyWriteReopens is every spelling under which a write entry strictly beneath the fs.deny_write entry r reopens
// part of it (nearest wins, ADR 0071): each such write entry's own spellings, and its place beneath r spelled from each
// of r's spellings, so a path spelled through a link to r, or to the write entry, meets the write entry first as the
// kernel's walk on the resolved path does. Clean, in table order, without repeats; nil for a built-in target, which no
// write entry reopens, and for an entry with no write entry beneath it. internal/policy/decide indexes the same list.
func (rt *RuleTable) DenyWriteReopens(r *FSRule) []string {
	if rt == nil || r == nil || !r.IsDeclaredDenyWrite() {
		return nil
	}
	g := r.Canonical()
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if s = filepath.Clean(s); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	for i := range rt.FS {
		w := &rt.FS[i]
		if w.Kind != FSWrite {
			continue
		}
		wc := w.Canonical()
		if wc == g || !Covers(g, wc) {
			continue
		}
		rel, err := filepath.Rel(g, wc)
		if err != nil {
			continue
		}
		add(w.Path)
		add(w.Resolved)
		for _, t := range [2]string{r.Path, r.Resolved} {
			if t != "" {
				add(filepath.Join(t, rel))
			}
		}
	}
	return out
}

// AskDenyWriteTarget applies the same predicate to protected configuration in
// approval scopes. These entries do not widen the ordinary kernel policy.
func (rt *RuleTable) AskDenyWriteTarget(p string, ancestors bool) (FSRule, bool) {
	if rt == nil {
		return FSRule{}, false
	}
	return denyWriteTarget(rt.AskDenyWrite, p, ancestors)
}

func denyWriteTarget(rules []FSRule, p string, ancestors bool) (FSRule, bool) {
	if p == "" {
		return FSRule{}, false
	}
	p = filepath.Clean(p)
	for j := range rules {
		if r := &rules[j]; moveReaches(r, p, ancestors) {
			return *r, true
		}
	}
	return FSRule{}, false
}

// moveReaches reports whether r, at its path or its symlink-resolved one, lies at or above p or, with ancestors,
// beneath it. p is clean, as Covers wants, so a spelling such as dir/ still matches. It compares in place:
// Evaluate's scans, and decide.FSIndex's fallback for a table with an unclean spelling, walk every entry with it.
func moveReaches(r *FSRule, p string, ancestors bool) bool {
	for _, t := range [2]string{r.Path, r.Resolved} {
		if t != "" && (Covers(t, p) || (ancestors && Covers(p, t))) {
			return true
		}
	}
	return false
}

// DenyReadMoveTarget reports the deny_read entry a link or rename would carry a file out of: an entry the
// Landlock ruleset leaves unenforced (Unenforced, nested in a write entry) at or above p, or, when ancestors
// is set (a rename moves a directory's whole subtree), one beneath p. At tier 2 such an entry is enforced by
// the fanotify listener, which matches the path of each open, so a hard link or a rename gave the file a
// name no entry denies and it was read with no refusal; SEMANTICS §2 says "hard links and renames cannot
// move a file out of a rule". The supervisor refuses the move there (supervisor.md R15d), asking it through
// decide.FSIndex: this scan walks every fs entry, up to envScanMaxEntries of them.
func (rt *RuleTable) DenyReadMoveTarget(p string, ancestors bool) (FSRule, bool) {
	if rt == nil || p == "" {
		return FSRule{}, false
	}
	p = filepath.Clean(p)
	for j := range rt.FS {
		if r := &rt.FS[j]; r.Kind == FSDenyRead && r.Unenforced && moveReaches(r, p, ancestors) {
			return *r, true
		}
	}
	return FSRule{}, false
}
