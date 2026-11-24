// SPDX-License-Identifier: Apache-2.0

package agentdiff

import (
	"reflect"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file orders the refusal side of the filesystem families: the compiled deny_read rows (a refusal, or a question
// when AskRead marks an fs.ask_read entry), the deny_write rows and the deny_read patterns. A grant is ordered by
// containment (fsCovers); a refusal is ordered the other way, by how strict the nearest entry at a path is.
//
// The ordering is deliberately smaller than the decision: it claims Narrowed only when every difference is a refusal
// that was added or made stricter in a place where nothing nearer can reopen it, and Widened when a refusal was
// removed or made looser. Anything it cannot prove (a nearer write grant at the same path, a stricter refusal above
// a new weaker one, a changed attribute of an unchanged refusal, another protection field) is CannotClassify. It
// performs no evaluation: it reads the rows the compiler wrote. Its soundness against the decision engine is checked
// by the property test in internal/policy/decide (TestAgentdiffNeverCallsLooserTighter).

// strictness is how much a refusal takes away at its path: 0 none, 1 a question, 2 a refusal.
type strictness int

func rowStrictness(r agent.FSRule) strictness {
	if r.AskRead {
		return 1
	}
	return 2
}

// splitRefusals separates the deny_read rows from the other non-write rows.
func splitRefusals(rows []agent.FSRule) (refusals, rest []agent.FSRule) {
	for _, r := range rows {
		if r.Kind == agent.FSDenyRead {
			refusals = append(refusals, r)
		} else {
			rest = append(rest, r)
		}
	}
	return
}

// merge is the direction of two orderings of one family: a widening anywhere is a widening.
func merge(a, b Result) Result {
	switch {
	case a.Direction == CannotClassify || b.Direction == CannotClassify:
		return unknown()
	case a.Direction == Widened || b.Direction == Widened:
		added := append(slices.Clone(a.NewlyAllowed), b.NewlyAllowed...)
		slices.Sort(added)
		return Result{Direction: Widened, NewlyAllowed: slices.Compact(added)}
	case a.Direction == Narrowed || b.Direction == Narrowed:
		return Result{Direction: Narrowed}
	}
	return Result{Direction: Unchanged}
}

// byPath groups rows by the path they govern, with the attributes that do not order them cleared.
func byPath(rows []agent.FSRule) map[string][]agent.FSRule {
	m := map[string][]agent.FSRule{}
	for _, r := range rows {
		r = fsAuthority(r)
		// A write grant elsewhere decides whether the kernel can enforce a refusal beneath it; that is the
		// grant's own change, ordered by the write family.
		r.Unenforced = false
		p := fsPath(r)
		m[p] = append(m[p], r)
	}
	return m
}

func levelOf(rows []agent.FSRule) strictness {
	var l strictness
	for _, r := range rows {
		l = max(l, rowStrictness(r))
	}
	return l
}

// nearestAbove is the nearest entry strictly above p among the refusal paths and the write grant paths, and whether it
// is a refusal (with its strictness).
func nearestAbove(p string, refusals map[string][]agent.FSRule, grants []agent.FSRule) (level strictness, grant bool) {
	best := -1
	for q, rows := range refusals {
		if q != p && within(p, q) && len(q) > best {
			best, level, grant = len(q), levelOf(rows), false
		}
	}
	for _, g := range grants {
		if q := fsPath(g); q != p && within(p, q) && len(q) > best {
			best, level, grant = len(q), 0, true
		}
	}
	return
}

// fsRefusals orders the deny_read rows of two tables. ag and bg are their write grants. ok is false when the change
// cannot be ordered.
func fsRefusals(a, b, ag, bg []agent.FSRule) (Result, bool) {
	am, bm := byPath(a), byPath(b)
	var tight, loose []string
	paths := map[string]bool{}
	for p := range am {
		paths[p] = true
	}
	for p := range bm {
		paths[p] = true
	}
	for p := range paths {
		la, lb := levelOf(am[p]), levelOf(bm[p])
		if la == lb {
			if la != 0 && !reflect.DeepEqual(am[p], bm[p]) {
				return Result{}, false // an attribute of an unchanged refusal differs
			}
			continue
		}
		for _, g := range append(slices.Clone(ag), bg...) {
			if fsPath(g) == p {
				return Result{}, false // a grant at the same place: which one decides is not ordered here
			}
		}
		if lb > la {
			// The nearest entry above, before the change, must not refuse more than the new row does.
			if above, grant := nearestAbove(p, am, ag); la == 0 && !grant && above > lb {
				return Result{}, false
			}
			tight = append(tight, p)
			continue
		}
		// A row that goes where a stricter refusal still covers its path (the question beneath a folder that is now
		// refused) loses nothing: the nearest entry above, with no grant between, refuses at least as much.
		if lb == 0 {
			if above, grant := nearestAbove(p, bm, bg); !grant && above >= la {
				continue
			}
		}
		switch {
		case la == 1:
			loose = append(loose, "Read "+p+" without asking")
		case lb == 1:
			loose = append(loose, "Read "+p+" after asking (it was refused)")
		default:
			loose = append(loose, "Read "+p+" (it was refused)")
		}
	}
	switch {
	case len(loose) > 0:
		slices.Sort(loose)
		return Result{Direction: Widened, NewlyAllowed: slices.Compact(loose)}, true
	case len(tight) > 0:
		return Result{Direction: Narrowed}, true
	}
	return Result{Direction: Unchanged}, true
}

// fsProtection orders the protection family: the deny_write rows (writes refused beneath a grant), the approval
// scope's protected rows and the deny_read patterns, each only a refusal, so one added narrows and one removed widens.
// Every other field of the family, and a changed attribute of a row that stayed, cannot be ordered.
func fsProtection(a, b *agent.RuleTable) Result {
	for _, f := range []string{"DenyWriteLinked", "NameDeny", "NameExempt", "NameLeftOut", "OwnState", "OwnReadable", "AbsentDenyRead", "AskReadRelaxes"} {
		if !compiledEqual(fieldValue(a, f), fieldValue(b, f), map[equalPointerPair]bool{}) {
			return unknown()
		}
	}
	// The held-read record repeats the deny_read patterns and lists the refusals inside a write entry; both are
	// ordered below, and the rest of it (mode, name rules, aliases) must be equal.
	ra, rb := a.Reads, b.Reads
	ra.Patterns, ra.Nested, rb.Patterns, rb.Nested = nil, nil, nil, nil
	if !reflect.DeepEqual(ra, rb) {
		return unknown()
	}
	var out Result
	out.Direction = Unchanged
	for _, set := range []struct {
		a, b []agent.FSRule
		verb string
	}{{a.DenyWrite, b.DenyWrite, "Write "}, {a.AskDenyWrite, b.AskDenyWrite, "Write "}} {
		r, ok := refusalRows(set.a, set.b, set.verb)
		if !ok {
			return unknown()
		}
		out = merge(out, r)
	}
	patterns := func(t *agent.RuleTable) []string {
		var out []string
		for _, p := range append(slices.Clone(t.DenyReadPatterns), t.Reads.Patterns...) {
			out = append(out, p.Pattern+"\x00"+p.Rule)
		}
		slices.Sort(out)
		return slices.Compact(out)
	}
	pa, pb := patterns(a), patterns(b)
	nested := func(t *agent.RuleTable) map[string]agent.NestedRead {
		m := map[string]agent.NestedRead{}
		for _, n := range t.Reads.Nested {
			n.Pos = agent.Pos{}
			m[n.Rule+"\x00"+n.Path+"\x00"+n.Resolved] = n
		}
		return m
	}
	na, nb := nested(a), nested(b)
	for k, n := range nb {
		if old, had := na[k]; had && !reflect.DeepEqual(old, n) {
			return unknown()
		}
	}
	var nestedAdded, nestedRemoved []string
	for k := range nb {
		if _, had := na[k]; !had {
			nestedAdded = append(nestedAdded, k)
		}
	}
	for k, n := range na {
		if _, has := nb[k]; !has {
			nestedRemoved = append(nestedRemoved, "Read "+n.Path+" (it was refused)")
		}
	}
	switch {
	case len(nestedRemoved) > 0:
		slices.Sort(nestedRemoved)
		out = merge(out, Result{Direction: Widened, NewlyAllowed: nestedRemoved})
	case len(nestedAdded) > 0:
		out = merge(out, Result{Direction: Narrowed})
	}
	var added, removed []string
	for _, p := range pb {
		if !slices.Contains(pa, p) {
			added = append(added, p)
		}
	}
	for _, p := range pa {
		if !slices.Contains(pb, p) {
			removed = append(removed, "Read files matching "+strings.SplitN(p, "\x00", 2)[0]+" (they were refused)")
		}
	}
	switch {
	case len(removed) > 0:
		slices.Sort(removed)
		out = merge(out, Result{Direction: Widened, NewlyAllowed: removed})
	case len(added) > 0:
		out = merge(out, Result{Direction: Narrowed})
	}
	return out
}

// refusalRows orders two sets of rows that only ever refuse: a path that appears narrows, one that goes widens.
func refusalRows(a, b []agent.FSRule, verb string) (Result, bool) {
	am, bm := byPath(a), byPath(b)
	var added, removed []string
	for p, rows := range bm {
		old, had := am[p]
		switch {
		case !had:
			added = append(added, p)
		case !reflect.DeepEqual(old, rows):
			return Result{}, false
		}
	}
	for p := range am {
		if _, has := bm[p]; !has {
			removed = append(removed, verb+p+" (it was refused)")
		}
	}
	switch {
	case len(removed) > 0:
		slices.Sort(removed)
		return Result{Direction: Widened, NewlyAllowed: removed}, true
	case len(added) > 0:
		return Result{Direction: Narrowed}, true
	}
	return Result{Direction: Unchanged}, true
}
