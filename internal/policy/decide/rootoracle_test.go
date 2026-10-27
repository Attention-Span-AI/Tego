// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The root model's reference answers, which only tests ask: the rows of a whole table, the walk's answer
// asked of the table rather than the rows, and the exec rows. The plane's row compiler (planerows.go) and
// RootIndex.Walk are checked against them (TestRootWalkMatchesEvaluate, TestRootExecRowsMatchMatchExec).

// RootRows is rowIndex.rows (whose doc is the contract) of rt; nil for a nil table.
func RootRows(rt *agent.RuleTable) []RootRow {
	if rt == nil {
		return nil
	}
	return newRowIndex(rt).rows()
}

// evalFSRoot is the root tiers' rule on the table (root.go): Evaluator.root without an index.
func evalFSRoot(rt *agent.RuleTable, kind agent.ActionKind, path string) agent.EvalResult {
	return (&Evaluator{rt: rt}).root(kind, path, objFile)
}

// RootDecide is the root model's answer for an fs action on path, the reference the rows reproduce:
// Evaluate's bpflsm column without its deny_write and rename arms, as a verdict, a reason and the deciding
// and naming entries.
func RootDecide(rt *agent.RuleTable, kind agent.ActionKind, path string) (RootVerdict, record.Reason) {
	res := evalFSRoot(rt, kind, Canonical(rt, cleanPath(path)))
	v := RootVerdict{Allow: res.Verdict == agent.VerdictAllow, Rule: -1, Named: -1}
	p := Canonical(rt, cleanPath(path))
	if i, ok := fsDecider(rt, p, kind == agent.ActionFSRead); ok {
		v.Rule = i
	}
	if i, n, ok := nearestFS(rt, p); ok && n <= agent.MaxWalk {
		v.Named = i
	}
	v.Unresolved = res.Reason == record.ReasonPathUnresolved
	if v.Unresolved {
		v.Rule = -1
	}
	return v, res.Reason
}

// RootExecRow is one exec entry as tier 3's exec hook matches it (SEMANTICS §4, "Root tiers"; ADR 0025 (1):
// exec rows carry the parent directory and the final component): a file entry by the directory holding it and
// its name, a directory entry by the directory, an entry the author wrote as a bare name by that name wherever
// it lies. Each entry has a row under its declared and, where it differs, its resolved spelling.
type RootExecRow struct {
	// Rule is the entry's position in RuleTable.Exec; of several rows matching one file, the lowest wins.
	Rule int
	// Parent and Name are a file entry's directory and final component; Parent is "" for a name row.
	Parent, Name string
	// Dir is a directory entry's path: every file beneath it matches. "" for a file or name row.
	Dir string
	// Allow is the entry's verdict (an ask entry compiles as refused in P0).
	Allow bool
}

// RootExecRows is the root model's exec rows of rt, in RuleTable.Exec order.
func RootExecRows(rt *agent.RuleTable) []RootExecRow {
	if rt == nil {
		return nil
	}
	var out []RootExecRow
	for i := range rt.Exec {
		r := &rt.Exec[i]
		allow := r.Verdict == agent.VerdictAllow
		for j, p := range [2]string{r.Path, r.Resolved} {
			if p == "" || (j == 1 && p == r.Path) { // the resolved spelling only where it differs
				continue
			}
			if r.IsDir {
				out = append(out, RootExecRow{Rule: i, Dir: p, Allow: allow})
				continue
			}
			out = append(out, RootExecRow{Rule: i, Parent: filepath.Dir(p), Name: filepath.Base(p), Allow: allow})
		}
		if r.Basename != "" && r.ByName {
			out = append(out, RootExecRow{Rule: i, Name: r.Basename, Allow: allow})
		}
	}
	return out
}

// RootExecMatch is the exec rows' answer for the file at path, a clean absolute canonical path: the lowest
// entry any row of which matches, and false when none does. It is matchExec's bpflsm answer on such a path.
func RootExecMatch(rows []RootExecRow, path string) (rule int, allow, ok bool) {
	parent, name := filepath.Dir(path), filepath.Base(path)
	rule = -1
	for _, r := range rows {
		if rule >= 0 && r.Rule >= rule {
			continue
		}
		var hit bool
		switch {
		case r.Dir != "":
			hit = agent.Covers(r.Dir, path)
		case r.Parent != "":
			hit = r.Parent == parent && r.Name == name
		default:
			hit = r.Name == name
		}
		if hit {
			rule, allow = r.Rule, r.Allow
		}
	}
	return rule, allow, rule >= 0
}
