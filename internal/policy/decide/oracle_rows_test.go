// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// This file is the row compiler as T5 first wrote it (7f054b0), kept verbatim under oracle names: one nearest-entry
// scan over the whole table per row, per question and per keyed path. It is quadratic in the table and took
// seconds at the plane's caps; TestCompilePlaneMatchesOracle holds the indexed compiler to it. Since then it has
// gained, as CompilePlane did, the link rows of a deny_write target declared through a symlink (oracleLinkRows,
// PlaneRows.NoFollow) and the exec map's policy and name rows in the exec cap (PlaneRows.ExecMapEntries).

type oracleGrants struct {
	enumerated bool
	onPath     map[string]map[string]bool
	writes     []grantRule
	execDirs   []string
	execFiles  []string
}

type grantRule struct {
	path   string
	access agent.AccessSet
}

func oracleRootRows(rt *agent.RuleTable) []RootRow {
	if rt == nil {
		return nil
	}
	named := map[string]int{}
	for i := range rt.FS {
		if rt.FS[i].Path == "" {
			continue
		}
		p := rt.FS[i].Canonical()
		if _, seen := named[p]; !seen {
			named[p] = i
		}
	}
	rows := make([]RootRow, 0, len(named))
	for p, i := range named {
		rows = append(rows, RootRow{Path: p, Named: i, Read: oracleRootCell(rt, p, true), Modify: oracleRootCell(rt, p, false)})
	}
	sort.Slice(rows, func(a, b int) bool { return rows[a].Path < rows[b].Path })
	return rows
}

func oracleRootCell(rt *agent.RuleTable, p string, read bool) RootCell {
	i, ok := fsDecider(rt, p, read)
	if !ok {
		return RootCell{Rule: -1}
	}
	if n, _ := ruleSteps(rt.FS[i], p); n != 0 {
		return RootCell{Rule: -1}
	}
	k := rt.FS[i].Kind
	if read {
		return RootCell{Rule: i, Allow: k != agent.FSDenyRead}
	}
	return RootCell{Rule: i, Allow: k == agent.FSWrite}
}

func oracleCompilePlane(rt *agent.RuleTable) (*PlaneRows, error) {
	if rt == nil {
		return nil, fmt.Errorf("decide: no rule table")
	}
	s := &PlaneRows{fsByPath: map[string]int{}, execByPath: map[string]int{}, nameRule: map[string]int{}}
	paths := map[string]bool{}
	for i := range rt.FS {
		if rt.FS[i].Path != "" {
			paths[rt.FS[i].Canonical()] = true
		}
	}
	// A deny_write target and every directory above it up to the outermost write entry that encloses it
	// (enforce-plane R11): renaming any of them carries the target out of its place. Above that entry no write
	// entry covers the path, so every modification there is refused already.
	for j := range rt.DenyWrite {
		t := denyWritePath(rt.DenyWrite[j])
		top, ok := oracleOutermostWrite(rt, t)
		if !ok {
			continue // compile keeps only targets beneath a write entry; nothing to key otherwise
		}
		for cur := t; ; cur = filepath.Dir(cur) {
			paths[cur] = true
			if cur == top || cur == "/" {
				break
			}
		}
	}
	for i := range rt.Exec {
		r := &rt.Exec[i]
		if r.Verdict != agent.VerdictAllow {
			return nil, &ErrPlaneExecVerdict{Rule: i}
		}
		p := execPath(r)
		switch {
		case p == "":
		case r.IsDir:
			paths[p] = true
		default:
			if _, dup := s.execByPath[p]; !dup {
				s.execByPath[p] = len(s.Exec)
				s.Exec = append(s.Exec, PlaneExecRow{Path: p, Parent: filepath.Dir(p), Name: filepath.Base(p), Rule: i})
			}
		}
		if r.ByName && r.Basename != "" {
			if _, dup := s.nameRule[r.Basename]; !dup {
				s.nameRule[r.Basename] = i
				s.Names = append(s.Names, PlaneExecName{Name: r.Basename, Rule: i})
			}
		}
	}
	noFollow := oracleLinkRows(rt, paths, s.Exec)
	for p := range noFollow {
		paths[p] = true
	}
	s.ExecPolicy = !rt.ExecUnrestricted()
	s.NetPolicy = rt.Contract == nil || rt.Contract.Net != nil
	fsEntries := len(paths)
	if fsEntries > PlaneRowsMax || s.ExecMapEntries() > PlaneExecRowsMax {
		return nil, &ErrPlaneCap{FSRows: fsEntries, ExecRows: s.ExecMapEntries()}
	}
	sorted := make([]string, 0, len(paths))
	for p := range paths {
		sorted = append(sorted, p)
	}
	sort.Strings(sorted)
	x := NewRootIndex(oracleRootRows(rt))
	s.FS = make([]PlaneRow, 0, len(sorted))
	for _, p := range sorted {
		s.fsByPath[p] = len(s.FS)
		s.FS = append(s.FS, oracleCompileRow(rt, &x, p))
	}
	keyed := map[string]bool{}
	for p := range paths {
		if noFollow[p] {
			s.NoFollow = append(s.NoFollow, p)
		} else {
			keyed[p] = true
		}
	}
	sort.Strings(s.NoFollow)
	for _, e := range s.Exec {
		keyed[e.Path], keyed[e.Parent] = true, true
	}
	s.Keyed = make([]string, 0, len(keyed))
	for p := range keyed {
		s.Keyed = append(s.Keyed, p)
	}
	sort.Strings(s.Keyed)
	g := newOracleGrants(rt)
	for _, p := range s.Keyed {
		if a := g.at(p) & (agent.AccessReadFile | agent.AccessReadDir); a != 0 {
			s.Neutral = append(s.Neutral, NeutralRule{Path: p, Access: a})
		}
	}
	return s, nil
}

func oracleCompileRow(rt *agent.RuleTable, x *RootIndex, p string) PlaneRow {
	row := PlaneRow{Path: p, Read: planeNone, Modify: planeNone, Rename: planeNone, Exec: -1}
	rv, mv := x.Walk(p, true), x.Walk(p, false)
	row.Named = rv.Named
	switch {
	case rv.Unresolved:
		row.Kind |= PlaneReadDeny // an exhausted walk refuses both questions (SEMANTICS §2)
	case !rv.Allow:
		row.Kind |= PlaneReadDeny
		row.Read = PlaneRule{Section: PlaneFSRule, Index: rv.Rule}
	case rv.Rule >= 0:
		row.Read = PlaneRule{Section: PlaneFSRule, Index: rv.Rule}
	}
	if j, ok := oracleDenyWriteIdx(rt, p, false); ok {
		row.Modify = PlaneRule{Section: PlaneDenyWriteRule, Index: j}
		row.Kind |= PlaneProtected
	} else if !mv.Unresolved {
		if mv.Allow {
			row.Kind |= PlaneModifyAllow
		}
		if mv.Rule >= 0 {
			row.Modify = PlaneRule{Section: PlaneFSRule, Index: mv.Rule}
		}
	}
	if j, ok := oracleDenyWriteIdx(rt, p, true); ok {
		row.Kind |= PlaneRenameRefused
		row.Rename = PlaneRule{Section: PlaneDenyWriteRule, Index: j}
	}
	for i := range rt.Exec {
		if r := &rt.Exec[i]; r.IsDir && execPath(r) != "" && under(execPath(r), p) {
			row.Kind |= PlaneExecDir
			row.Exec = i
			break
		}
	}
	return row
}

func oracleDenyWriteIdx(rt *agent.RuleTable, p string, ancestors bool) (int, bool) {
	for j := range rt.DenyWrite {
		r := &rt.DenyWrite[j]
		for _, t := range [2]string{r.Path, r.Resolved} {
			if t != "" && (agent.Covers(t, p) || (ancestors && agent.Covers(p, t))) {
				return j, true
			}
		}
	}
	return -1, false
}

func oracleOutermostWrite(rt *agent.RuleTable, t string) (string, bool) {
	best := ""
	for i := range rt.FS {
		if rt.FS[i].Kind != agent.FSWrite {
			continue
		}
		w := rt.FS[i].Canonical()
		if agent.Covers(w, t) && (best == "" || len(w) < len(best)) {
			best = w
		}
	}
	return best, best != ""
}

func newOracleGrants(rt *agent.RuleTable) oracleGrants {
	var targets []string
	for i := range rt.FS {
		if rt.FS[i].Kind != agent.FSDenyRead || denyUnenforced(rt, i) {
			continue
		}
		if t := filepath.Clean(rt.FS[i].Governed()); t != "/" {
			targets = append(targets, t)
		}
	}
	g := oracleGrants{enumerated: len(targets) > 0}
	if g.enumerated {
		_, g.onPath = AncestorSet(Outermost(targets))
	}
	for i := range rt.FS {
		if r := &rt.FS[i]; r.Kind == agent.FSWrite {
			g.writes = append(g.writes, grantRule{filepath.Clean(r.Governed()), r.Access})
		}
	}
	for i := range rt.Exec {
		switch r := &rt.Exec[i]; {
		case execPath(r) == "":
		case r.IsDir:
			g.execDirs = append(g.execDirs, execPath(r))
		default:
			g.execFiles = append(g.execFiles, execPath(r))
		}
	}
	return g
}

func (g *oracleGrants) at(p string) agent.AccessSet {
	const read = agent.AccessReadFile | agent.AccessReadDir
	var a agent.AccessSet
	if !g.enumerated {
		a |= read
	} else {
		if _, level := g.onPath[p]; level {
			a |= agent.AccessReadDir
		}
		for cur := p; cur != "/"; cur = filepath.Dir(cur) {
			names, level := g.onPath[filepath.Dir(cur)]
			if !level {
				continue
			}
			a |= agent.AccessReadDir
			if !names[filepath.Base(cur)] {
				a |= read // cur is a sibling the enumeration grants
			}
		}
	}
	for _, w := range g.writes {
		if under(w.path, p) {
			a |= read | w.access
		}
	}
	for _, e := range g.execDirs {
		if under(e, p) {
			a |= read | agent.AccessExecute
		}
	}
	for _, e := range g.execFiles {
		if e == p {
			a |= agent.AccessReadFile | agent.AccessExecute
		}
	}
	return a
}

// under reports whether p is e or lies beneath it; both are clean absolute paths.
func under(e, p string) bool {
	return e == p || e == "/" || (len(p) > len(e) && p[len(e)] == '/' && p[:len(e)] == e)
}

// oracleLinkRows is linkRows by the scan: each deny_write target's declared spelling, where it differs from the
// resolved path, and its directories up to the outermost write entry, less what paths or an exec row keys.
func oracleLinkRows(rt *agent.RuleTable, paths map[string]bool, exec []PlaneExecRow) map[string]bool {
	var out map[string]bool
	for _, r := range rt.DenyWrite {
		t := filepath.Clean(r.Path)
		if r.Path == "" || t == denyWritePath(r) {
			continue
		}
		top, ok := oracleOutermostWrite(rt, t)
		if !ok {
			continue
		}
		for cur := t; ; cur = filepath.Dir(cur) {
			if !paths[cur] {
				if out == nil {
					out = map[string]bool{}
				}
				out[cur] = true
			}
			if cur == top || cur == "/" {
				break
			}
		}
	}
	for _, e := range exec {
		for _, p := range []string{e.Path, e.Parent} {
			if out[p] {
				delete(out, p)
				paths[p] = true
			}
		}
	}
	return out
}
