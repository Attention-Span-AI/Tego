// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// rowIndex is a table's entries keyed by the paths they are matched under, built once per CompilePlane or FSIndex,
// so that each row's questions cost a walk up its own ancestors instead of a scan over every entry. Every question
// the row compiler asks of an entry is whether one of its (cleaned) spellings is a row's path or an ancestor of it,
// which on a clean path is exactly membership of that spelling in the path's chain of filepath.Dir parents. The
// nearest-wins scans (nearestDeciding, nearestReadDeciding, nestedReadGrant) take the lowest index among the
// entries nearest the path, so a walk from the path upwards that takes the lowest index at the first level with a
// hit answers as they do. Evaluate, FSDecider and RootIndex.Walk keep their scans: they allocate nothing and
// answer one question each. Tier 2's recorder, which asks per event of a table the .env scan can fill with
// 50,000 entries, asks FSIndex, which holds this index and reads it only.
//
// The row paths are clean (FSRule.Canonical, denyWritePath, execPath and their parents); a question that depends on
// a spelling Covers would not clean (a deny_read target or a deny_write path as the covered side) takes the scan
// the index replaces when that spelling is not clean, so an unusual table answers exactly as before.
type rowIndex struct {
	rt *agent.RuleTable
	// at is each spelling's entries: the lowest of each class and the write entries in order.
	at map[string]*spellingEntries
	// unenforced memoizes denyUnenforced by entry: 0 unknown, 1 enforced, 2 unenforced.
	unenforced []uint8
	// writeAskGov is every write and ask entry's cleaned Governed path, what denyUnenforced covers a target by.
	writeAskGov map[string]bool
}

// spellingEntries is the entries matched under one spelling, -1 for none.
type spellingEntries struct {
	named  int   // lowest entry with a declared path, of any kind (FSIndex.nearest)
	decide int   // lowest entry that is not a watch entry (nearestDeciding)
	read   int   // lowest write or deny_read entry (nearestReadDeciding)
	deny   int   // lowest deny_read entry (FSIndex.ListenerOpenRefused)
	writes []int // write entries, ascending (nestedReadGrant)
	all    []int // every entry, ascending (FSIndex.GrantName)
}

// spellingsOf is the keys ruleSteps matches r under: the cleaned declared path and, where given, the cleaned
// resolved one; "." (an empty or relative-dot spelling), which CoverSteps never matches, is left out.
func spellingsOf(r *agent.FSRule) (a, b string) {
	if a = filepath.Clean(r.Path); a == "." {
		a = ""
	}
	if r.Resolved != "" {
		if b = filepath.Clean(r.Resolved); b == "." || b == a {
			b = ""
		}
	}
	return a, b
}

func newRowIndex(rt *agent.RuleTable) *rowIndex {
	x := &rowIndex{rt: rt, at: make(map[string]*spellingEntries, len(rt.FS)), unenforced: make([]uint8, len(rt.FS)),
		writeAskGov: map[string]bool{}}
	for i := range rt.FS {
		r := &rt.FS[i]
		a, b := spellingsOf(r)
		for _, s := range [2]string{a, b} {
			if s == "" {
				continue
			}
			e := x.at[s]
			if e == nil {
				e = &spellingEntries{named: -1, decide: -1, read: -1, deny: -1}
				x.at[s] = e
			}
			if r.Path != "" && e.named < 0 {
				e.named = i
			}
			if r.Kind != agent.FSWatch && e.decide < 0 {
				e.decide = i
			}
			if (r.Kind == agent.FSWrite || r.Kind == agent.FSDenyRead) && e.read < 0 {
				e.read = i
			}
			if r.Kind == agent.FSDenyRead && e.deny < 0 {
				e.deny = i
			}
			if r.Kind == agent.FSWrite {
				e.writes = append(e.writes, i)
			}
			if len(e.all) == 0 || e.all[len(e.all)-1] != i { // an entry's two spellings may be one key
				e.all = append(e.all, i)
			}
		}
		if r.Kind == agent.FSWrite || r.Kind == agent.FSAsk {
			if g := filepath.Clean(r.Governed()); g != "." {
				x.writeAskGov[g] = true
			}
		}
	}
	return x
}

// parent is the next step of a walk up from a clean path cur, false at the top ("/", or a relative path's first
// component, above which CoverSteps matches nothing). On a clean path it is filepath.Dir without Dir's Clean, which
// was a third of the compile.
func parent(cur string) (string, bool) {
	i := strings.LastIndexByte(cur, '/')
	switch {
	case cur == "/" || i < 0:
		return "", false
	case i == 0:
		return "/", true
	}
	return cur[:i], true
}

// cell is rootCell on the index: the answer at p when the entry deciding it names p itself.
func (x *rowIndex) cell(p string, read bool) RootCell {
	e := x.at[p]
	if e == nil {
		return RootCell{Rule: -1}
	}
	rt := x.rt
	if !read {
		// The nearest non-watch entry lies at p when any does, and is then the lowest of them.
		if e.decide < 0 {
			return RootCell{Rule: -1}
		}
		return RootCell{Rule: e.decide, Allow: rt.FS[e.decide].Kind == agent.FSWrite}
	}
	i := e.read
	if i < 0 {
		return RootCell{Rule: -1}
	}
	if rt.FS[i].Kind == agent.FSDenyRead && !x.denyUnenforced(i) {
		if w, steps, ok := x.nestedReadGrant(p, i); ok {
			if steps != 0 {
				return RootCell{Rule: -1} // the reopening write entry lies above p: its own row answers
			}
			return RootCell{Rule: w, Allow: true}
		}
	}
	return RootCell{Rule: i, Allow: rt.FS[i].Kind != agent.FSDenyRead}
}

// nestedReadGrant is nestedReadGrant(rt, p, deny) on the index, with the grant's steps above p.
func (x *rowIndex) nestedReadGrant(p string, deny int) (int, int, bool) {
	return x.nestedReadGrantTo(p, deny, true)
}

// nestedReadGrantTo is nestedReadGrant, bounded to agent.MaxWalk steps or, for the Landlock arm, which bounds no
// depth, not (nestedReadGrant(rt, p, deny, false)).
func (x *rowIndex) nestedReadGrantTo(p string, deny int, bounded bool) (int, int, bool) {
	target := x.rt.FS[deny]
	cur := p
	for steps := 0; !bounded || steps <= agent.MaxWalk; steps++ {
		if e := x.at[cur]; e != nil {
			for _, w := range e.writes {
				r := &x.rt.FS[w]
				if agent.Covers(target.Path, cleanPath(r.Path)) || agent.Covers(target.Governed(), cleanPath(r.Governed())) {
					return w, steps, true
				}
			}
		}
		var ok bool
		if cur, ok = parent(cur); !ok {
			break
		}
	}
	return -1, 0, false
}

// denyUnenforced is denyUnenforced(rt, i), memoized, walking the target's ancestors when it is clean.
func (x *rowIndex) denyUnenforced(i int) bool {
	if m := x.unenforced[i]; m != 0 {
		return m == 2
	}
	r := &x.rt.FS[i]
	var u bool
	switch t := r.Governed(); {
	case r.Unenforced:
		u = true
	case t != filepath.Clean(t):
		u = denyUnenforced(x.rt, i)
	default:
		for cur, ok := t, true; ok && !u; cur, ok = parent(cur) {
			u = x.writeAskGov[cur]
		}
	}
	x.unenforced[i] = 1
	if u {
		x.unenforced[i] = 2
	}
	return u
}

// rows is the root model of the indexed table as rows, one per distinct canonical path an fs entry names, sorted by
// path. A row whose cells both go on still stops the walk's bound: the kernel's 64-step walk counts an entry of any
// kind (Evaluator.root), and a watch entry is attributed where it lies. Each cell is rootCell's answer, asked of the
// index rather than by a scan of the table per row.
func (x *rowIndex) rows() []RootRow {
	rt := x.rt
	named := make(map[string]int, len(rt.FS))
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
		rows = append(rows, RootRow{Path: p, Named: i, Read: x.cell(p, true), Modify: x.cell(p, false)})
	}
	slices.SortFunc(rows, func(a, b RootRow) int {
		switch {
		case a.Path < b.Path:
			return -1
		case a.Path > b.Path:
			return 1
		}
		return 0
	})
	return rows
}

// planeIndex is the rest of what the row compiler asks per row, keyed by path: deny_write targets, exec.allow
// directories and write entries.
type planeIndex struct {
	rt *agent.RuleTable
	// dwAt is the lowest deny_write entry with a spelling at each cleaned path (Covers(t, p)); dwBelow the lowest
	// with a clean spelling at or beneath each path (Covers(p, t)). dwUnclean is the entries with a spelling that
	// is not clean, asked as denyWriteIdx asks them.
	// dwAt holds the built-in targets alone: the fs.deny_write entries at or above a path are asked of user, by nearest
	// wins (ADR 0071); beneath a path (dwBelow, dwUnclean) every target counts, since a rename moves what lies inside.
	dwAt, dwBelow map[string]int
	dwUnclean     []int
	user          *userDenyWrite
	// execDir is the lowest exec.allow directory entry at each path.
	execDir map[string]int
	// writeCanon is every write entry's canonical path (outermostWrite).
	writeCanon map[string]bool
}

func newPlaneIndex(rt *agent.RuleTable) *planeIndex {
	x := &planeIndex{rt: rt, dwAt: map[string]int{}, dwBelow: map[string]int{}, execDir: map[string]int{}, writeCanon: map[string]bool{},
		user: newUserDenyWrite(rt)}
	lowest := func(m map[string]int, k string, j int) {
		if o, ok := m[k]; !ok || j < o {
			m[k] = j
		}
	}
	for j := range rt.DenyWrite {
		r := &rt.DenyWrite[j]
		unclean := false
		for _, t := range [2]string{r.Path, r.Resolved} {
			if t == "" {
				continue
			}
			if c := filepath.Clean(t); c != "." && !r.IsDeclaredDenyWrite() {
				lowest(x.dwAt, c, j)
			}
			if t != filepath.Clean(t) {
				unclean = true
				continue
			}
			for cur, ok := t, true; ok; cur, ok = parent(cur) {
				lowest(x.dwBelow, cur, j)
			}
		}
		if unclean {
			x.dwUnclean = append(x.dwUnclean, j)
		}
	}
	for i := range rt.Exec {
		if r := &rt.Exec[i]; r.IsDir && execPath(r) != "" {
			lowest(x.execDir, execPath(r), i)
		}
	}
	for i := range rt.FS {
		if rt.FS[i].Kind == agent.FSWrite {
			x.writeCanon[rt.FS[i].Canonical()] = true
		}
	}
	return x
}

// denyWriteIdx is RuleTable.DenyWriteTarget as a position for a clean path p: the first target at or above
// p, or, with ancestors (a rename), beneath it; the tests hold it to the scan in planerows_test.go.
func (x *planeIndex) denyWriteIdx(p string, ancestors bool) (int, bool) {
	if rule := x.rt.Builtins.WriteRule(p, ancestors); rule != "" {
		for j, r := range x.rt.DenyWrite {
			if r.BuiltinRule == rule && (agent.Covers(r.Canonical(), p) || ancestors && agent.Covers(p, r.Canonical())) {
				return j, true
			}
		}
	}
	best := -1
	take := func(j int) {
		if best < 0 || j < best {
			best = j
		}
	}
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if j, hit := x.dwAt[cur]; hit {
			if x.rt.DenyWrite[j].BuiltinRule != "" && x.rt.Builtins.OwnPath(p) {
				continue
			}
			take(j)
		}
	}
	if x.user != nil {
		// A rename of the reopening write entry's own name reaches the entry: its row refuses a rename
		// at depth 0, while its modification question, which decides beneath it too, stays the write entry's.
		if j := x.user.nearest(p, ancestors); j >= 0 {
			take(j)
		}
	}
	if ancestors {
		if j, hit := x.dwBelow[p]; hit {
			take(j)
		}
		for _, j := range x.dwUnclean {
			r := &x.rt.DenyWrite[j]
			for _, t := range [2]string{r.Path, r.Resolved} {
				if t != "" && agent.Covers(p, t) {
					take(j)
				}
			}
		}
	}
	return best, best >= 0
}

// execDirAt is the lowest exec.allow directory entry covering the clean path p (under), -1 for none.
func (x *planeIndex) execDirAt(p string) int {
	best := -1
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if i, hit := x.execDir[cur]; hit && (best < 0 || i < best) {
			best = i
		}
	}
	if i, hit := x.execDir["/"]; hit && (best < 0 || i < best) {
		best = i // under("/", p) holds for any p, a relative one too
	}
	return best
}

// outermostWrite is outermostWrite(rt, t) for a clean path t: the highest write entry on t's chain of parents.
func (x *planeIndex) outermostWrite(t string) (string, bool) {
	best := ""
	for cur, ok := t, true; ok; cur, ok = parent(cur) {
		if x.writeCanon[cur] {
			best = cur
		}
	}
	return best, best != ""
}
