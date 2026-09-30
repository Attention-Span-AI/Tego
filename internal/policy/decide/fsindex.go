// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// FSIndex is a RuleTable's fs entries indexed for tier 2's recorder, which asks, for every fs sample it drains,
// which entry names the path (Nearest) and which entries decide a read and a modification of it (NewFSMatch,
// FSDecider). Asked by scan, each question walked every entry, several times per sample: against a table the
// built-in .env scan filled with 50,000 deny_read entries (agent.Compile's envScanMaxEntries, files the agent
// can plant in an earlier run) one sample cost 53–65 ms, so the single drain goroutine fell behind and the ring
// dropped samples. Indexed, each question is a map lookup per ancestor of the path, whatever the number of
// entries (TestFSIndexCostDoesNotGrowWithEntries), with the answers the scans give (TestFSIndexMatchesScans):
// the nearest entry at the first level with a hit, the lowest index among several there (rowIndex).
//
// It is built once and read only, so the drain goroutine reads it without a lock. A table with an entry whose
// declared path is not clean is asked by scan, as rowIndex asks such a spelling, so it answers exactly as before.
type FSIndex struct {
	rt *agent.RuleTable
	x  *rowIndex
	// links is the lowest symlinked entry at each cleaned declared path (Canonical's rewrite).
	links map[string]int
	// scan is set when an entry's declared path is not clean: every question is then the scan's.
	scan bool
	// move answers DenyReadMoveTarget, denyWrite DenyWriteTarget for the built-in targets (targetIndex), userDW for
	// the fs.deny_write entries (nil when the table has none).
	move, denyWrite *targetIndex
	userDW          *userDenyWrite
	// names is the table's name entries (ADR 0043), nil while no mechanism enforces them.
	names *NameIndex
}

// NewFSIndex indexes rt's fs entries. rt nil yields an index that decides nothing.
func NewFSIndex(rt *agent.RuleTable) *FSIndex {
	if rt == nil {
		return nil
	}
	ix := &FSIndex{rt: rt, x: newRowIndex(rt), links: map[string]int{}, move: newTargetIndex(rt.FS, unenforcedDenyRead),
		denyWrite: newTargetIndex(rt.DenyWrite, builtInDenyWrite), userDW: newUserDenyWrite(rt), names: NewNameIndex(rt)}
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Path != "" && filepath.Clean(r.Path) != r.Path {
			ix.scan = true
		}
		if r.Resolved == "" || r.Resolved == r.Path || filepath.Clean(r.Resolved) == filepath.Clean(r.Path) {
			continue
		}
		if _, ok := ix.links[r.Path]; !ok {
			ix.links[r.Path] = i
		}
	}
	// denyUnenforced memoizes into the row index; filled here, so no query writes to it.
	for i := range rt.FS {
		if rt.FS[i].Kind == agent.FSDenyRead {
			ix.x.denyUnenforced(i)
		}
	}
	return ix
}

// Canonical is Canonical(rt, path) on the index: path must be clean.
func (ix *FSIndex) Canonical(path string) string {
	if ix.scan {
		return Canonical(ix.rt, path)
	}
	best := -1
	for cur, ok := path, true; ok; cur, ok = parent(cur) {
		if i, hit := ix.links[cur]; hit {
			best = i
			break
		}
	}
	if best < 0 {
		return path
	}
	r := &ix.rt.FS[best]
	rest := strings.TrimPrefix(path, filepath.Clean(r.Path))
	return filepath.Join(filepath.Clean(r.Resolved), rest)
}

// FSDecider is FSDecider(rt, path, read) on the index.
func (ix *FSIndex) FSDecider(path string, read bool) (*agent.FSRule, bool) {
	if ix == nil || path == "" {
		return nil, false
	}
	if ix.scan {
		return FSDecider(ix.rt, path, read)
	}
	return ix.decider(ix.Canonical(cleanPath(path)), read)
}

// decider is fsDecider on the index, on a clean canonical path.
func (ix *FSIndex) decider(p string, read bool) (*agent.FSRule, bool) {
	i, ok := ix.deciderIndex(p, read)
	if !ok {
		return nil, false
	}
	return &ix.rt.FS[i], true
}

func (ix *FSIndex) deciderIndex(p string, read bool) (int, bool) {
	cur := p
	for steps := 0; steps <= agent.MaxWalk; steps++ {
		if e := ix.x.at[cur]; e != nil {
			if !read && e.decide >= 0 {
				return e.decide, true
			}
			if read && e.read >= 0 {
				i := e.read
				if ix.rt.FS[i].Kind == agent.FSDenyRead && !ix.x.denyUnenforced(i) {
					if w, _, ok := ix.x.nestedReadGrant(p, i); ok {
						return w, true
					}
				}
				return i, true
			}
		}
		var ok bool
		if cur, ok = parent(cur); !ok {
			break
		}
	}
	return -1, false
}

// ListenerOpenRefused is ListenerOpenRefused(rt, path) on the index: the deny_read entry tier 2's fanotify
// listener refuses an open of path by, whatever its mode, and whether one does. Walking up from the path, the
// first level holding a deny_read entry refuses unless a write entry sat at a level below it; a write entry at
// the same level does not reopen it (listenerOpenRefused's strict comparison). No depth bound, as the listener's.
// A path with the unlinked suffix is decided under both spellings, as the listener decides it (unlinkedSpelling).
func (ix *FSIndex) ListenerOpenRefused(path string) (agent.FSRule, bool) {
	if ix == nil || path == "" {
		return agent.FSRule{}, false
	}
	if ix.scan {
		return ListenerOpenRefused(ix.rt, path)
	}
	if r, ok := ix.listenerOpenRefused(path); ok {
		return r, true
	}
	if s, ok := unlinkedSpelling(path); ok {
		return ix.listenerOpenRefused(s)
	}
	return agent.FSRule{}, false
}

// listenerOpenRefused is ListenerOpenRefused of one spelling on the index.
func (ix *FSIndex) listenerOpenRefused(path string) (agent.FSRule, bool) {
	for cur, ok := ix.Canonical(cleanPath(path)), true; ok; cur, ok = parent(cur) {
		e := ix.x.at[cur]
		if e == nil {
			continue
		}
		if e.deny >= 0 {
			return ix.rt.FS[e.deny], true
		}
		if len(e.writes) > 0 {
			return agent.FSRule{}, false
		}
	}
	return agent.FSRule{}, false
}

// HasNames reports whether the index answers name questions: the table has name entries. The supervisor stats a
// rename's source only then.
func (ix *FSIndex) HasNames() bool { return ix != nil && ix.names != nil }

// NameRefused is the name entries' answer for a file at the canonical path p that the walk allowed (ADR 0043 D1):
// refused, with reason, when an entry covers it, named per D8 (the deny_read entry at the path, else the entry's own
// rule), or refused path-unresolved, named unmatched, when the climb cannot decide within the walk's bound, as
// Evaluator.root refuses both. A directory is never asked (D1). It is what the supervisor's advisory verdict asks at
// tier cgroup (AdvisoryFS) and what an approval's completion asks of the held file (ADR 0043 interface 2). It
// allocates nothing.
func (ix *FSIndex) NameRefused(p string, reason record.Reason) (rule string, why record.Reason, refused bool) {
	if ix == nil {
		return "", "", false
	}
	return nameRefused(ix.names, p, reason, ix.denyAt)
}

// nameRefused is NameRefused over n, asking denyAt for the deny_read entry at p only once an entry covers it.
func nameRefused(n *NameIndex, p string, reason record.Reason, denyAt func(string) int) (rule string, why record.Reason, refused bool) {
	m, ok := n.Match(p, false)
	if !ok {
		return "", "", false
	}
	if m.Unresolved {
		return agent.UnmatchedRule, record.ReasonPathUnresolved, true
	}
	return n.Rule(m, denyAt(p)), reason, true
}

// NameMoveRefused is ADR 0043 D5 at tier cgroup, the supervisor's R15d beside DenyReadMoveTarget (interface 1): a
// rename of a directory from src to dst, the canonical ends, that takes a file out of a name entry's coverage
// (NameIndex.MoveRefused) is refused rename-outside-contract, named by the entry's own rule, or path-unresolved,
// named unmatched, when a climb cannot decide. dir is whether the moved object is a directory: a file is decided at
// both ends' names (NameRefused), never here. ADR 0043 named the result (rule, refused); the reason is returned too,
// since a climb the bound stops refuses under another one.
func (ix *FSIndex) NameMoveRefused(src, dst string, dir bool) (rule string, reason record.Reason, refused bool) {
	if ix == nil || !dir {
		return "", "", false
	}
	m, refused := ix.names.MoveRefused(src, dst)
	if !refused {
		return "", "", false
	}
	r := nameMoveRefusal(ix.names, m)
	return r.Rule, r.Reason, true
}

// DenyReadAt is the first deny_read entry whose canonical path is p, and whether there is one: what a name refusal of
// the file at p is named by (ADR 0043 D8's first choice), an expansion entry compaction may have dropped from the
// plane's rows, which the recorder names the kernel's refusal by.
func (ix *FSIndex) DenyReadAt(p string) (agent.FSRule, bool) {
	if ix == nil {
		return agent.FSRule{}, false
	}
	if i := ix.denyAt(p); i >= 0 {
		return ix.rt.FS[i], true
	}
	return agent.FSRule{}, false
}

// ListenerOpenName is ListenerOpenName on the index's name entries: whether tier 2's fanotify listener refuses an
// open of the canonical path by a name entry, with the rule and reason its line carries. Nothing is refused while no
// mechanism enforces names.
func (ix *FSIndex) ListenerOpenName(path string) (rule string, reason record.Reason, refused bool) {
	if ix == nil {
		return "", "", false
	}
	return ListenerOpenName(ix.names, path)
}

// denyAt is the first deny_read entry at the canonical path p, -1 for none (NameIndex.Rule's first choice).
func (ix *FSIndex) denyAt(p string) int {
	if ix.scan {
		return denyAtScan(ix.rt, p)
	}
	if row := ix.x.at[p]; row != nil && row.deny >= 0 && ix.rt.FS[row.deny].Canonical() == p {
		return row.deny
	}
	return -1
}

// ExecReadGrant is ExecReadGrant(rt, path) on the index: the nearest enforced deny_read entry of the canonical
// path, unbounded as Landlock's walk is, then the exec entry that reopens it. The exec entries are scanned: they
// are the contract's own, not the .env scan's.
func (ix *FSIndex) ExecReadGrant(path string) (*agent.ExecRule, bool) {
	if ix == nil || path == "" {
		return nil, false
	}
	if ix.scan {
		return ExecReadGrant(ix.rt, path)
	}
	p := ix.Canonical(cleanPath(path))
	deny := -1
	for cur, ok := p, true; ok && deny < 0; cur, ok = parent(cur) {
		if e := ix.x.at[cur]; e != nil {
			deny = e.deny
		}
	}
	if deny < 0 || ix.x.denyUnenforced(deny) {
		return nil, false
	}
	if _, _, ok := ix.x.nestedReadGrantTo(p, deny, false); ok {
		return nil, false
	}
	if x, ok := execReadGrant(ix.rt, p, deny); ok {
		return &ix.rt.Exec[x], true
	}
	return nil, false
}

// RenameGains is REFER's no-gain rule on a rename, on the index with the table's exec grants: ReferRefuses of
// RenameGained.
func (ix *FSIndex) RenameGains(src, dst string, dir bool) bool {
	return ReferRefuses(ix.RenameGained(src, dst), dir)
}

// RenameGained is RenameGainedBy on the index with the table's exec grants (ExecGrantAt): the rights the ruleset
// grants at a path are the union over the entries at each ancestor of its landed end (landlockUnion).
func (ix *FSIndex) RenameGained(src, dst string) agent.AccessSet {
	return ix.RenameGainedBy(src, dst, nil)
}

// RenameGainedBy is RenameGainedBy(rt, src, dst, exec) on the index.
func (ix *FSIndex) RenameGainedBy(src, dst string, exec ExecGrants) agent.AccessSet {
	if ix == nil || src == "" || dst == "" {
		return 0
	}
	if ix.scan {
		return RenameGainedBy(ix.rt, src, dst, exec)
	}
	return referGained(landedEnd(src), landedEnd(dst), ix.rights(exec))
}

// LinkGains is LinkGainsBy on the index with the table's exec grants (ExecGrantAt).
func (ix *FSIndex) LinkGains(src, dst string) bool {
	return ix.LinkGainsBy(src, dst, nil)
}

// LinkGainsBy is LinkGainsBy(rt, src, dst, exec) on the index.
func (ix *FSIndex) LinkGainsBy(src, dst string, exec ExecGrants) bool {
	if ix == nil || src == "" || dst == "" {
		return false
	}
	if ix.scan {
		return LinkGainsBy(ix.rt, src, dst, exec)
	}
	return linkGains(landedEnd(src), landedEnd(dst), ix.rights(exec))
}

// LandlockRenameRefusal is LandlockRenameRefusal(rt, src, dst, dir) on the index.
func (ix *FSIndex) LandlockRenameRefusal(src, dst string, dir bool) (rule string, refused bool) {
	return ix.LandlockRenameRefusalBy(src, dst, dir, nil)
}

// LandlockRenameRefusalBy is LandlockRenameRefusal on the index with the exec grants' rights from exec (nil: their
// table's, ExecGrantAt), as LandlockLinkRefusalBy.
func (ix *FSIndex) LandlockRenameRefusalBy(src, dst string, dir bool, exec ExecGrants) (rule string, refused bool) {
	if ix == nil || src == "" || dst == "" {
		return agent.UnmatchedRule, false
	}
	if ix.scan {
		return (&Evaluator{rt: ix.rt, exec: exec}).landlockRename(landedEnd(src), landedEnd(dst), dir, false)
	}
	return (&Evaluator{rt: ix.rt, fs: ix, exec: exec}).landlockRename(landedEnd(src), landedEnd(dst), dir, false)
}

// rights is the ruleset's rights at an end on the index: landlockUnion, or the write entries' with exec's.
func (ix *FSIndex) rights(exec ExecGrants) func(string) agent.AccessSet {
	if exec == nil {
		return ix.landlockUnion
	}
	return func(p string) agent.AccessSet { return ix.landlockFSUnion(p) | exec(p) }
}

// landlockUnion is landlockRights(rt, p) on the index: what the Landlock ruleset grants through the entries at each
// ancestor of the clean canonical end p, with the exec entries' grants, which are scanned (the contract's own, not the
// .env scan's).
func (ix *FSIndex) landlockUnion(p string) agent.AccessSet {
	return ix.landlockFSUnion(p) | landlockExecGrant(ix.rt, p)
}

// landlockFSUnion is landlockFSRights(rt, p) on the index: a symlinked entry is not counted at its own declared name.
func (ix *FSIndex) landlockFSUnion(p string) agent.AccessSet {
	var union agent.AccessSet
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if e := ix.x.at[cur]; e != nil {
			for _, i := range e.all {
				if cur == p && symlinkName(&ix.rt.FS[i], p) {
					continue
				}
				union |= landlockGrant(ix.rt, &ix.rt.FS[i])
			}
		}
	}
	return union
}

// accessUnion is the union of the rights every entry covering the clean path p grants (accessAt's first half).
func (ix *FSIndex) accessUnion(p string) agent.AccessSet {
	var union agent.AccessSet
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if e := ix.x.at[cur]; e != nil {
			for _, i := range e.all {
				union |= ix.rt.FS[i].Access
			}
		}
	}
	return union
}

// GrantName is GrantName(rt, op, path) on the index: the nearest entry granting the right op needs, the lowest
// position among several at one level.
func (ix *FSIndex) GrantName(op, path string) (string, bool) {
	if ix == nil || path == "" {
		return "", false
	}
	if ix.scan {
		return GrantName(ix.rt, op, path)
	}
	kind := grantKind(op)
	var at string
	if kind == agent.ActionFSDelete || kind == agent.ActionFSRename {
		at = filepath.Dir(ix.canonicalEnd(cleanPath(path)))
	} else {
		at = ix.Canonical(cleanPath(path))
	}
	need := fsAccess(kind)
	for cur, ok := at, true; ok; cur, ok = parent(cur) {
		e := ix.x.at[cur]
		if e == nil {
			continue
		}
		for _, i := range e.all {
			if ix.rt.FS[i].Access.Has(need) {
				return ix.rt.FS[i].RuleName(), true
			}
		}
	}
	return "", false
}

// EvaluateExec is Evaluate(rt, a, tier) for an exec action, with the reads the exec's opens are asked of the index
// in the root tiers (execRead). A nil index is a nil table's answer.
func (ix *FSIndex) EvaluateExec(a agent.Action, tier backend.Tier) agent.EvalResult {
	if ix == nil {
		return invalidAction()
	}
	if a.Kind != agent.ActionExec {
		return Evaluate(ix.rt, a, tier)
	}
	if tier == "" || tier == backend.TierAuto || !tier.Valid() {
		tier = ix.rt.Tier
	}
	return evalExec(ix.rt, ix, a, tier)
}

// evalRootRead is Evaluator.root's answer for a read of the clean canonical path p, on the index.
func (ix *FSIndex) evalRootRead(p string) agent.EvalResult {
	return (&Evaluator{rt: ix.rt, fs: ix}).root(agent.ActionFSRead, p, objFile)
}

// nearestAny is nearestFS on the index: the lowest entry of any kind at the first level above p, p included, that
// holds one, and how many steps above p it sits.
func (ix *FSIndex) nearestAny(p string) (idx, steps int, ok bool) {
	for cur, more := p, true; more; cur, more = parent(cur) {
		if e := ix.x.at[cur]; e != nil && len(e.all) > 0 {
			return e.all[0], steps, true
		}
		steps++
	}
	return -1, 0, false
}

// Nearest is the entry naming path, the nearest entry of any kind with a declared path, and its position in
// rt.FS: the entry at path itself or the one at its nearest ancestor, matched by each entry's declared and
// resolved spelling (agent.FSRule.Spellings), the lowest position among several at one path; false when none
// covers path. It bounds no depth, as naming does not (§7).
func (ix *FSIndex) Nearest(path string) (int, bool) {
	if ix == nil || path == "" {
		return -1, false
	}
	if ix.scan || path != filepath.Clean(path) {
		return nearestNamed(ix.rt, path)
	}
	for cur, ok := path, true; ok; cur, ok = parent(cur) {
		if e := ix.x.at[cur]; e != nil && e.named >= 0 {
			return e.named, true
		}
	}
	return -1, false
}

// nearestNamed is Nearest by scan: the covering spelling that is longest, the lowest position among several.
func nearestNamed(rt *agent.RuleTable, path string) (int, bool) {
	best, bestLen := -1, -1
	for i := range rt.FS {
		r := &rt.FS[i]
		if r.Path == "" {
			continue
		}
		for _, s := range [2]string{r.Path, r.Resolved} {
			if s == "" {
				continue
			}
			if c := filepath.Clean(s); len(c) > bestLen && agent.Covers(c, path) {
				best, bestLen = i, len(c)
			}
		}
	}
	return best, best >= 0
}

// NewFSMatch is the match of path whose nearest entry is entry, named name, with the entries of the indexed
// table that decide a read and a modification of it (FSDecider's answers, asked of the index).
func (ix *FSIndex) NewFSMatch(path, name string, entry *agent.FSRule) FSMatch {
	m := FSMatch{Rule: name, Entry: entry, Watched: entry.Kind == agent.FSWatch, Path: path}
	if ix != nil {
		if r, ok := ix.FSDecider(path, true); ok {
			m.Read = r
			m.DenyRead = r.Kind == agent.FSDenyRead
		}
		if w, ok := ix.FSDecider(path, false); ok {
			m.Write = w
		}
	}
	return m
}

// InferFS is InferFS(rt, op, write, m) on the index.
func (ix *FSIndex) InferFS(op string, write bool, m FSMatch) (record.Verdict, record.Reason) {
	if ix == nil {
		return InferFS(nil, op, write, m)
	}
	return inferFS(ix.rt, op, write, m, ix)
}
