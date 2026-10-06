// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Evaluator is the reusable, read-only query model of one compiled RuleTable.
// Construct it once per immutable table; replacement tables need a new model.
// Evaluate remains the compatibility/reference entry point for mutable hand-built
// tables. No global pointer cache can silently keep a stale model alive.
type Evaluator struct {
	rt                                           *agent.RuleTable
	fs                                           *FSIndex
	names, unenforced, execNames, denyWriteNames []string
	// nm is the reference path's name index (an Evaluator with no FSIndex), built on first use; an indexed
	// Evaluator reads its FSIndex's.
	nm      *NameIndex
	nmBuilt bool
	// exec is the exec grants' rights by identity a producer supplied for REFER's no-gain rule (HeldExecGrants),
	// nil for the table's (ExecGrantAt): compile --test's answer.
	exec ExecGrants
	// held is the held-read floor (ADR 0069), built on the first read asked at a tier that holds reads.
	held *HeldReadIndex
}

// NewEvaluator builds the query indexes and rule labels outside the query path.
func NewEvaluator(rt *agent.RuleTable) *Evaluator {
	e := &Evaluator{rt: rt, fs: NewFSIndex(rt)}
	if rt == nil {
		return e
	}
	for _, r := range rt.FS {
		name := r.RuleName()
		e.names = append(e.names, name)
		e.unenforced = append(e.unenforced, name+agent.UnenforcedSuffix)
	}
	for _, r := range rt.Exec {
		e.execNames = append(e.execNames, r.RuleName())
	}
	for _, r := range rt.DenyWrite {
		e.denyWriteNames = append(e.denyWriteNames, r.RuleName())
	}
	return e
}

// Evaluate answers using the indexed model. Clean ordinary filesystem paths
// allocate nothing; normalizing an unclean/alias spelling remains the caller's
// explicit path normalization, as in the compatibility entry point.
//
// An Adjustable table's allowed action a fence entry reaches is named after that entry (fenceNamed), as Evaluate
// names it.
func (e *Evaluator) Evaluate(a agent.Action, tier backend.Tier) agent.EvalResult {
	if e == nil || e.rt == nil {
		return invalidAction()
	}
	return fenceNamed(e.rt, a, e.evaluate(a, tier))
}

// evaluate is Evaluate before the fence naming.
func (e *Evaluator) evaluate(a agent.Action, tier backend.Tier) agent.EvalResult {
	rt := e.rt
	if tier == "" || tier == backend.TierAuto || !tier.Valid() {
		tier = rt.Tier
	}
	if e.fs != nil && e.fs.scan {
		return Evaluate(rt, a, tier)
	}
	switch a.Kind {
	case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir:
		if a.Path == "" {
			return invalidAction()
		}
		if a.Kind == agent.ActionFSDelete {
			return e.evaluateFS(a.Kind, e.canonicalEnd(cleanPath(a.Path)), tier, objectOf(a))
		}
		p := e.canonical(cleanPath(a.Path))
		res := e.evaluateFS(a.Kind, p, tier, objectOf(a))
		// Evaluate's held-read floor (ADR 0069), on the same canonical path.
		if a.Kind == agent.ActionFSRead && res.Verdict == agent.VerdictAllow && rt.ReadsHeldAt(tier) {
			if e.held == nil {
				e.held = NewHeldReadIndex(rt)
			}
			if rule, refused := e.held.Refusal(nil, p, a.Dir); refused {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonReadDenied}
			}
		}
		return res
	case agent.ActionFSRename:
		if a.Path == "" || a.DestPath == "" {
			return invalidAction()
		}
		src, dst := e.canonicalEnd(cleanPath(a.Path)), e.canonicalEnd(cleanPath(a.DestPath))
		obj := objectOf(a)
		if tier == backend.TierCgroup && e.fs.move.scan {
			return Evaluate(rt, a, tier)
		}
		if tier == backend.TierCgroup {
			if i := e.fs.move.lookup(src, true); i >= 0 {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: e.name(i), Reason: record.ReasonRenameOutsideContract}
			}
			if m, refused := e.fs.names.MoveRefused(src, dst); refused && obj == objDir {
				return nameMoveRefusal(e.fs.names, m)
			}
		}
		if r := e.evaluateFS(a.Kind, src, tier, obj); r.Verdict != agent.VerdictAllow {
			return r
		}
		if r := e.evaluateFS(a.Kind, dst, tier, obj); r.Verdict != agent.VerdictAllow {
			return r
		}
		if tier == backend.TierObserve {
			return e.observe(src)
		}
		name := e.endName(src, tier == backend.TierBPFLSM)
		// Tiers 1 and 2: the Landlock ruleset's rights, compared as hook_path_rename compares them (evalRename);
		// tier 3: the rows' rights at the ends, with the ruleset as the floor below.
		var refused bool
		if tier == backend.TierBPFLSM {
			refused = e.fs.accessUnion(dst)&^e.fs.accessUnion(src) != 0
		} else {
			refused = ReferRefuses(referGained(src, dst, e.fs.landlockUnion), obj == objDir)
		}
		if refused {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: record.ReasonRenameOutsideContract}
		}
		if tier == backend.TierBPFLSM && obj == objDir {
			if m, refused := e.fs.names.MoveRefused(src, dst); refused {
				return nameMoveRefusal(e.fs.names, m)
			}
		}
		// Tier 3's Landlock floor (evalRename).
		if tier == backend.TierBPFLSM {
			if rule, refused := e.landlockRename(src, dst, obj == objDir, true); refused {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonRenameOutsideContract}
			}
		}
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
	case agent.ActionExec:
		return ExecCommandRow(rt, a, e.fs.EvaluateExec(a, tier), tier)
	}
	return Evaluate(rt, a, tier)
}

// EvaluateIn includes the same explicit resolver exception as EvaluateIn.
func (e *Evaluator) EvaluateIn(a agent.Action, tier backend.Tier, env Env) agent.EvalResult {
	if e != nil && e.rt != nil && resolverAction(a, env) {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.ResolverRule}
	}
	return e.Evaluate(a, tier)
}

func (e *Evaluator) nearestName(p string, bounded bool) string {
	if i, steps, ok := e.nearest(p); ok && (!bounded || steps <= agent.MaxWalk) {
		return e.name(i)
	}
	return agent.UnmatchedRule
}

func (e *Evaluator) observe(p string) agent.EvalResult {
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.nearestName(p, true)}
}

// evaluateFS is evalFS on the index, with the same floor for a read an absent built-in row's ungranted name refuses
// (absentReadFloor).
func (e *Evaluator) evaluateFS(kind agent.ActionKind, p string, tier backend.Tier, obj fsObject) agent.EvalResult {
	return absentReadFloor(e.rt, kind, p, tier, e.evaluateFSTier(kind, p, tier, obj))
}

func (e *Evaluator) evaluateFSTier(kind agent.ActionKind, p string, tier backend.Tier, obj fsObject) agent.EvalResult {
	if tier == backend.TierObserve {
		return e.observe(p)
	}
	if kind != agent.ActionFSRead {
		rename := kind == agent.ActionFSRename
		if i, scan := e.fs.denyWritePos(p, rename, rename || kind == agent.ActionFSMkdir); scan {
			if r, ok := evalDenyWrite(e.fs.rt, kind, p); ok {
				return r
			}
		} else if i >= 0 {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: e.denyWriteNames[i], Reason: agent.FSReason(kind)}
		}
	}
	if tier == backend.TierLandlock || (tier == backend.TierCgroup && kind != agent.ActionFSRead) {
		if tier == backend.TierCgroup && kind == agent.ActionFSWrite {
			for cur, ok := p, true; ok; cur, ok = parent(cur) {
				if row := e.fs.x.at[cur]; row != nil {
					if row.deny >= 0 {
						return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: e.names[row.deny], Reason: record.ReasonReadDenied}
					}
					if len(row.writes) > 0 {
						break
					}
				}
			}
			if r, refused := listenerNameRefused(e.fs.names, p, obj, e.denyAt(p)); refused {
				return r
			}
		}
		if tier == backend.TierCgroup {
			if r := e.root(kind, p, obj); r.Verdict != agent.VerdictAllow {
				return r
			}
		}
		return e.landlock(kind, p)
	}
	r := e.root(kind, p, obj)
	// Tier 3's Landlock floor under the plane's unlink and rmdir hooks (evalFS).
	if kind == agent.ActionFSDelete && r.Verdict == agent.VerdictAllow {
		if l, refused := e.landlockDelete(p); refused {
			return l
		}
	}
	return r
}

// root is the root tiers' answer (root.go's rule): the nearest-wins walk, then, where the walk allows the question, the
// name entries (ADR 0043 D1: a name entry decides only what the walk allows): a file one covers is refused as a
// deny_read entry at its own path would refuse it, read-denied for a read and the hook's reason for a modification,
// named per D8 (NameIndex.Rule); a climb that cannot decide is refused path-unresolved.
//
// p may be an end a rename, a link or an unlink acts on without following it (canonicalEnd) that is a symlinked entry's
// own declared name: the symlink, on which no rule is (symlinkName). The walk then starts at its directory, a step
// above p, as the plane's hooks walk the symlink's dentry.
func (e *Evaluator) root(kind agent.ActionKind, p string, obj fsObject) agent.EvalResult {
	at, extra := p, 0
	if e.ownSymlinkOnly(p) {
		at, extra = filepath.Dir(p), 1
	}
	ni, steps, ok := e.nearest(at)
	steps += extra
	name := agent.UnmatchedRule
	if ok {
		name = e.name(ni)
	}
	i, hit := e.decider(at, kind == agent.ActionFSRead)
	if hit && extra > 0 {
		if n, _ := ruleSteps(e.rt.FS[i], at); n+extra > agent.MaxWalk {
			hit = false
		}
	}
	var d fsDecision
	if hit {
		d = fsDecision{e.name(i), e.rt.FS[i].Kind}
	}
	r := rootAnswer(p, name, steps, ok, d, hit, kind == agent.ActionFSRead, agent.FSReason(kind))
	nm := e.nameIndex()
	if r.Verdict != agent.VerdictAllow || obj != objFile || nm == nil {
		return r
	}
	if rule, why, refused := nameRefused(nm, p, agent.FSReason(kind), e.denyAt); refused {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: why}
	}
	return r
}

// nameIndex is the table's name index: the FSIndex's, or, on the reference path, one built for this Evaluator.
func (e *Evaluator) nameIndex() *NameIndex {
	if e.fs != nil {
		return e.fs.names
	}
	if !e.nmBuilt {
		e.nm, e.nmBuilt = newNameIndex(e.rt), true
	}
	return e.nm
}

// denyAt is the first deny_read entry at the canonical path p, -1 for none (NameIndex.Rule's first choice).
func (e *Evaluator) denyAt(p string) int {
	if e.fs == nil {
		return denyAtScan(e.rt, p)
	}
	return e.fs.denyAt(p)
}

type fsDecision struct {
	name string
	kind agent.FSKind
}

// rootAnswer is the root model's verdict over indexed or advisory lookup
// evidence. Both views keep their own authentic pathname basis and share the
// walk bound, read asymmetry and nearest mutation decision.
func rootAnswer(p, name string, steps int, named bool, d fsDecision, hit, read bool, reason record.Reason) agent.EvalResult {
	if (named && steps > agent.MaxWalk) || (!named && pathDepth(p) > agent.MaxWalk) {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
	}
	if !hit {
		if read {
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
		}
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: reason}
	}
	if read {
		if d.kind == agent.FSDenyRead {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: d.name, Reason: record.ReasonReadDenied}
		}
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
	}
	if d.kind == agent.FSWrite {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: d.name}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: d.name, Reason: reason}
}

func (e *Evaluator) landlock(kind agent.ActionKind, p string) agent.EvalResult {
	if kind == agent.ActionFSRead {
		if i, ok := e.deny(p); ok {
			if e.denyUnenforced(i) {
				return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.unenforcedName(i)}
			}
			if w, ok := e.nestedGrant(p, i); ok {
				return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.name(w)}
			}
			if x, ok := execReadGrant(e.rt, p, i); ok {
				return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.execName(x)}
			}
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: e.name(i), Reason: record.ReasonReadDenied}
		}
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.nearestName(p, false)}
	}
	at := p
	if kind == agent.ActionFSDelete || kind == agent.ActionFSRename || kind == agent.ActionFSLink {
		at = filepath.Dir(p)
	}
	if i, ok := e.grant(at, fsAccess(kind)); ok {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: e.name(i)}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: e.nearestName(at, false), Reason: agent.FSReason(kind)}
}

// These lookups select the indexed compiled model or the mutable-table adapter.
// The tier decision bodies above are shared; the legacy scans are no separate
// implementation of a verdict and remain useful independent index oracles.
func (e *Evaluator) canonical(p string) string {
	if e.fs == nil {
		return Canonical(e.rt, p)
	}
	return e.fs.Canonical(p)
}

// ownSymlinkOnly reports whether every entry at the clean path p itself is a symlinked entry by its own declared name
// (symlinkName), and one is: p names the symlink, not any entry.
func (e *Evaluator) ownSymlinkOnly(p string) bool {
	if e.fs == nil {
		any := false
		for i := range e.rt.FS {
			if n, ok := ruleSteps(e.rt.FS[i], p); ok && n == 0 {
				if !symlinkName(&e.rt.FS[i], p) {
					return false
				}
				any = true
			}
		}
		return any
	}
	if len(e.fs.links) == 0 {
		return false
	}
	row := e.fs.x.at[p]
	if row == nil || len(row.all) == 0 {
		return false
	}
	for _, i := range row.all {
		if !symlinkName(&e.rt.FS[i], p) {
			return false
		}
	}
	return true
}
func (e *Evaluator) canonicalEnd(p string) string {
	if e.fs == nil {
		return canonicalEnd(e.rt, p)
	}
	return e.fs.canonicalEnd(p)
}
func (e *Evaluator) name(i int) string {
	if e.names == nil {
		return e.rt.FS[i].RuleName()
	}
	return e.names[i]
}
func (e *Evaluator) unenforcedName(i int) string {
	if e.unenforced == nil {
		return e.name(i) + agent.UnenforcedSuffix
	}
	return e.unenforced[i]
}
func (e *Evaluator) execName(i int) string {
	if e.execNames == nil {
		return e.rt.Exec[i].RuleName()
	}
	return e.execNames[i]
}
func (e *Evaluator) nearest(p string) (int, int, bool) {
	if e.fs == nil {
		return nearestFS(e.rt, p)
	}
	return e.fs.nearestAny(p)
}
func (e *Evaluator) decider(p string, read bool) (int, bool) {
	if e.fs == nil {
		return fsDecider(e.rt, p, read)
	}
	return e.fs.deciderIndex(p, read)
}
func (e *Evaluator) deny(p string) (int, bool) {
	if e.fs == nil {
		return nearestFSOfKind(e.rt, p, agent.FSDenyRead)
	}
	for cur, ok := p, true; ok; cur, ok = parent(cur) {
		if row := e.fs.x.at[cur]; row != nil && row.deny >= 0 {
			return row.deny, true
		}
	}
	return -1, false
}
func (e *Evaluator) denyUnenforced(i int) bool {
	if e.fs == nil {
		return denyUnenforced(e.rt, i)
	}
	return e.fs.x.denyUnenforced(i)
}
func (e *Evaluator) nestedGrant(p string, i int) (int, bool) {
	if e.fs == nil {
		return nestedReadGrant(e.rt, p, i, false)
	}
	w, _, ok := e.fs.x.nestedReadGrantTo(p, i, false)
	return w, ok
}
func (e *Evaluator) grant(p string, need agent.AccessSet) (int, bool) {
	if e.fs == nil {
		return nearestGrant(e.rt, p, need)
	}
	for cur, more := p, true; more; cur, more = parent(cur) {
		if row := e.fs.x.at[cur]; row != nil {
			for _, i := range row.all {
				if e.rt.FS[i].Access.Has(need) {
					return i, true
				}
			}
		}
	}
	return -1, false
}
