// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/policy/httppolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Evaluate reports the verdict a compiled table gives a hypothetical action in
// one tier, as `compile --test` uses it (R15). It is pure: no I/O, no kernel
// call, no filesystem probe — a write path that does not exist yet evaluates
// as declared (§6 E19).
//
// The tier is simulated, not checked: the caller passes the tier the table was
// compiled for (R33) and Evaluate runs that tier's own resolution — the root
// tiers' nearest-ancestor walk, or Landlock's union with the unenforced
// deny_read rule (SEMANTICS §2). An empty, "auto" or unknown tier falls back
// to rt.Tier, which Compile always resolved.
//
// There is no error return (§4): an Action malformed for its Kind yields
// EvalResult{Verdict: refused, Rule: invalid-action}, so a table reports every
// row instead of aborting on one.
//
// A read at a tier whose runs hold their reads (agent.RuleTable.ReadsHeldAt, ADR 0069) that the tier's own
// mechanisms allow is put to the held-read floor too (HeldReadIndex.Refusal), which the supervisor applies to the
// object the open deputy reached.
func Evaluate(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	return evaluate(rt, a, tier, true)
}

// LandlockRuleset is how the run's Landlock ruleset alone answers a: Evaluate's tier landlock column without the
// held-read floor, which the supervisor applies on top of the ruleset. It is what a tier 2 reader asks of the ruleset
// it inherits (the supervisor's listenerRefuses, the kernel recorder's listenerRefused).
func LandlockRuleset(rt *agent.RuleTable, a agent.Action) agent.EvalResult {
	return evaluate(rt, a, backend.TierLandlock, false)
}

// evaluate is evaluateTable with an Adjustable table's fence naming: an allowed action a fence entry reaches (read,
// exec or TCP connect, agent.LiveTable.For) is named after that entry, live.fence[<kind>:<value>], whatever contract
// rule matched it, since it is allowed only once the entry is lifted (ADR 0125 decision 9). A Locked table (no
// RuleTable.Live) is answered exactly as before.
func evaluate(rt *agent.RuleTable, a agent.Action, tier backend.Tier, held bool) agent.EvalResult {
	return fenceNamed(rt, a, evaluateTable(rt, a, tier, held))
}

// fenceNamed names res after the fence entry a reaches when rt is Adjustable and res allows a (evaluate). Evaluate and
// Evaluator.Evaluate both answer through it, so the two models name the same action alike.
func fenceNamed(rt *agent.RuleTable, a agent.Action, res agent.EvalResult) agent.EvalResult {
	if res.Verdict != agent.VerdictAllow || !rt.Adjustable() {
		return res
	}
	if a.Kind == agent.ActionFSRead && a.Path != "" {
		a.Path = Canonical(rt, cleanPath(a.Path))
	}
	if e, ok := rt.Live.For(a); ok {
		res.Rule = e.Rule()
	}
	return res
}

func evaluateTable(rt *agent.RuleTable, a agent.Action, tier backend.Tier, held bool) agent.EvalResult {
	if rt == nil {
		return invalidAction()
	}
	if tier == "" || tier == backend.TierAuto || !tier.Valid() {
		tier = rt.Tier
	}
	switch a.Kind {
	case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir:
		if a.Path == "" {
			return invalidAction()
		}
		if a.Kind == agent.ActionFSDelete {
			// unlink(2) and rmdir(2) remove the name itself, never following a final symlink (canonicalEnd).
			return evalFS(rt, a.Kind, canonicalEnd(rt, cleanPath(a.Path)), tier, objectOf(a))
		}
		p := Canonical(rt, cleanPath(a.Path))
		res := evalFS(rt, a.Kind, p, tier, objectOf(a))
		if held && a.Kind == agent.ActionFSRead && res.Verdict == agent.VerdictAllow && rt.ReadsHeldAt(tier) {
			if rule, refused := NewHeldReadIndex(rt).Refusal(nil, p, a.Dir); refused {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonReadDenied}
			}
		}
		return res
	case agent.ActionFSRename:
		return evalRename(rt, a, tier)
	case agent.ActionExec:
		return ExecCommandRow(rt, a, evalExec(rt, nil, a, tier), tier)
	case agent.ActionNetConnect:
		return evalNet(rt, a, tier, false)
	case agent.ActionNetBind:
		return evalBind(rt, a, tier)
	case agent.ActionNetHTTP:
		if a.Host == "" || a.Port < 1 || a.Port > 65535 || rt.HTTP == nil || tier == backend.TierObserve {
			return invalidAction()
		}
		rule, allow, err := rt.HTTP.Match(httppolicy.Authority(agent.CanonicalHost(a.Host), a.Port), a.Method, a.Path)
		if err != nil {
			return invalidAction()
		}
		if allow {
			return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rule}
		}
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonNetHTTP}
	case agent.ActionMapExec:
		return evalMap(rt, a, tier)
	case agent.ActionFSLink:
		return evalLink(rt, a, tier)
	case agent.ActionFSAttr:
		return evalAttr(rt, a, tier)
	case agent.ActionNetSocket:
		return evalSocket(rt, a, tier)
	case agent.ActionNetSend:
		return evalSend(rt, a, tier)
	case agent.ActionExecAnon:
		return evalExecAnon(rt, tier)
	}
	return invalidAction()
}

// invalidAction is the verdict of an Action that describes nothing evaluable.
func invalidAction() agent.EvalResult {
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.InvalidActionRule}
}

// cleanPath normalizes an action path. A relative path is cleaned but never
// resolved against a working directory: Compile already resolved every entry
// (E28) and this package makes no syscall (I6), so the caller supplies an
// absolute path — LoadTestTable does that for a table's rows.
func cleanPath(p string) string { return filepath.Clean(p) }

// evalFS answers one non-rename filesystem action in the tier's own semantics
// (R15).
//
// Unlike net: and exec:, an absent fs: section has no unrestricted reading
// here: it compiles no write entry (R6), so a mutation is refused in every
// enforcing tier exactly as under fs: {}. That is SEMANTICS §1 as amended —
// Landlock cannot leave writes open while keeping the implicit entries (the
// run directory, the contract file) unwritable, and the root tiers' walk
// refuses what no entry covers.
//
// A modification that reaches a built-in deny_write target is refused in every enforcing tier before the
// tier's own rule is asked (evalDenyWrite): beneath a write entry that rule would allow it, and the
// target's refusal is what the run records.
//
// At the root tiers a name entry (ADR 0043) decides what the walk allows of a file it covers (Evaluator.root);
// obj says whether the object is one it may decide.
//
// A read the tier allows at or beneath the name the Landlock ruleset leaves ungranted for an absent built-in row is
// refused there (absentReadFloor).
func evalFS(rt *agent.RuleTable, kind agent.ActionKind, path string, tier backend.Tier, obj fsObject) agent.EvalResult {
	return absentReadFloor(rt, kind, path, tier, evalFSTier(rt, kind, path, tier, obj))
}

// absentReadFloor is r, or the refusal of a read r allows that AbsentRead says the Landlock ruleset every enforcing
// tier installs refuses (ADR 0067 D3): the kernel refuses it whatever the tier's own rule grants, as compile --test
// must say.
func absentReadFloor(rt *agent.RuleTable, kind agent.ActionKind, path string, tier backend.Tier, r agent.EvalResult) agent.EvalResult {
	if kind != agent.ActionFSRead || r.Verdict != agent.VerdictAllow {
		return r
	}
	if rule, ok := AbsentRead(rt, tier, path); ok {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonReadDenied}
	}
	return r
}

// evalFSTier is evalFS without the absent rows' floor: the tier's own resolution.
func evalFSTier(rt *agent.RuleTable, kind agent.ActionKind, path string, tier backend.Tier, obj fsObject) agent.EvalResult {
	if tier == backend.TierObserve {
		return evalObserveFS(rt, path)
	}
	if rt.Builtins != nil && agent.OtherTTY(path) {
		why := record.ReasonReadDenied
		if kind != agent.ActionFSRead {
			why = record.ReasonWriteOutsideContract
		}
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.BuiltinOtherTTY, Reason: why}
	}
	if res, ok := evalDenyWrite(rt, kind, path); ok {
		return res
	}
	if tier == backend.TierLandlock {
		return evalFSLandlock(rt, kind, path)
	}
	// Tier 2's supervisor applies the root mutation decision, intersected with
	// the inherited Landlock ruleset (ADR 0028 S3). A write-open also reaches
	// fanotify, which sees no access mode and refuses the open read-denied.
	if tier == backend.TierCgroup && kind != agent.ActionFSRead {
		if kind == agent.ActionFSWrite {
			if i, refused := listenerOpenRefused(rt, path); refused {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rt.FS[i].RuleName(), Reason: record.ReasonReadDenied}
			}
			if r, refused := listenerNameRefused(newNameIndex(rt), path, obj, denyAtScan(rt, path)); refused {
				return r
			}
		}
		// The listener fallback's supervisor supplies the root walk's
		// negative mutation decision, then the inherited union remains a floor.
		if r := (&Evaluator{rt: rt}).root(kind, path, obj); r.Verdict != agent.VerdictAllow {
			return r
		}
		return evalFSLandlock(rt, kind, path)
	}
	e := &Evaluator{rt: rt}
	r := e.root(kind, path, obj)
	// Tier 3 keeps the Landlock ruleset under the plane, whose unlink and rmdir hooks decide on the object: an unlink
	// its directory's grant does not allow (a file-level write entry's own) is refused there.
	if kind == agent.ActionFSDelete && r.Verdict == agent.VerdictAllow {
		if l, refused := e.landlockDelete(path); refused {
			return l
		}
	}
	return r
}

// listenerNameRefused is tier 2's fanotify open decision for a write-open of a file a name entry covers (ADR 0043
// D7): the listener sees no access mode, so it refuses the open read-denied, as for a nested deny_read. A climb that
// cannot decide is left to the root walk's name check, which refuses it path-unresolved. at is the deny_read entry
// at the path, -1 for none.
func listenerNameRefused(n *NameIndex, path string, obj fsObject, at int) (agent.EvalResult, bool) {
	if n == nil || obj != objFile {
		return agent.EvalResult{}, false
	}
	m, ok := n.Match(path, false)
	if !ok || m.Unresolved {
		return agent.EvalResult{}, false
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: n.Rule(m, at), Reason: record.ReasonReadDenied}, true
}

// denyAtScan is the first deny_read entry whose canonical path is path, -1 for none: the entry a name refusal of the
// file names (ADR 0043 D8), by scan, as Evaluate's other reference questions are.
func denyAtScan(rt *agent.RuleTable, path string) int {
	for i := range rt.FS {
		if rt.FS[i].Kind == agent.FSDenyRead && rt.FS[i].Canonical() == path {
			return i
		}
	}
	return -1
}

// fsObject is what an fs action's object is to the name entries (ADR 0043 D1): a file they decide, a directory they
// never decide, or a question no hook asks them (step C's writability of a mapped file).
type fsObject uint8

const (
	objFile fsObject = iota
	objDir
	objUnnamed
)

// objectOf is an fs action's object: fs.mkdir's is a directory, any other one's what Action.Dir says.
func objectOf(a agent.Action) fsObject {
	if a.Dir || a.Kind == agent.ActionFSMkdir {
		return objDir
	}
	return objFile
}

// nameMoveRefusal is D5's refusal of a directory rename: the name entry's own rule, rename-outside-contract (the
// plane's refer reason), or path-unresolved when a climb could not decide.
func nameMoveRefusal(n *NameIndex, m NameMatch) agent.EvalResult {
	if m.Unresolved {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: n.Rule(m, -1), Reason: record.ReasonRenameOutsideContract}
}

// evalDenyWrite is Evaluate's answer for a modification that reaches a deny_write target in an enforcing
// tier: refused, named after the target. Landlock cannot enforce the target beneath a writable parent, so a
// decision plane decides the actual resolved syscall arguments where one runs; at tier landlock and on tier
// cgroup's listener the supervisor refuses the copied pathname best effort (supervisor R15c), which this
// answer models, or, under fs.assurance: kernel, the run is refused before launch (ADR 0041 D1 (a)). A read of
// a target is not a modification and is not decided here.
func evalDenyWrite(rt *agent.RuleTable, kind agent.ActionKind, path string) (agent.EvalResult, bool) {
	if kind == agent.ActionFSRead {
		return agent.EvalResult{}, false
	}
	r, ok := rt.DenyWriteTarget(path, kind == agent.ActionFSRename)
	if kind == agent.ActionFSMkdir {
		r, ok = rt.DenyWriteNameTarget(path) // a mkdir makes the name
	}
	if !ok {
		return agent.EvalResult{}, false
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: agent.FSReason(kind)}, true
}

// evalObserveFS answers for observe mode, which enforces nothing and only
// records (backend.TierObserve): the nearest entry names the rule an event
// would carry and every action is allowed. SEMANTICS speaks of the three
// enforcing tiers only; this is the reading that keeps a `compile --test`
// table honest about an observe-mode run.
func evalObserveFS(rt *agent.RuleTable, path string) agent.EvalResult {
	if i, steps, ok := nearestFS(rt, path); ok && steps <= agent.MaxWalk {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.FS[i].RuleName()}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
}

// evalRename applies the REFER rule both tiers share: both ends must admit the
// mutation and a rename may not move a file to a less restrictive entry
// (SEMANTICS §2; R7 leaves the check to Evaluate, since compile has no live
// rename to inspect).
func evalRename(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	if a.Path == "" || a.DestPath == "" {
		return invalidAction()
	}
	// rename(2) moves the names themselves, never following a final symlink (canonicalEnd).
	src, dst := canonicalEnd(rt, cleanPath(a.Path)), canonicalEnd(rt, cleanPath(a.DestPath))
	obj := objectOf(a)
	names := newNameIndex(rt)
	// At tier 2 a rename that carries a file, or a directory above one, out of a deny_read entry the
	// fanotify listener enforces by path is refused by the supervisor (DenyReadMoveTarget), and so is a directory
	// rename that takes files out of a name entry's coverage (ADR 0043 D5, the supervisor's R15d).
	if tier == backend.TierCgroup {
		if r, ok := rt.DenyReadMoveTarget(src, true); ok {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: record.ReasonRenameOutsideContract}
		}
		if m, refused := names.MoveRefused(src, dst); refused && obj == objDir {
			return nameMoveRefusal(names, m)
		}
	}
	if res := evalFS(rt, agent.ActionFSRename, src, tier, obj); res.Verdict != agent.VerdictAllow {
		return res
	}
	if res := evalFS(rt, agent.ActionFSRename, dst, tier, obj); res.Verdict != agent.VerdictAllow {
		return res
	}
	if tier == backend.TierObserve {
		return evalObserveFS(rt, src)
	}
	// Tiers 1 and 2 decide a rename with the Landlock ruleset, which bounds no depth and grants what its builder
	// grants, compared as hook_path_rename compares it (RenameGainedBy: nothing within one directory, the new name's
	// directory against the object itself, the file rights only for a file); tier 3's walk compares the rows' rights
	// at the ends, and the same ruleset is the floor under it.
	bounded := tier == backend.TierBPFLSM
	ev := &Evaluator{rt: rt}
	srcName := ev.endName(src, bounded)
	if bounded {
		srcAccess, _ := accessAt(rt, src, bounded)
		if dstAccess, _ := accessAt(rt, dst, bounded); dstAccess&^srcAccess != 0 {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: srcName, Reason: record.ReasonRenameOutsideContract}
		}
	} else if ReferRefuses(referGained(src, dst, ev.landlockRights), obj == objDir) {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: srcName, Reason: record.ReasonRenameOutsideContract}
	}
	// The plane asks D5 after REFER (ADR 0043, path_rename).
	if m, refused := names.MoveRefused(src, dst); refused && obj == objDir && tier == backend.TierBPFLSM {
		return nameMoveRefusal(names, m)
	}
	// Tier 3 keeps the Landlock floor under the plane (landlockRename), as PlaneEvaluator.rename composes it: the
	// directories' REFER, which a file-level write entry's own directory lacks, and REFER's no-gain
	// rule, which refuses a move that gains a right the ruleset grants at the destination alone (an exec.allow
	// directory's EXECUTE).
	if bounded {
		if rule, refused := ev.landlockRename(src, dst, obj == objDir, true); refused {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonRenameOutsideContract}
		}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: srcName}
}
