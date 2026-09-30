// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"path/filepath"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// PlaneUnbuildableRule is the rule a PlaneEvaluator names for every fs and exec answer when the table does not
// compile for the plane (ErrPlaneCap, ErrPlaneExecVerdict): the run Prepare refuses answers nothing.
const PlaneUnbuildableRule = "plane-unbuildable"

// PlaneEvaluator is compile --test's bpflsm column (TIER3-PLAN T10, ADR 0019's 2026-09-29 note, enforce-plane
// R25): every fs and exec answer is read out of the plane's own rows, CompilePlane's output walked as the kernel
// walks them (PlaneRows.Decide, ExecMatch), so the column is what the loaded programs decide and not a second
// model of it. Evaluate at bpflsm stays the independent root model the rows are property-tested against
// (TestPlaneEvaluatorMatchesEvaluate); a net action has no plane rows (step D) and is Evaluate's. It is pure, and
// the rows are compiled once per table.
type PlaneEvaluator struct {
	rt   *agent.RuleTable
	rows *PlaneRows
	err  error
}

// NewPlaneEvaluator compiles rt's rows once. A table the plane cannot hold is reported by Err and answers every
// fs and exec action refused.
func NewPlaneEvaluator(rt *agent.RuleTable) *PlaneEvaluator {
	rows, err := CompilePlane(rt)
	return &PlaneEvaluator{rt: rt, rows: rows, err: err}
}

// madeAt is where the plane's walk starts for a create of the name path (a mkdir, a hard link's new name): path, but
// for the reopening write entry's own name in an fs.deny_write directory, its directory. That name
// exists or the create is EEXIST before any hook; made anew, it is a negative dentry, whose walk starts at the entry's
// directory, and the entry refuses it there (agent.RuleTable.DenyWriteNameTarget).
func (p *PlaneEvaluator) madeAt(path string) string {
	if _, ok := p.rt.DenyWriteNameTarget(path); ok {
		if _, plain := p.rt.DenyWriteTarget(path, false); !plain {
			return filepath.Dir(path)
		}
	}
	return path
}

// Err is why the table does not compile for the plane, nil when it does.
func (p *PlaneEvaluator) Err() error { return p.err }

// NameEntries is how many of the table's name entries (ADR 0043) the plane's name rows decide: none for a table
// without them, one the plane cannot hold, or a build that does not enforce them.
func (p *PlaneEvaluator) NameEntries() int {
	if p.rows == nil || len(p.rows.NameRows) == 0 {
		return 0
	}
	return p.rows.nameEntries
}

// Evaluate is the verdict the plane gives a in the bpflsm column, with Evaluate's contract for a malformed action.
func (p *PlaneEvaluator) Evaluate(a agent.Action, env Env) agent.EvalResult {
	if p.rt == nil {
		return invalidAction()
	}
	switch a.Kind {
	case agent.ActionFSRead, agent.ActionFSWrite, agent.ActionFSDelete, agent.ActionFSMkdir:
		if a.Path == "" {
			return invalidAction()
		}
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		if a.Kind == agent.ActionFSDelete {
			return p.delete(canonicalEnd(p.rt, cleanPath(a.Path)), objectOf(a) == objDir)
		}
		path := Canonical(p.rt, cleanPath(a.Path))
		if a.Kind == agent.ActionFSMkdir {
			path = p.madeAt(path)
		}
		return p.fsObject(a.Kind, path, objectOf(a) == objDir)
	case agent.ActionFSRename:
		if a.Path == "" || a.DestPath == "" {
			return invalidAction()
		}
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		return p.rename(canonicalEnd(p.rt, cleanPath(a.Path)), canonicalEnd(p.rt, cleanPath(a.DestPath)), a.Dir)
	case agent.ActionExec:
		if a.Path == "" && (len(a.Argv) == 0 || a.Argv[0] == "") {
			return invalidAction()
		}
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		// The command rules are the supervisor's at every tier, decided after the plane's image floor (ADR 0048 (3)).
		return ExecCommandRow(p.rt, a, p.exec(a), backend.TierBPFLSM)
	case agent.ActionMapExec:
		return p.mapExec(a)
	case agent.ActionExecAnon:
		// An exec row: a table the plane cannot hold starts no run at bpflsm, so it is refused as every exec is
		// (correctness F2). Otherwise the supervisor refuses an anonymous image before the plane's
		// bprm_check sees it (recordExec), with the policy model's answer.
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		return EvaluateIn(p.rt, a, backend.TierBPFLSM, env)
	case agent.ActionFSLink:
		if a.Path == "" || a.DestPath == "" {
			return invalidAction()
		}
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		return p.link(canonicalEnd(p.rt, cleanPath(a.Path)), canonicalEnd(p.rt, cleanPath(a.DestPath)))
	case agent.ActionFSAttr:
		if a.Path == "" {
			return invalidAction()
		}
		if p.err != nil {
			return p.unbuildable(a.Kind)
		}
		// path_chmod, path_chown and the xattr and ACL hooks: refused only where the walk meets a protected row or
		// fails (enforce-plane R12, R7); an allowed change is named as the root model names it, the run's line.
		if v := p.rows.Decide(Canonical(p.rt, cleanPath(a.Path)), PlaneProtect); !v.Allow {
			return p.answer(v, a.Kind)
		}
		return Evaluate(p.rt, a, backend.TierBPFLSM)
	}
	return EvaluateIn(p.rt, a, backend.TierBPFLSM, env)
}

func (p *PlaneEvaluator) unbuildable(k agent.ActionKind) agent.EvalResult {
	reason := agent.FSReason(k)
	if k == agent.ActionExec || k == agent.ActionExecAnon {
		reason = record.ReasonExecNotAllowed
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: PlaneUnbuildableRule, Reason: reason}
}

// PlaneRefusal is the rule and reason the ledger line of a refusal by the plane carries (enforce-plane §4): the
// deciding entry, else the row's nearest entry, else unmatched; an exhausted walk is path-unresolved.
func PlaneRefusal(rt *agent.RuleTable, v PlaneVerdict, kind agent.ActionKind) (string, record.Reason) {
	if v.Unresolved {
		return agent.UnmatchedRule, record.ReasonPathUnresolved
	}
	name := agent.UnmatchedRule
	switch {
	case v.Rule.Section != PlaneNoRule:
		name = v.Rule.Name(rt)
	case v.Named >= 0:
		name = rt.FS[v.Named].RuleName()
	}
	if kind == agent.ActionFSRead {
		return name, record.ReasonReadDenied
	}
	return name, agent.FSReason(kind)
}

// fs answers one non-rename fs action on a canonical path whose object is a file: file_open for a read, the create,
// delete and write-open hooks for the rest.
func (p *PlaneEvaluator) fs(kind agent.ActionKind, path string) agent.EvalResult {
	return p.fsObject(kind, path, false)
}

// fsObject is fs with the object's kind: a name entry decides a file and never a directory (ADR 0043 D1), so the
// hooks' answers are the walk's, then the name check's for a file (PlaneRows.DecideObject).
func (p *PlaneEvaluator) fsObject(kind agent.ActionKind, path string, dir bool) agent.EvalResult {
	q := PlaneModify
	if kind == agent.ActionFSRead {
		q = PlaneRead
	}
	return p.answer(p.rows.DecideObject(path, q, dir), kind)
}

func (p *PlaneEvaluator) answer(v PlaneVerdict, kind agent.ActionKind) agent.EvalResult {
	if !v.Allow {
		name, reason := PlaneRefusal(p.rt, v, kind)
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: reason}
	}
	// An allowed read is named by the nearest entry of any kind (SEMANTICS §7); an allowed modification by the
	// entry that granted it.
	name := agent.UnmatchedRule
	if kind == agent.ActionFSRead {
		if v.Named >= 0 {
			name = p.rt.FS[v.Named].RuleName()
		}
	} else if v.Rule.Section != PlaneNoRule {
		name = v.Rule.Name(p.rt)
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
}

// rename is path_rename and REFER on two canonical ends: each end decides as a rename of itself (a file's name
// check included), then the source's row may not be stricter than the destination's (enforce-plane R10, R11), then a
// directory may not take covered files out of coverage (ADR 0043 D5, ScopeMoveRefused), then the Landlock floor's
// no-gain rule (RenameGainedBy, ReferRefuses). Where an end lies above
// every write entry and above a deny_write target, the plane names the row's nearest entry where the root model
// names the target; both refuse for one reason.
func (p *PlaneEvaluator) rename(src, dst string, dir bool) agent.EvalResult {
	for _, end := range [...]string{src, dst} {
		if v := p.rows.DecideObject(end, PlaneRename, dir); !v.Allow {
			return p.answer(v, agent.ActionFSRename)
		}
	}
	name := agent.UnmatchedRule
	if sv := p.rows.Decide(src, PlaneRead); sv.Named >= 0 {
		name = p.rt.FS[sv.Named].RuleName()
	}
	if PlaneReferRefused(p.rows.KindAt(src), p.rows.KindAt(dst)) {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: record.ReasonRenameOutsideContract}
	}
	if dir {
		if rule, unresolved, refused := p.rows.ScopeMoveRefused(src, dst); refused {
			if unresolved {
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
			}
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule.Name(p.rt), Reason: record.ReasonRenameOutsideContract}
		}
	}
	// The Landlock floor under the plane (landlockRename), as link composes LandlockLinkRefusal: REFER on both ends'
	// directories, which a file-level write entry's own directory lacks, then REFER's no-gain rule
	// over the rights the ruleset grants, as hook_path_rename compares them (RenameGainedBy, ReferRefuses), which refuses a move into an
	// exec.allow directory path_rename allows.
	if rule, refused := (&Evaluator{rt: p.rt}).landlockRename(src, dst, dir, true); refused {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: rule, Reason: record.ReasonRenameOutsideContract}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
}

// delete is path_unlink or path_rmdir on the canonical end p, which decides on the object (fsObject), then the Landlock
// floor under the plane, which asks REMOVE_* of p's directory and refuses a file-level write entry's own unlink the
// hooks allow (landlockDelete).
func (p *PlaneEvaluator) delete(path string, dir bool) agent.EvalResult {
	r := p.fsObject(agent.ActionFSDelete, path, dir)
	if r.Verdict != agent.VerdictAllow {
		return r
	}
	if l, refused := (&Evaluator{rt: p.rt}).landlockDelete(path); refused {
		return l
	}
	return r
}

// link is path_link on two canonical ends (enforce-plane R10, bpf/decide.bpf.c), in the hook's order: a walk of
// either end that cannot finish refuses first (the source's, then the new name's), then the new name is a creation in
// its directory, a modification there (a file the name entries cover included, ADR 0043 D7), and then REFER holds the
// source's nearest row to be no stricter than the destination's, so a second name for a file under a deny_read or a
// deny_write target outside it is refused, named by the source row's nearest entry as the recorder names a REFER
// refusal. A source the name entries cover is a deny_read at its own path (ADR 0043: REFER strictness 2). An allowed
// link is named by the source's grant, as the root model and the run's line name it.
//
// Two producers answer before or after the plane, and the column composes both: a table that holds fs
// notifications keeps link notified at tier 3 (landlock planeSkips), so the supervisor's R15c refuses a deny_write
// end first under the target's own name (recordLink's denyWrite); and the Landlock floor the run keeps under the
// plane refuses what hook_path_link refuses (LandlockLinkRefusal), as the column composes the floor for a script.
func (p *PlaneEvaluator) link(src, dst string) agent.EvalResult {
	reason := agent.FSReason(agent.ActionFSLink)
	if p.rt.HoldsFSNotifications() {
		if r, ok := p.rt.DenyWriteTarget(src, false); ok {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: reason}
		}
		if r, ok := p.rt.DenyWriteNameTarget(dst); ok { // the new name is made
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: reason}
		}
	}
	sv := p.rows.DecideObject(src, PlaneRead, false)
	if sv.Unresolved {
		return p.answer(sv, agent.ActionFSLink)
	}
	if v := p.rows.DecideObject(p.madeAt(dst), PlaneModify, false); !v.Allow {
		return p.answer(v, agent.ActionFSLink)
	}
	kind := p.rows.KindAt(src)
	if !sv.Allow {
		kind |= PlaneReadDeny
	}
	if PlaneReferRefused(kind, p.rows.KindAt(dst)) {
		name := agent.UnmatchedRule
		if sv.Named >= 0 {
			name = p.rt.FS[sv.Named].RuleName()
		}
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: reason}
	}
	res := p.answer(p.rows.Decide(src, PlaneModify), agent.ActionFSLink)
	if res.Verdict != agent.VerdictAllow {
		return res
	}
	if name, refused := (&Evaluator{rt: p.rt}).landlockLink(src, dst); refused {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: reason}
	}
	return res
}

// exec is bprm_check_security's stages then file_open's read of each file the exec opens (SEMANTICS §4): the
// program, a #! script's interpreter and the loader compile recorded. bprm_check passes a #! stage on its buffer
// and decides on the interpreter; the script itself meets the Landlock floor the run also installs (ScriptFloor),
// which grants EXECUTE by inode only, so the column is the plane intersected with Landlock (ADR 0019).
func (p *PlaneEvaluator) exec(a agent.Action) agent.EvalResult {
	path := a.Path
	if path == "" && len(a.Argv) > 0 {
		path = a.Argv[0]
	}
	if path == "" {
		return invalidAction()
	}
	path = cleanPath(path)
	opened := []string{path}
	if a.Script != "" {
		opened = append(opened, cleanPath(a.Script))
	}
	loader := p.loader(opened[len(opened)-1])
	named := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	if p.rt.ExecUnrestricted() {
		if rule, ok := p.match(path); ok {
			named.Rule = p.rt.Exec[rule].RuleName()
		}
	} else {
		stage := path
		if a.Script != "" {
			// The plane passes the #! stage; the Landlock floor under it refuses a script no entry grants.
			if floor := ScriptFloor(p.rt, path, backend.TierBPFLSM); floor.Verdict != agent.VerdictAllow {
				return floor
			}
			stage = opened[1]
		}
		rule, ok := p.match(stage)
		switch {
		case !ok:
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonExecNotAllowed}
		case p.rt.Exec[rule].Verdict != agent.VerdictAllow:
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: p.rt.Exec[rule].RuleName(), Reason: record.ReasonExecNotAllowed}
		}
		named.Rule = p.rt.Exec[rule].RuleName()
	}
	if res, refused := p.execOpenRefused(opened, loader); refused {
		return res
	}
	return named
}

// execOpenRefused is the read each file of the exec opens, decided by file_open's rows.
func (p *PlaneEvaluator) execOpenRefused(opened []string, loader string) (agent.EvalResult, bool) {
	files := opened
	if loader != "" {
		files = append(append([]string(nil), opened...), loader)
	}
	for i, f := range files {
		if i < len(opened) {
			var ok bool
			if f, ok = p.file(f); !ok {
				continue
			}
		}
		if res := p.fs(agent.ActionFSRead, Canonical(p.rt, f)); res.Verdict == agent.VerdictRefused {
			return res, true
		}
	}
	return agent.EvalResult{}, false
}

// match is the exec entry the plane finds for a file: the rows' ExecMatch on a canonical path, and for a bare
// command name the first entry that names it, the entry's own candidate being the only file it can mean
// (Evaluate makes no PATH lookup).
func (p *PlaneEvaluator) match(path string) (int, bool) {
	if path == filepath.Base(path) {
		return p.bare(path)
	}
	return p.rows.ExecMatch(path)
}

func (p *PlaneEvaluator) bare(name string) (int, bool) {
	for i := range p.rt.Exec {
		if p.rt.Exec[i].Basename == name {
			return i, true
		}
	}
	return -1, false
}

// file is the file an exec action opens: a path names itself, a bare name the candidate of the entry naming it.
func (p *PlaneEvaluator) file(path string) (string, bool) {
	if path != filepath.Base(path) {
		return path, true
	}
	i, ok := p.bare(path)
	if !ok || p.rt.Exec[i].IsDir || p.rt.Exec[i].Path == "" {
		return "", false
	}
	return p.rt.Exec[i].Path, true
}

// loader is the PT_INTERP loader compile recorded for a declared file entry, "" for any other file.
func (p *PlaneEvaluator) loader(path string) string {
	file, ok := p.file(path)
	if !ok {
		return ""
	}
	for i := range p.rt.Exec {
		if r := &p.rt.Exec[i]; !r.IsDir && r.Path == file && r.Interp != "" {
			return cleanPath(r.Interp)
		}
	}
	return ""
}
