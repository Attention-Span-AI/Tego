// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ExecMapRule is the rule a refused executable mapping names (ADR 0027; enforce-plane R26; the plane's refused
// line carries it too, observe.PlaneMapRule): the policy, which no single entry of the contract states.
const ExecMapRule = "exec-map"

// evalMap answers a PROT_EXEC map of the file at a.Path (agent.ActionMapExec) in the root model. Only a decision
// plane decides mappings: tier bpflsm, and tier cgroup in a plane mode, whose column is bpflsm's (ADR 0019). Tier
// landlock has no mmap hook at any ABI and tier cgroup's fanotify listener sees no mapping, so both allow it
// (SEMANTICS §4). At bpflsm, with an exec: section, a file a write entry lets the agent modify is refused unless an
// exec entry covers it (a directory above it, its own entry, a bare name: the exec rows' match), and a walk that
// cannot resolve is refused path-unresolved; any other file maps.
func evalMap(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	if a.Path == "" {
		return invalidAction()
	}
	allowed := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	if tier != backend.TierBPFLSM || rt.ExecUnrestricted() {
		return allowed
	}
	path := Canonical(rt, cleanPath(a.Path))
	w := evalFS(rt, agent.ActionFSWrite, path, backend.TierBPFLSM, objUnnamed) // step C asks the rows, never a name (ADR 0043 D1)
	if w.Verdict != agent.VerdictAllow {
		if w.Reason == record.ReasonPathUnresolved {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
		}
		return allowed
	}
	if rule, ok := matchExec(rt, path, backend.TierBPFLSM); ok && rt.Exec[rule].Verdict == agent.VerdictAllow {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: rt.Exec[rule].RuleName()}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: ExecMapRule, Reason: record.ReasonExecNotAllowed}
}

// mapExec is the plane's mmap_file and file_mprotect answer for a.Path, from the rows as the kernel reads them
// (bpf/decide_stepc.h tego_map_decide): no exec: section decides nothing; the nearest row's modification answer
// says whether the agent could have written the file; under a write row the exec rows' match (ExecMatch) covers it.
func (p *PlaneEvaluator) mapExec(a agent.Action) agent.EvalResult {
	if a.Path == "" {
		return invalidAction()
	}
	// A table the plane cannot hold answers refused before the no-exec:-section shortcut, as every fs and exec
	// action does (NewPlaneEvaluator): the run Prepare refuses allows nothing.
	if p.err != nil {
		return p.unbuildable(agent.ActionExec)
	}
	allowed := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	if p.rt.ExecUnrestricted() {
		return allowed
	}
	path := Canonical(p.rt, cleanPath(a.Path))
	v := p.rows.Decide(path, PlaneModify)
	if v.Unresolved {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
	}
	if !v.Allow {
		return allowed
	}
	if rule, ok := p.rows.ExecMatch(path); ok && p.rt.Exec[rule].Verdict == agent.VerdictAllow {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: p.rt.Exec[rule].RuleName()}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: ExecMapRule, Reason: record.ReasonExecNotAllowed}
}
