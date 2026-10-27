// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/policy/socketpolicy"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The actions ADR 0017 (b)'s conformance cells take beyond the R28 set (plans/adr0017 C9, ADR 0019: compile --test
// answers every runnable action): each is routed to the matcher the run decides it with, and no new rule is made
// here.

// evalLink answers a hard link, link(2) or linkat(2): Path the existing file, DestPath the new name. It is the
// supervisor's recordLink at tiers 1 and 2: at tier 2 a link out of a deny_read the listener enforces by path is
// refused (R15d, DenyReadMoveTarget), a built-in deny_write target at either end is refused (R15c), each end is
// decided as Landlock's hook_path_link decides it (decideFS, decideMoveDest: MAKE_REG and REFER asked of the end's
// directory, never of the file, after tier 2's nearest-wins walk at the end itself), and a link across directories may
// not give the file a file right the ruleset does not grant where it was (LinkGainsBy: an exec.allow directory's EXECUTE
// included). An allowed link is named by the source directory's grant, as the run's line is. At tier 3 the plane's
// path_link decides it (PlaneEvaluator.link), and the Landlock floor under the plane after it (LandlockLinkRefusal);
// this is the root model it is held to, composed the same way.
func evalLink(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	if a.Path == "" || a.DestPath == "" {
		return invalidAction()
	}
	// linkat(2) without AT_SYMLINK_FOLLOW links the name itself, never following a final symlink (canonicalEnd).
	src, dst := canonicalEnd(rt, cleanPath(a.Path)), canonicalEnd(rt, cleanPath(a.DestPath))
	if tier == backend.TierObserve {
		return evalObserveFS(rt, src)
	}
	reason := agent.FSReason(agent.ActionFSLink)
	if tier == backend.TierCgroup {
		if r, ok := rt.DenyReadMoveTarget(src, false); ok {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: reason}
		}
	}
	// The source is an existing file; the new name is made (DenyWriteNameTarget).
	if r, ok := rt.DenyWriteTarget(src, false); ok {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: reason}
	}
	if r, ok := rt.DenyWriteNameTarget(dst); ok {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: reason}
	}
	res := evalFS(rt, agent.ActionFSLink, src, tier, objFile)
	if res.Verdict != agent.VerdictAllow {
		return res
	}
	if d := evalFS(rt, agent.ActionFSLink, dst, tier, objFile); d.Verdict != agent.VerdictAllow {
		return d
	}
	// Tiers 1 and 2 asked the Landlock ruleset at both directories (evalFS); tier 3's walk asked the ends themselves,
	// and the Landlock floor the run keeps under the plane decides the link as well (LandlockLinkRefusal).
	if tier == backend.TierBPFLSM {
		if name, refused := (&Evaluator{rt: rt}).landlockLink(src, dst); refused {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: reason}
		}
		return res
	}
	if linkGains(src, dst, func(p string) agent.AccessSet { return landlockRights(rt, p) }) {
		return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: res.Rule, Reason: reason}
	}
	return res
}

// evalAttr answers an attribute change of the file at Path: chmod, chown or an extended attribute, a POSIX ACL
// included. No Landlock ABI governs one and no tier-1 or tier-2 mechanism refuses one (CAPABILITIES fs.deny_chmod),
// so it is allowed, named as the supervisor's recordAttr names its line: the write entry that covers the path, else
// the nearest entry, else unmatched. Where a decision plane decides (the bpflsm column: tier bpflsm, and tier cgroup
// in a plane mode), path_chmod, path_chown and the xattr and ACL hooks refuse it at or beneath a built-in deny_write
// target, and their walk refuses what it cannot finish (enforce-plane R12, R7).
func evalAttr(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	if a.Path == "" {
		return invalidAction()
	}
	p := Canonical(rt, cleanPath(a.Path))
	if tier == backend.TierBPFLSM {
		if r, ok := rt.DenyWriteTarget(p, false); ok {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: r.RuleName(), Reason: agent.FSReason(agent.ActionFSAttr)}
		}
		if _, steps, ok := nearestFS(rt, p); (ok && steps > agent.MaxWalk) || (!ok && pathDepth(p) > agent.MaxWalk) {
			return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonPathUnresolved}
		}
	}
	return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: attrName(rt, p)}
}

// attrName is the rule an attribute change's line names (decide.AdvisoryFS for a chmod, chown or xattr op): the
// nearest write entry covering p, else the nearest entry of any kind, else unmatched.
func attrName(rt *agent.RuleTable, p string) string {
	if i, ok := nearestGrant(rt, p, agent.AccessWriteFile); ok {
		return rt.FS[i].RuleName()
	}
	if i, _, ok := nearestFS(rt, p); ok {
		return rt.FS[i].RuleName()
	}
	return agent.UnmatchedRule
}

// The address families and the protocol evalSocket names itself (Linux's stable ABI numbers); the allowlist's own are
// pkg/policy/socketpolicy's.
const (
	afUnix = 1
	// ipprotoMPTCP is refused by every run's seccomp filter, whatever the contract (enforce-landlock E30).
	ipprotoMPTCP = 262
)

// evalSocket answers a socket(2), or a socketpair(2) with Socket.Pair (ADR 0018): under a net: section the
// allowlist (socketpolicy.Allowed with the table's ICMP flag, RuleTable.NetSocketPolicy, the predicate the filter and the
// plane's slot header read), socketpair AF_UNIX only; without one nothing is refused (SEMANTICS §1). IPPROTO_MPTCP
// is refused by every filter, an observe run's included (E30), with no ledger line. A refusal names no entry: rule
// unmatched, reason net-not-allowed, as the supervisor's refuseSocket and the plane's sample write it.
func evalSocket(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	s := a.Socket
	if s.Family < 0 || s.Type < 0 || s.Protocol < 0 {
		return invalidAction()
	}
	refused := agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.UnmatchedRule, Reason: record.ReasonNetNotAllowed}
	if !s.Pair && s.Protocol == ipprotoMPTCP {
		return refused
	}
	allowed := agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	pol := rt.NetSocketPolicy()
	if tier == backend.TierObserve || !pol.Restricted {
		return allowed
	}
	if s.Pair {
		if s.Family == afUnix {
			return allowed
		}
		return refused
	}
	if socketpolicy.Allowed(s.Family, s.Type, s.Protocol, pol.ICMP) {
		return allowed
	}
	return refused
}

// evalSend answers an unconnected datagram send: the connect to the same destination over UDP, or to the same unix
// socket, which is the decision the supervisor's sendDecisionCtl takes for it (R13b) and the run's kernel programs
// take on their own copy of the address. A unix name is decided, as a connect's is, on the name and then on the socket
// it landed on (unixLanded, the supervisor's decideLanded).
func evalSend(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	c := a
	c.Kind = agent.ActionNetConnect
	if c.Host != "" && c.Proto == "" {
		c.Proto = agent.ProtoUDP
	}
	return evalNet(rt, c, tier, true)
}

// evalExecAnon answers the exec of an anonymous image (a memfd, a file unlinked since it was opened): allowed when
// the run's images are unrestricted (no exec: section, or a deny-list one) or the contract set exec.anonymous;
// otherwise refused, rule exec-anon, reason exec-not-allowed, at every enforcing tier (the supervisor's decideExec,
// and bprm_check without TEGO_SLOT_EXEC_ANON at tier 3). An observe run continues it and names exec-anon. A table
// with no contract fails closed, as the plane's slot header and the Landlock builder do.
func evalExecAnon(rt *agent.RuleTable, tier backend.Tier) agent.EvalResult {
	if rt.ExecUnrestricted() || rt.ExecAnonymous() {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.UnmatchedRule}
	}
	if tier == backend.TierObserve {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.ExecAnonRule}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.ExecAnonRule, Reason: record.ReasonExecNotAllowed}
}
