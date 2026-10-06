// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// evalBind combines the listener declaration with the filesystem creation floor
// for pathname Unix sockets. IP listeners use literal addresses, not DNS names.
func evalBind(rt *agent.RuleTable, a agent.Action, tier backend.Tier) agent.EvalResult {
	proto := strings.ToLower(a.Proto)
	if proto == "" {
		proto = agent.ProtoTCP
	}
	var matched agent.ListenRule
	var allow bool
	if proto == agent.ProtoUnix {
		target := a.Path
		if target == "" {
			target = a.Host
		}
		target = strings.TrimPrefix(target, "unix:")
		if target == "" {
			return invalidAction()
		}
		abstract := strings.HasPrefix(target, "@")
		if !abstract {
			if !strings.HasPrefix(target, "/") {
				return invalidAction()
			}
			if a.Walk != agent.UnixWalkLookup && bindUnixDecides(rt, tier) {
				// The walk of the socket's directory failed (TestTable.RunResolved), and the supervisor's bindUnix,
				// which decides this column's binds, refuses a bind it cannot place, whatever the listen entries say
				// (supervisor.md R11a). Elsewhere the row is answered on its spelling, as a row whose walk fails is (R15).
				return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: agent.PathUnreliableRule, Reason: record.ReasonNetNotAllowed}
			}
			target = Canonical(rt, cleanPath(target))
		}
		allow = rt.Listen == nil
		for _, r := range rt.Listen {
			if r.Proto != agent.ProtoUnix || r.Abstract != abstract {
				continue
			}
			want := target
			if abstract {
				want = strings.TrimPrefix(want, "@")
			}
			if r.UnixPath == want {
				matched, allow = r, true
				break
			}
		}
		if (allow || tier == backend.TierObserve) && !abstract {
			// A bind creates a socket entry, rather than opening its contents: a file node path_mknod decides, a
			// name entry included (ADR 0043 D1).
			floor := evalFS(rt, agent.ActionFSMkdir, target, tier, objFile)
			if floor.Verdict != agent.VerdictAllow {
				return floor
			}
		}
	} else {
		if a.Port < 0 || a.Port > 65535 || (proto != agent.ProtoTCP && proto != agent.ProtoUDP) {
			return invalidAction()
		}
		addr, err := netip.ParseAddr(agent.CanonicalHost(a.Host))
		if err != nil || addr.Zone() != "" {
			return invalidAction()
		}
		matched, allow = agent.MatchBind(rt.Listen, netip.AddrPortFrom(addr, uint16(a.Port)), proto)
	}
	name := agent.UnmatchedRule
	if matched.Raw != "" {
		name = matched.RuleName()
	}
	if allow || tier == backend.TierObserve {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: name}
	}
	return agent.EvalResult{Verdict: agent.VerdictRefused, Rule: name, Reason: record.ReasonNetNotAllowed}
}

// bindUnixDecides reports whether the supervisor's bindUnix decides a pathname unix bind in tier's column: the one part
// of the run that refuses a bind whose walk fails, path-unreliable (supervisor.md R11a, handleBind). Which part decides
// is the column's (ADR 0019's design note):
//   - with no listener policy, and in observe, none: the supervisor records the bind (R11a) and continues it with no
//     line, and the kernel's own checks answer it, the creation floor;
//   - under a listener policy at tiers landlock and cgroup (tier 2 with no decision plane: a run whose plane decides is
//     the bpflsm column's, ADR 0019's 2026-09-29 note), bindUnix, on the walk of the socket's directory;
//   - under one in the bpflsm column, the decision plane: the supervisor hands the bind to it (bindHandoffReady), and it
//     decides at path_mknod, which a bind whose lookup fails never reaches. That bind binds nothing, the agent gets the
//     kernel's own errno, and the line is the kernel recorder's (observed, or refused path-unresolved for EACCES),
//     which names no rule; it was answered path-unreliable, a line that run never writes (-2s4-3).
//
// Where bindUnix does not decide, a row whose walk fails is answered on its spelling, as every row whose walk fails as
// the agent's own lookup fails is (agent-contract R15).
func bindUnixDecides(rt *agent.RuleTable, tier backend.Tier) bool {
	return rt.Listen != nil && (tier == backend.TierLandlock || tier == backend.TierCgroup)
}
