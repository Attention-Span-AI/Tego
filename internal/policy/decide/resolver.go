// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"net/netip"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// ResolverPort is the port the resolver exception covers on UDP and TCP alike (docs/p0/supervisor.md R14,
// SEMANTICS §5).
const ResolverPort = 53

// Env is what a run decides with besides its table: the machine's resolver endpoints, snapshotted at run
// start (the machine config's `resolver` list, or /etc/resolv.conf's nameservers under `resolver: auto`).
// The caller reads them; this package makes no I/O (ADR 0028).
type Env struct {
	Resolvers []netip.AddrPort
}

// EvaluateIn is Evaluate for a run whose machine env is env: a TCP or UDP connect to one of env's
// resolvers on port 53 is allowed as agent.ResolverRule before any entry is asked, in every tier and under
// every net: shape, as the supervisor's decideInet and decideGuarded and the tier-2 kernel recorder that
// names a continued connect through supervisor.Loop.ContinuedNet decide it (IsResolver, R14).
func EvaluateIn(rt *agent.RuleTable, a agent.Action, tier backend.Tier, env Env) agent.EvalResult {
	if rt != nil && resolverAction(a, env) {
		return agent.EvalResult{Verdict: agent.VerdictAllow, Rule: agent.ResolverRule}
	}
	return Evaluate(rt, a, tier)
}

func resolverAction(a agent.Action, env Env) bool {
	// An unconnected send is decided as the connect to its destination (supervisor R13b), the resolver included.
	if (a.Kind == agent.ActionNetConnect || a.Kind == agent.ActionNetSend) && len(env.Resolvers) > 0 {
		if addr, err := netip.ParseAddr(a.Host); err == nil && a.Port >= 0 && a.Port <= 0xffff {
			proto := strings.ToLower(a.Proto)
			switch {
			case proto != "":
			case a.Kind == agent.ActionNetSend:
				proto = "udp"
			default:
				proto = "tcp"
			}
			if IsResolver(env.Resolvers, netip.AddrPortFrom(addr, uint16(a.Port)), proto) {
				return true
			}
		}
	}
	return false
}

// IsResolver reports whether ap is one of resolvers on port 53, reached over TCP or UDP: the exception
// allowed ungated by net.allow (R14; glibc falls back to TCP on truncation). An empty list matches nothing,
// and DNS falls through to ordinary matching (E32). Two spellings of one endpoint (a zone, the IPv4-in-IPv6
// wrapper) compare equal. It is the one lookup the supervisor and compile --test share.
func IsResolver(resolvers []netip.AddrPort, ap netip.AddrPort, proto string) bool {
	if ap.Port() != ResolverPort || (proto != "tcp" && proto != "udp") {
		return false
	}
	want := canonicalAddrPort(ap)
	for _, r := range resolvers {
		if canonicalAddrPort(r) == want {
			return true
		}
	}
	return false
}

// canonicalAddrPort strips the zone and the IPv4-in-IPv6 wrapper.
func canonicalAddrPort(ap netip.AddrPort) netip.AddrPort {
	return netip.AddrPortFrom(ap.Addr().Unmap().WithZone(""), ap.Port())
}
