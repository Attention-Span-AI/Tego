// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"net"
	"net/netip"
	"strconv"

	"github.com/attention-span-ai/tego/pkg/policy/thishost"
)

// ModelRule is the rule a refused direct connection to a guarded models[] endpoint carries (GuardedModels):
// "models[<host>:<port>]" (an IPv6 host in brackets), the declared models: entry that refused it. It is not a runtime grant
// (IsRuntimeRule is false for it), so `tego drift` counts such a refusal like any other.
func ModelRule(m ModelEndpoint) string {
	return "models[" + net.JoinHostPort(CanonicalHost(m.Host), strconv.Itoa(m.Port)) + "]"
}

// ModelPortRule names a refusal of an undeclared destination on a named forwarder model's port.
// Without an explicit network allowance that destination might be a different DNS answer for the model.
func ModelPortRule(m ModelEndpoint) string {
	return "models.port[" + net.JoinHostPort(CanonicalHost(m.Host), strconv.Itoa(m.Port)) + "]"
}

// GuardedModels returns endpoints an enforcing forwarder run may reach only through the capture listener: each
// models[] entry and each of its routes' backends (ADR 0127), a backend's refusal naming it models[<host>:<port>].
// Known model addresses and their local aliases stay refused even under explicit net.allow. Under a net:
// section, named model ports additionally refuse unknown destinations unless net.allow explicitly admits
// them: a remote service cannot be identified reliably from an IP address that differs from this process's
// DNS answer. With no net: section they do not (SEMANTICS §1, amended 2026-10-05).
//
// It is empty unless the table's capture mode is forwarder. Under uprobe the uprobes record a direct
// connection's TLS themselves: under auto the forwarder runs beside them, and under a pinned capture: uprobe
// no forwarder runs at all (PinsUprobe), so the direct connection is the agent's only route to its model. A
// pinned uprobe that a machine ceiling lowered is capture forwarder here, and guarded like any other.
// Under off nothing captures. Refusing the model host there would only refuse the agent its model. The table's
// mode is the one the run's tier carries (AtTier), which is what every component reads. A uprobe source that
// failed to start at run time (a capture ring the host's budget had no room for) leaves the mode uprobe: a
// direct connection is then neither captured nor refused, and the source's mechanism-unavailable gap is what
// says the run's model traffic went uncaptured; a run with a token, cost or repeats budget is refused instead,
// the forwarder beside the probes running or not (runtime refuseUnmeteredBudget, limits-check-doctor-cli.md R32).
// Under record: off the probes place none by design, so Compile gives an auto contract the forwarder mode there
// (recordOffCapture), and its endpoints are guarded.
func (rt *RuleTable) GuardedModels() []ModelEndpoint {
	if rt == nil || rt.Contract == nil || rt.Capture != CaptureForwarder {
		return nil
	}
	var out []ModelEndpoint
	seen := map[string]bool{}
	for _, m := range rt.Contract.Models {
		if m.Port <= 0 || m.Port > 65535 || CanonicalHost(m.Host) == "" {
			continue // Load refuses both; a hand-built table's hole names nothing to refuse
		}
		m.Host = CanonicalHost(m.Host)
		if k := ModelRule(m); !seen[k] {
			seen[k] = true
			out = append(out, m)
		}
		// A route's backend is guarded as the endpoint is (ADR 0127, R32): the agent reaches it through the forwarder,
		// captured, budgeted and recorded with its route, or not at all; a keyless model server on loopback is no
		// way around the capture.
		for _, r := range m.Routes {
			b := ModelEndpoint{Provider: m.Provider, Host: CanonicalHost(r.Host), Port: r.Port}
			if b.Port <= 0 || b.Port > 65535 || b.Host == "" {
				continue // Load refuses both
			}
			if k := ModelRule(b); !seen[k] {
				seen[k] = true
				out = append(out, b)
			}
		}
	}
	return out
}

// GuardAddrMatches reports whether a connection to dst can reach a guarded models[] endpoint at address ep
// (GuardedModels): the same address, IPv4-mapped or not; both addresses of this host's loopback; or dst the
// unspecified address, whatever ep is. The last two were each a way around the forwarder. The kernel sends a
// connection to the unspecified address to this host: ip_route_output_key_hash_rcu turns daddr 0.0.0.0 into
// 127.0.0.1 or the socket's bound source address, and tcp_v6_connect and udpv6_sendmsg turn :: into ::1 (or
// v4-mapped loopback), so 0.0.0.0:P reached a model server on 127.0.0.1:P — the address vLLM and its like
// print for a server bound to all interfaces — and, from a socket bound to one of this host's other
// addresses, a server on that address. Such a connection never leaves the host, so it matches every guarded
// endpoint on its port. And a server bound to all interfaces answers on every loopback address, 127.0.0.2 and
// ::1 among them, so a loopback endpoint stands for all of 127.0.0.0/8 and ::1 on its port. Refusing them
// all costs at most another local server on the model's own port.
//
// This host's other addresses (a LAN or bridge address) reach a model server bound to all interfaces as its
// loopback does, and a pure predicate cannot tell which addresses are this host's: the run's guard is to
// count them from a snapshot of the host's interface addresses (docs/p0/supervisor.md R7 Limit (b)), and
// Evaluate answers such a destination refused, rule unresolved (evalGuard).
func GuardAddrMatches(dst, ep netip.Addr) bool {
	dst, ep = dst.Unmap().WithZone(""), ep.Unmap().WithZone("")
	return dst == ep || dst.IsUnspecified() || (thishost.Names(dst, nil) && thishost.Names(ep, nil))
}

// LocalhostName reports whether h is a name RFC 6761 §6.3 reserves for loopback: localhost, and every name
// under .localhost, which resolvers are to answer with a loopback address. The guard matches it as one
// without a lookup (guardAddr, and the supervisor's modelGuard), so `compile --test` refuses
// localhost:<port> against a loopback endpoint as the run refuses the address the agent's lookup returns.
func LocalhostName(h string) bool {
	return thishost.Name(CanonicalHost(h))
}
