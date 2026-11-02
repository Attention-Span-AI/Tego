// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// admitResolved is R7's resolved-address check (agent-contract R18) on an IP destination the resolver
// matched, or failed to match. A net.allow host name admits what the name resolves to, and the Resolver
// re-resolves it on TTL through whatever DNS answers, so a name the author allowed can come to resolve to
// the cloud metadata endpoint, loopback or a link-local address between two lookups (DNS rebinding) —
// Compile has already dropped such an address from the first answer (NetRule.Denied), and this refuses one
// a refresh brought in — or, for a name whose first answer was public only (NetRule.PublicAnswer), to a
// private address on the host's own network. The refusal names the entry whose resolution was refused
// (agent.DeniedResolvedRule), not unmatched, so the ledger says which allowed name pointed where.
//
// This host's own addresses count as loopback for the same reason loopback is refused (thisHost): a name
// that resolves, or is rebound, to the host's LAN, bridge or global IPv6 address, or to an address of an AnyIP
// range the host's local routing table sends here, reaches every service bound to all interfaces, as loopback
// would, and neither the private class nor the machine ranges cover a public address the host holds.
//
// Another entry that admits the same destination on its own still admits it: a literal address or CIDR entry,
// which the author wrote, is the declared way to reach one of these classes on purpose; a localhost name
// admits loopback; another host name admits an address its own answer holds and its own check allows; and a
// grant the runtime added admits what it names. dns.Set.Match returns only the first entry that admits a
// destination, so when that one is a refused host entry the others are searched here, with their live
// addresses when the resolver can give them (liveRules). A destination no entry matches is refused either
// way, and is named after the host entry whose compile-time answer it was, when there is one.
func (c *compiled) admitResolved(ap netip.AddrPort, proto string, m *NetMatch) verdictOf {
	rt := c.pol.Rules
	addr := ap.Addr().Unmap().WithZone("")
	if m == nil {
		for _, r := range rt.Net {
			if r.FiltersResolved() && agent.ProtocolMatches(r.Proto, proto) && portAdmits(r.Port, ap.Port(), proto) && slices.Contains(r.Denied, addr) {
				return verdictOf{rule: agent.DeniedResolvedRule(r.Raw), host: r.Host}
			}
		}
		return refuse(ruleUnmatched)
	}
	if !agent.HostFiltered(m.Host) {
		return allow(m)
	}
	if !resolvedDenied(rt, entryOf(rt, m), addr) {
		return allow(m)
	}
	rules := rt.Net
	if live, ok := c.pol.Resolver.(liveRules); ok {
		rules = live.Refreshed(rt.Net)
	}
	for _, r := range rules {
		if !agent.IsIPProtocol(r.Proto) || !agent.ProtocolMatches(r.Proto, proto) || !portAdmits(r.Port, ap.Port(), proto) {
			continue
		}
		switch {
		case r.CIDR != nil:
			if !r.CIDR.Masked().Contains(addr) {
				continue
			}
		case !slices.Contains(r.IPs, addr):
			continue
		case r.FiltersResolved():
			if resolvedDenied(rt, r, addr) {
				continue
			}
		}
		return verdictOf{rule: r.RuleName(), host: r.Host, allowed: true}
	}
	return verdictOf{rule: agent.DeniedResolvedRule(m.Raw), host: m.Host}
}

// resolvedDenied is RuleTable.ResolvedDenied for a host entry r and a destination a it resolved to, with
// this host's own addresses in the loopback class: refused unless r is a localhost name, which keeps the
// loopback class (agent-contract R18), and refused as well while the host's addresses cannot be known.
func resolvedDenied(rt *agent.RuleTable, r agent.NetRule, a netip.Addr) bool {
	if _, denied := rt.ResolvedDenied(r, a); denied {
		return true
	}
	if agent.LocalhostName(r.Host) {
		return false
	}
	local, known := thisHost.has(a)
	return local || !known
}

// hostAddrs is a snapshot of the addresses assigned to this host's interfaces, taken through list
// (net.InterfaceAddrs: an RTM_GETADDR dump over netlink, which needs no privilege and no cgo) and taken
// again when it is older than maxAge, on the next check that needs it, so an address DHCP, a VPN or a
// container bridge adds is known within maxAge. With them it takes the kernel's local routing table through
// table (hostaddr.ReadLocalTable: an RTM_GETROUTE dump, unprivileged as well), so every address of a `local`
// route there, an AnyIP range's, is one of the host's own. That is the one reading of this host every check
// here takes: the resolved-address check (has), a live block and a net gate (Own, Broadcast, Anycast), and
// the models[] guard, which reads the addresses and the table afresh for each decision (Fresh). The supervisor
// runs in the host's network namespace, which the agent shares in tiers 1 and 2, so these are the addresses a
// connect from the run reaches this host on. The run's own snapshot, which tier 2's rows are filtered by
// (internal/runtime, refreshDenied), reads the same, so the rows refuse what has refuses (R13b).
type hostAddrs struct{ *hostaddr.Snapshot }

// thisHost is the process's snapshot: every run this process supervises shares its network namespace. The
// models[] guard also uses this snapshot for local endpoints. A test replaces it before any loop reads it.
var thisHost = newHostAddrs(net.InterfaceAddrs, hostaddr.ReadLocalTable, time.Now)

// newHostAddrs is a snapshot over list and table; a nil table reads the interfaces' addresses alone.
func newHostAddrs(list func() ([]net.Addr, error), table func() (hostaddr.LocalTable, error), now func() time.Time) *hostAddrs {
	return &hostAddrs{hostaddr.NewWithLocalTable(list, table, now, time.Second)}
}

// has reports whether a is one of this host's own addresses: an interface's, or one in a `local` route of the
// local table (an AnyIP range). known is false while no snapshot was ever taken: resolvedDenied then refuses,
// since an address the check cannot place may be this host's (fail-closed). A snapshot that fails to refresh
// keeps the last one taken, the table's as the addresses', which is the best knowledge there is of addresses
// that change rarely; a failed first snapshot is tried again after maxAge.
func (h *hostAddrs) has(a netip.Addr) (local, known bool) { return h.Has(a) }

// Own is thishost.Addrs' reading of the snapshot, for a live block and a net gate: has's, an interface's address or
// one in a range the local table sends here as the host's own (an AnyIP range), which a server bound to all interfaces
// answers on as well. An address the snapshot cannot place counts as this host's, as resolvedDenied counts it
// (fail-closed): both only refuse, and only on their own port. While the table was never read, the interfaces'
// addresses answer; once it was, the last table read stays in force while it cannot be read again.
func (h *hostAddrs) Own(a netip.Addr) bool {
	local, known := h.Has(a)
	return local || !known
}

// Broadcast is thishost.Addrs' second reading: a subnet's broadcast address, from its mask or from the local table's
// `broadcast` route, which is how one set by hand is read; fail-closed as Own is.
func (h *hostAddrs) Broadcast(a netip.Addr) bool {
	bcast, known := h.HasBroadcast(a)
	return bcast || !known
}

// Anycast is thishost.Addrs' third reading: an IPv6 anycast address this host joined, from the local table's `anycast`
// route; fail-closed as Own is.
func (h *hostAddrs) Anycast(a netip.Addr) bool {
	anycast, known := h.HasAnycast(a)
	return anycast || !known
}

// liveRules is the part of the run's resolver that gives each host entry's live addresses: dns.Set, which the
// runtime hands the loop, built from the same rt.Net the policy carries. Without it the table's compile-time
// addresses are what admitResolved's search reads.
type liveRules interface {
	Refreshed(base []agent.NetRule) []agent.NetRule
}

// entryOf is the table's entry a resolver match names, for its own resolved-address check; an entry the table
// does not hold (a resolver built from another table) is checked by its host name alone.
func entryOf(rt *agent.RuleTable, m *NetMatch) agent.NetRule {
	for _, r := range rt.Net {
		if r.Raw == m.Raw && r.RuleName() == m.Rule {
			return r
		}
	}
	proto := m.Proto
	if proto == "" {
		proto = agent.ProtoInet
	}
	return agent.NetRule{Raw: m.Raw, Host: m.Host, Proto: proto}
}

// portAdmits is dns.Set.Match's port test: a declared port matches itself, and port 0 — SEMANTICS §5's
// spelling of an ICMP or raw destination — matches a destination with no port or a raw socket.
func portAdmits(declared int, port uint16, proto string) bool {
	return decide.PortAdmits(declared, port, proto)
}
