// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// modelGuard keeps declared models behind the forwarder, under both open and explicit network policies.
// Exact endpoint addresses and local aliases are always refused. Under a net: section an ordinary named
// model also reserves its port: an unknown address there could be a divergent DNS answer, so only an
// explicit net.allow entry may admit it. With no net: section nothing reserves the port (SEMANTICS §1,
// amended 2026-10-05), and such an answer is admitted unmatched, supervisor R7's Limit (a). Such entries are deliberate trust grants, not proof of remote service identity; known model
// endpoints still refuse. The runtime's synthetic forwarder listener grant is handled before this guard.
//
// DNS answers accumulate during the run. Each locality decision uses a fresh enumeration of this host's own
// addresses (thisHost.Fresh): the interfaces' and every address of a `local` route in the kernel's local routing
// table, an AnyIP range among them, which is how a live block and a net gate read this host (hostAddrs.Own), so a
// spelling of this host closed to one is closed to the others. A newly assigned alias or route is protected
// immediately; a failed enumeration of either refuses rather than trusts stale data.
type modelGuard struct {
	// eps is every guarded endpoint with the addresses it matches, swapped whole on each refresh so a match
	// never sees a half-updated set (I9).
	eps atomic.Pointer[[]guardEndpoint]
	// set resolves the named endpoints, keeping the previous addresses when a lookup fails (R8a); nil when
	// every endpoint is a literal address. rules is what it was built from, in named-endpoint order.
	set   *dns.Set
	rules []agent.NetRule
}

// guardEndpoint is one guarded models[] endpoint.
type guardEndpoint struct {
	rule  string // agent.ModelRule
	host  string // as declared, lower case
	port  uint16
	named bool
	local *atomic.Bool // monotonic: an endpoint once seen on this host keeps every local alias guarded
	// addrs is a literal endpoint's one address; a named one's every address it resolved to this run, the
	// latest answer first, with loopback from the start for a localhost name. Empty for a name that has
	// never resolved.
	addrs []netip.Addr
}

// modelRefreshEvery is how often the guard looks for a name whose TTL has passed; the set only looks up a
// name that is due, so this bounds the staleness, not the lookup rate (the runtime's dnsRefreshTick).
const modelRefreshEvery = 5 * time.Second

// maxGuardAddrs bounds what one name accumulates (refresh). A name's answers come from a finite pool, and the
// set re-resolves it at most once per dns.DefaultMinTTL, so the bound is there for a resolver that answers
// every lookup with new addresses: past it the oldest are dropped, the latest answer never.
const maxGuardAddrs = 4096

// newModelGuard builds the guard for agent.RuleTable.GuardedModels, or nil when that is empty, resolving the
// named endpoints with a dns.Set built from opts. A named endpoint is resolved once before this returns,
// bounded by the set's per-lookup timeout, so the run does not start refusing a whole port while a lookup that
// takes milliseconds is still in flight.
func newModelGuard(models []agent.ModelEndpoint, opts dns.Options) *modelGuard {
	if len(models) == 0 {
		return nil
	}
	g := &modelGuard{}
	eps := make([]guardEndpoint, 0, len(models))
	addresses := thisHost.Fresh()
	for _, m := range models {
		ep := guardEndpoint{rule: agent.ModelRule(m), host: m.Host, port: uint16(m.Port), local: &atomic.Bool{}}
		if a, err := netip.ParseAddr(m.Host); err == nil {
			ep.addrs = []netip.Addr{a.Unmap().WithZone("")}
			own, _ := addresses.Has(a)
			ep.local.Store(own || a.Unmap().IsLoopback() || a.IsUnspecified())
		} else {
			ep.named = true
			if agent.LocalhostName(m.Host) {
				ep.local.Store(true)
				ep.addrs = []netip.Addr{netip.IPv6Loopback()}
			}
			g.rules = append(g.rules, agent.NetRule{
				Raw: m.Host + ":" + strconv.Itoa(m.Port), Host: m.Host, Port: m.Port,
				Proto: agent.ProtoInet, Verdict: agent.VerdictRefused,
			})
		}
		eps = append(eps, ep)
	}
	g.eps.Store(&eps)
	if len(g.rules) > 0 {
		g.set = dns.NewSet(g.rules, nil, opts)
		g.refresh(context.Background())
	}
	return g
}

// refresh re-resolves the named endpoints whose TTL has passed and adds what they resolved to. A lookup that
// fails keeps what the name had (dns.Set.Refresh), and one that succeeds adds to it rather than replacing it
// (union): for a deny list both are the side that refuses more, and an address a name stopped returning can
// still be in the agent's resolver cache or its own connection pool.
func (g *modelGuard) refresh(ctx context.Context) {
	if g.set == nil {
		return
	}
	if err := g.set.Refresh(ctx); err != nil {
		return // only ctx's own error: the run is ending
	}
	live := g.set.Refreshed(g.rules)
	addresses := thisHost.Fresh()
	eps := slices.Clone(*g.eps.Load())
	i := 0
	for j := range eps {
		if !eps[j].named {
			continue
		}
		eps[j].addrs = union(live[i].IPs, eps[j].addrs)
		for _, a := range eps[j].addrs {
			if own, _ := addresses.Has(a); own || a.IsLoopback() || a.IsUnspecified() {
				eps[j].local.Store(true)
				break
			}
		}
		i++
	}
	g.eps.Store(&eps)
}

// union is latest followed by every address of had it lacks, up to maxGuardAddrs. had is never modified: a
// match can be reading it.
func union(latest, had []netip.Addr) []netip.Addr {
	out := make([]netip.Addr, 0, len(latest)+len(had))
	for _, a := range latest {
		if a = a.Unmap().WithZone(""); !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	// had is itself a union, so its addresses differ from each other: only the latest answer can repeat one.
	fresh := len(out)
	for _, a := range had {
		if len(out) >= maxGuardAddrs {
			break
		}
		if !slices.Contains(out[:fresh], a) {
			out = append(out, a)
		}
	}
	return out
}

// matchAllowed permits an unknown address on a named model's port only when an explicit net.allow entry
// has already admitted it, including the resolved-address safety check, or the contract has no net:
// section, which reserves no port (decideGuarded). It never exempts known endpoints, local aliases, failed
// locality enumeration or a model name that has not resolved.
func (g *modelGuard) matchAllowed(ap netip.AddrPort, explicit bool) (verdictOf, bool) {
	if g == nil {
		return verdictOf{}, false
	}
	addr := ap.Addr()
	var pending, port *guardEndpoint
	var addresses hostaddr.View
	var enumerated bool
	eps := *g.eps.Load()
	for i := range eps {
		ep := &eps[i]
		if ep.port != ap.Port() {
			continue
		}
		for _, a := range ep.addrs {
			if agent.GuardAddrMatches(addr, a) {
				return verdictOf{rule: ep.rule, host: ep.host}, true
			}
		}
		// Every address on this host can reach a service bound to all interfaces. Classify both
		// ends, so a model declared by a LAN address also guards loopback and another interface.
		if !enumerated {
			addresses, enumerated = thisHost.Fresh(), true
		}
		local, known := addresses.Has(addr)
		endpointLocal := ep.local.Load()
		if !endpointLocal && known {
			for _, a := range ep.addrs {
				if own, _ := addresses.Has(a); own || a.IsLoopback() || a.IsUnspecified() {
					endpointLocal = true
					ep.local.Store(true)
					break
				}
			}
		}
		if endpointLocal && (local || agent.GuardAddrMatches(addr, netip.IPv6Loopback())) {
			return verdictOf{rule: ep.rule, host: ep.host}, true
		}
		if !known && pending == nil {
			pending = ep
		}
		if ep.named && len(ep.addrs) == 0 && pending == nil {
			pending = ep
		}
		if ep.named && !agent.LocalhostName(ep.host) && !explicit && port == nil {
			port = ep
		}
	}
	if pending != nil {
		return verdictOf{rule: ruleUnresolved, host: pending.host}, true
	}
	if port != nil {
		return verdictOf{rule: agent.ModelPortRule(agent.ModelEndpoint{Host: port.host, Port: int(port.port)}), host: port.host}, true
	}
	return verdictOf{}, false
}
