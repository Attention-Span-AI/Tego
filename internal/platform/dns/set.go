// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"net"
	"net/netip"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// Match is the compiled net.allow entry that admits a destination: what the supervisor needs for the
// event's rule and host fields (docs/p0/supervisor.md R7). A nil *Match means no entry admits it.
type Match struct {
	// Proto is the declared transport; inet is the legacy wildcard.
	Proto string
	// Rule is the entry's name in the contract, as agent.NetRule.RuleName spells
	// it: "net[api.anthropic.com:443]", the declared entry the event names
	// (spec/record/v1/README.md, "the declared entry or unmatched").
	Rule string
	// Host is the declared host name, empty for a cidr entry or a literal address entry.
	Host string
	// Raw is the entry as declared, e.g. "api.anthropic.com:443".
	Raw string
	// Verdict is the entry's compiled verdict; P0 compiles net.allow to allow only.
	Verdict agent.Verdict
}

// Options configures a Set. Every zero field takes the documented default.
type Options struct {
	// MaxStale bounds the time after TTL expiry during which an old hostname
	// answer remains usable. Nil preserves compatibility; zero expires at TTL.
	MaxStale *time.Duration
	// Lookup resolves host names; nil uses net.DefaultResolver.
	Lookup agent.Resolver
	// Timeout bounds one host lookup; <= 0 means agent.DefaultDNSTimeout.
	Timeout time.Duration
	// MinTTL floors a rule's re-resolution interval; <= 0 means DefaultMinTTL.
	// It does not extend a compiled grant's TTL or MaxStale deadline.
	MinTTL time.Duration
	// RefreshEvery is how often the caller calls Refresh (Run's interval, the runtime's tick); <= 0 means
	// DefaultInterval. With MaxStale set, a host entry falls due this long plus Timeout before its grant's
	// deadline, so the poll that finds it due has finished its lookup before the grant lapses: a same-answer
	// renewal leaves no refused window (amended 2026-10-05). MinTTL still floors that.
	RefreshEvery time.Duration
	// Now is the clock a test injects; nil means time.Now.
	Now func() time.Time
	// Parallel bounds concurrent lookups in one Refresh; <= 0 means DefaultParallel.
	Parallel int
	// ResolvedDenied, when set, is the run's resolved-address check: Refreshed leaves out of a host entry's
	// addresses every one it refuses for that entry and lists it in the entry's Denied instead, so a second
	// enforcer that follows the refreshes admits no address in the classes that check refuses (agent-contract
	// R18). The runtime hands it agent.RuleTable.ResolvedDenied, with the table's machine ranges, and this
	// host's own interface addresses from a snapshot of its own (internal/runtime, refreshDenied). It is called
	// on every Refreshed, so a check whose answer changes without a lookup (a host address added) changes what
	// the next Refreshed returns. nil filters nothing.
	ResolvedDenied func(r agent.NetRule, a netip.Addr) (class string, denied bool)
}

// Protocol names Match understands on its proto argument. Only ProtoRaw unlocks a port-0 entry against a
// destination that carries a port (R7, SEMANTICS §5: "ICMP and raw datagram sockets match by host with
// port 0").
const (
	ProtoTCP = "tcp"
	ProtoUDP = "udp"
	ProtoRaw = "raw"
)

// Defaults for Options.
const (
	// DefaultMinTTL is the floor on a re-resolution interval: contracts may carry a short DNS TTL, and
	// re-resolving faster than this buys nothing but lookups.
	DefaultMinTTL = 30 * time.Second
	// DefaultParallel is how many host lookups one Refresh runs at a time.
	DefaultParallel = 4
	// DefaultInterval is how often Run wakes to look for rules whose TTL has passed.
	DefaultInterval = 15 * time.Second
)

// Stats are a Set's cumulative refresh counters, for the run's own log and tests.
type Stats struct {
	// Refreshes is the number of completed Refresh calls.
	Refreshes uint64
	// Lookups is the number of host lookups attempted.
	Lookups uint64
	// Failures is the number of lookups that failed; each one kept the previous addresses (R8a).
	Failures uint64
	// Replaced is the number of rules whose address set a successful lookup replaced.
	Replaced uint64
	// Changed is the number of those replacements that brought a different set of addresses. Only a change
	// is something a kernel copy of the set has to follow (Refreshed), so it is counted apart from the
	// replacements that brought the same answer back.
	Changed uint64
}

// rule is one compiled net.allow entry with its live address set. Values are copied, never aliased,
// into each snapshot, so a stored snapshot is immutable (I9).
type rule struct {
	// src is the entry's index in the slice NewSet was given, which is how Refreshed finds it again.
	src        int
	raw        string
	name       string
	host       string
	proto      string
	port       uint16
	anyPort    bool // port 0: the entry matches ICMP/raw at any port (R7)
	cidr       netip.Prefix
	addrs      []netip.Addr
	static     bool // literal address or cidr: never re-resolved
	ttl        time.Duration
	resolvedAt time.Time
	verdict    agent.Verdict
}

// snapshot is the immutable table a Match reads; Refresh swaps a whole new one in (RCU, R27).
type snapshot struct {
	rules []rule
}

// Set is the live IP set of one run's net.allow entries: lock-free matching against an atomically
// swapped snapshot, single-writer refreshes that keep stale addresses when a lookup fails (R8a).
// The zero value is not usable; call NewSet.
type Set struct {
	snap      atomic.Pointer[snapshot]
	resolvers []netip.AddrPort // immutable after NewSet

	mu       sync.Mutex // serializes refreshes: one writer, many lock-free readers
	lookup   agent.Resolver
	timeout  time.Duration
	minTTL   time.Duration
	every    time.Duration
	now      func() time.Time
	par      int
	denied   func(agent.NetRule, netip.Addr) (string, bool) // immutable after NewSet
	maxStale *time.Duration

	refreshes, lookups, failures, replaced, changed atomic.Uint64
}

// NewSet compiles the inet entries of rules into a live set and snapshots resolvers as the endpoints the
// port-53 exception covers. Unix entries are ignored here: they carry no addresses and the supervisor
// matches them against the rule table directly (R11). The returned Set never starts a goroutine of its
// own; call Refresh or Run for that.
func NewSet(rules []agent.NetRule, resolvers []netip.AddrPort, opts Options) *Set {
	s := &Set{
		resolvers: append([]netip.AddrPort(nil), resolvers...),
		lookup:    opts.Lookup,
		timeout:   opts.Timeout,
		minTTL:    opts.MinTTL,
		every:     opts.RefreshEvery,
		now:       opts.Now,
		par:       opts.Parallel,
		denied:    opts.ResolvedDenied,
	}
	if opts.MaxStale != nil {
		v := max(*opts.MaxStale, 0)
		s.maxStale = &v
	}
	if s.lookup == nil {
		s.lookup = net.DefaultResolver
	}
	if s.timeout <= 0 {
		s.timeout = agent.DefaultDNSTimeout
	}
	if s.minTTL <= 0 {
		s.minTTL = DefaultMinTTL
	}
	if s.every <= 0 {
		s.every = DefaultInterval
	}
	if s.now == nil {
		s.now = time.Now
	}
	if s.par <= 0 {
		s.par = DefaultParallel
	}
	snap := &snapshot{rules: make([]rule, 0, len(rules))}
	for i, r := range rules {
		if !agent.IsIPProtocol(r.Proto) || r.Port < 0 || r.Port > 65535 {
			continue // a unix entry carries no address; a port out of range never came from Load
		}
		c := rule{
			src: i, raw: r.Raw, name: r.RuleName(), host: r.Host, proto: r.Proto,
			port: uint16(r.Port), anyPort: r.Port == 0,
			addrs: unmap(r.IPs), static: r.Static,
			ttl: r.TTL, resolvedAt: r.ResolvedAt, verdict: r.Verdict,
		}
		if r.CIDR != nil {
			c.cidr = r.CIDR.Masked()
			c.static = true
		}
		if c.verdict == "" {
			c.verdict = agent.VerdictAllow
		}
		snap.rules = append(snap.rules, c)
	}
	s.snap.Store(snap)
	return s
}

// Match reports the entry that decides dst, or nil when none covers it: among the covering entries a refusing
// one, whatever the declaration order, and otherwise the first declared (R7; SEMANTICS §5, the rule tier 2's
// rows and decide's matcher share). A
// bare host:port or cidr:port entry decides TCP and UDP alike; a tcp:// or udp://
// entry matches only its declared transport. A declared port of 0 is how SEMANTICS §5 spells
// an ICMP or raw destination, which has no port. Such an entry matches a destination whose port is also
// 0, and a raw socket whatever port the address happens to carry; it never admits a tcp or udp
// destination on a real port, which would turn "allow ping to this host" into "allow every port on it".
//
// Match does not apply Options.ResolvedDenied: an address a host entry's name resolved to is matched to that
// entry whether or not the entry may admit it, because the supervisor's resolved-address check refuses it
// under the entry's name, net.denied_resolved[<entry>] (docs/p0/supervisor.md R7), which a miss here would
// turn into unmatched. Refreshed, which kernel rows follow, is where the filter applies.
//
// Match is safe for any number of goroutines and never blocks.
func (s *Set) Match(dst netip.AddrPort, proto string) *Match {
	if !dst.IsValid() {
		return nil
	}
	addr := dst.Addr().Unmap().WithZone("")
	if addr.IsUnspecified() {
		// 0.0.0.0, :: and ::ffff:0.0.0.0 name no destination: the kernel sends such a connect or datagram to
		// this host after every check has run (tcp_v6_connect turns :: into ::1, or ::ffff:127.0.0.1 for a
		// socket bound to a v4-mapped address; the v4 route lookup takes 0.0.0.0 to 127.0.0.1). Matched as
		// written, an entry holding them (::/0, 0.0.0.0/0) admitted loopback, which that entry does not name.
		// The kernel rows refuse them the same way (bpf/cgroup_net.bpf.c tego_addr_unspecified).
		return nil
	}
	snap := s.snap.Load()
	var first *rule
	var now time.Time
	if s.maxStale != nil {
		now = s.now()
	}
	for i := range snap.rules {
		r := &snap.rules[i]
		if deadline := s.deadline(r); !deadline.IsZero() && !now.Before(deadline) {
			continue
		}
		if !agent.ProtocolMatches(r.proto, proto) {
			continue
		}
		if r.anyPort {
			if dst.Port() != 0 && proto != ProtoRaw {
				continue
			}
		} else if r.port != dst.Port() {
			continue
		}
		if r.cidr.IsValid() {
			if !r.cidr.Contains(addr) {
				continue
			}
		} else if !containsAddr(r.addrs, addr) {
			continue
		}
		if r.verdict != agent.VerdictAllow {
			return &Match{Rule: r.name, Host: r.host, Raw: r.raw, Verdict: r.verdict, Proto: r.proto}
		}
		if first == nil {
			first = r
		}
	}
	if first == nil {
		return nil
	}
	return &Match{Rule: first.name, Host: first.host, Raw: first.raw, Verdict: first.verdict, Proto: first.proto}
}

// GateHosts reports every current declared hostname covering the copied destination.
// A shared IP does not prove which DNS name the task intended; escalations must
// consider all matching names, rather than only Match's first attribution. The
// boolean reports whether the complete result fits the 256-name gate bound.
func (s *Set) GateHosts(dst netip.AddrPort, proto string) ([]string, bool) {
	if !dst.IsValid() {
		return nil, false
	}
	addr := dst.Addr().Unmap().WithZone("")
	if addr.IsUnspecified() {
		return nil, false
	}
	var hosts []string
	now := s.now()
	for _, r := range s.snap.Load().rules {
		if r.host == "" || !agent.ProtocolMatches(r.proto, proto) {
			continue
		}
		if deadline := s.deadline(&r); !deadline.IsZero() && !now.Before(deadline) {
			continue
		}
		if r.anyPort {
			if dst.Port() != 0 && proto != ProtoRaw {
				continue
			}
		} else if r.port != dst.Port() {
			continue
		}
		if r.cidr.IsValid() {
			if !r.cidr.Contains(addr) {
				continue
			}
		} else if !containsAddr(r.addrs, addr) {
			continue
		}
		if !slices.Contains(hosts, r.host) {
			if len(hosts) == 256 {
				return nil, false
			}
			hosts = append(hosts, r.host)
		}
	}
	return hosts, true
}

// ResolverAddrs returns the machine's resolver endpoints as snapshotted at run start; the caller must not
// modify the result.
func (s *Set) ResolverAddrs() []netip.AddrPort { return s.resolvers }

// Refreshed returns base, the entries NewSet was given, with each host entry's addresses and resolution time
// replaced by the live ones. It is how a second enforcer of the same entries follows the refreshes: tier 2's
// kernel rows decide every connect the supervisor relays, so they must admit the addresses this set admits now
// (docs/p0/enforce-cgroup-observe.md §6 E7). A literal-address or cidr entry is never re-resolved, and a unix
// entry carries no address, so those are returned as given. base is not modified; an entry that no longer
// sits where NewSet found it (another slice, or one reordered) is returned as given rather than guessed at.
//
// With Options.ResolvedDenied set, a host entry's live address that the check refuses for that entry is left
// out of its IPs and added to its Denied, as Compile does with the first answer (agent-contract R18): the
// metadata endpoint, loopback, one of this host's own addresses (with the runtime's check) or, after a public
// first answer, a private address that a name is rebound to is never among the addresses Refreshed gives tier
// 2's rows. The supervisor refuses every connect and send it sees to any of these; the row is what decides a
// datagram whose address a sibling thread rewrote after the supervisor read it (supervisor R13b).
func (s *Set) Refreshed(base []agent.NetRule) []agent.NetRule {
	out := append([]agent.NetRule(nil), base...)
	snap := s.snap.Load()
	for i := range snap.rules {
		r := &snap.rules[i]
		if r.static || r.host == "" || r.src >= len(out) || out[r.src].RuleName() != r.name || out[r.src].Proto != r.proto {
			continue
		}
		e := &out[r.src]
		e.IPs, e.ResolvedAt = append([]netip.Addr(nil), r.addrs...), r.resolvedAt
		e.ExpiresAt = s.deadline(r)
		if !e.ExpiresAt.IsZero() && !s.now().Before(e.ExpiresAt) {
			e.IPs = nil
		}
		if s.denied == nil || !e.FiltersResolved() {
			continue
		}
		kept := e.IPs[:0]
		denied := append([]netip.Addr(nil), e.Denied...)
		for _, a := range e.IPs {
			if _, refused := s.denied(*e, a); !refused {
				kept = append(kept, a)
			} else if !slices.Contains(denied, a) {
				denied = append(denied, a)
			}
		}
		e.IPs, e.Denied = kept, denied
	}
	return out
}

// Stats returns the cumulative refresh counters.
func (s *Set) Stats() Stats {
	return Stats{
		Refreshes: s.refreshes.Load(), Lookups: s.lookups.Load(),
		Failures: s.failures.Load(), Replaced: s.replaced.Load(), Changed: s.changed.Load(),
	}
}

// Due reports whether any host entry's TTL has passed and a Refresh would do work.
func (s *Set) Due() bool {
	now := s.now()
	snap := s.snap.Load()
	for i := range snap.rules {
		if s.due(&snap.rules[i], now) {
			return true
		}
	}
	return false
}

// due reports whether one rule needs re-resolution now: once its TTL has passed or, for a grant MaxStale
// bounds, once a poll's wait plus a lookup's timeout would no longer fit before its deadline, whichever comes
// first; MinTTL floors either. Due at the deadline itself, a same-answer renewal left the grant lapsed from
// the deadline until the next poll's lookup had finished, refusing an unchanged destination for up to a poll
// interval once a TTL.
func (s *Set) due(r *rule, now time.Time) bool {
	if r.static || r.host == "" {
		return false
	}
	every := r.ttl
	if s.maxStale != nil {
		every = min(every, r.ttl+*s.maxStale-s.every-s.timeout)
	}
	return r.resolvedAt.IsZero() || !now.Before(r.resolvedAt.Add(max(every, s.minTTL)))
}

func (s *Set) deadline(r *rule) time.Time {
	if s.maxStale == nil || r.static || r.host == "" {
		return time.Time{}
	}
	if r.resolvedAt.IsZero() {
		return time.Unix(0, 1) // no successful resolution is not an endless grant
	}
	return r.resolvedAt.Add(r.ttl).Add(*s.maxStale)
}

// Refresh re-resolves every host entry that is due (due) and swaps the merged result in atomically.
// A failed lookup keeps that entry's previous addresses and leaves its deadline in the past so the next
// Refresh retries (R8a, E29); Refresh returns nil in that case — a DNS failure is not a run failure — and
// only ctx's own error stops it. It is safe to call concurrently with Match; two concurrent Refreshes
// serialize.
func (s *Set) Refresh(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.snap.Load()
	now := s.now()
	// Two entries for one host share one lookup; hosts keeps the order deterministic for the tests.
	var hosts []string
	byHost := map[string][]int{}
	for i := range old.rules {
		r := &old.rules[i]
		if !s.due(r, now) {
			continue
		}
		if _, ok := byHost[r.host]; !ok {
			hosts = append(hosts, r.host)
		}
		byHost[r.host] = append(byHost[r.host], i)
	}
	if len(hosts) == 0 {
		s.refreshes.Add(1)
		return nil
	}
	results := make([]lookupResult, len(hosts))
	sem := make(chan struct{}, s.par)
	var wg sync.WaitGroup
	for i, host := range hosts {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int, host string) {
			defer wg.Done()
			defer func() { <-sem }()
			lctx, cancel := context.WithTimeout(ctx, s.timeout)
			defer cancel()
			addrs, err := s.lookup.LookupNetIP(lctx, "ip", host)
			results[i] = lookupResult{addrs: addrs, err: err}
		}(i, host)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	// Merge onto a copy of the old table, then store it whole: no reader ever sees a half-updated rule.
	next := &snapshot{rules: append([]rule(nil), old.rules...)}
	for i, host := range hosts {
		s.lookups.Add(1)
		res := results[i]
		if res.err != nil || len(res.addrs) == 0 {
			s.failures.Add(1)
			continue // keep the stale address set, keep the deadline in the past (R8a)
		}
		addrs := unmap(res.addrs)
		for _, idx := range byHost[host] {
			if !slices.Equal(next.rules[idx].addrs, addrs) {
				s.changed.Add(1) // both sides are unmap's sorted, deduplicated form
			}
			next.rules[idx].addrs = addrs
			next.rules[idx].resolvedAt = now
			s.replaced.Add(1)
		}
	}
	s.snap.Store(next)
	s.refreshes.Add(1)
	return nil
}

// Run refreshes on every tick until ctx is cancelled, at which point it returns nil: a cancelled
// refresher is a clean shutdown, not a run failure, and the run's own error group should see it that way.
// every <= 0 means Options.RefreshEvery, which bounded grants are renewed ahead of (due); a longer every can
// let one lapse before its renewal. Run owns no state beyond its ticker and holds no goroutine of its own
// past its return.
func (s *Set) Run(ctx context.Context, every time.Duration) error {
	if every <= 0 {
		every = s.every
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := s.Refresh(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}

// lookupResult is one host's resolution outcome.
type lookupResult struct {
	addrs []netip.Addr
	err   error
}

// containsAddr reports whether addr is in addrs.
func containsAddr(addrs []netip.Addr, addr netip.Addr) bool {
	for _, a := range addrs {
		if a == addr {
			return true
		}
	}
	return false
}

// unmap copies addresses with IPv4-in-IPv6 unwrapped and zones dropped, deduplicated and sorted, so
// matching compares like with like.
func unmap(in []netip.Addr) []netip.Addr {
	if len(in) == 0 {
		return nil
	}
	seen := make(map[netip.Addr]bool, len(in))
	out := make([]netip.Addr, 0, len(in))
	for _, a := range in {
		a = a.Unmap().WithZone("")
		if !a.IsValid() || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}
