// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// table builds a minimal compiled table with the given net entries.
func table(entries ...agent.NetRule) *agent.RuleTable {
	return &agent.RuleTable{Net: entries, Tier: backend.TierCgroup, Record: agent.RecordFull}
}

// inet is a compiled host:port entry. It carries no name of its own: agent.NetRule.RuleName derives
// one from Raw, the entry as the contract declared it.
func inet(raw string, port int, ips ...string) agent.NetRule {
	r := agent.NetRule{Raw: raw, Port: port, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow}
	for _, s := range ips {
		r.IPs = append(r.IPs, netip.MustParseAddr(s))
	}
	return r
}

// lookup finds the row for a destination the way the kernel would key it.
func lookup(t *testing.T, m RuleMaps, proto uint8, addr string, port uint16) (bpf.NetVerdict, bool) {
	t.Helper()
	want, err := bpf.NewNetKey(0, proto, netip.MustParseAddr(addr), port)
	if err != nil {
		t.Fatalf("NewNetKey: %v", err)
	}
	for _, row := range m.Exact {
		if row.Key == want {
			return row.Val, true
		}
	}
	return bpf.NetVerdict{}, false
}

// TestBuildRuleMapsInetIsBothProtocols pins SEMANTICS §5: one host:port entry decides a TCP connect and a UDP
// datagram, so it must produce a row under each protocol number the hook can key by.
func TestBuildRuleMapsInetIsBothProtocols(t *testing.T) {
	t.Parallel()
	m, err := BuildRuleMaps(table(inet("api.example:443", 443, "198.51.100.4")), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	// Two protocols times two address families (the v4 form and its v4-mapped v6 form).
	if len(m.Exact) != 4 {
		t.Fatalf("%d exact rows, want 4: %+v", len(m.Exact), m.Exact)
	}
	for _, proto := range []uint8{bpf.ProtoTCP, bpf.ProtoUDP} {
		v, ok := lookup(t, m, proto, "198.51.100.4", 443)
		if !ok {
			t.Fatalf("no row for protocol %d", proto)
		}
		if v.Verdict != uint8(bpf.VerdictAllow) || v.RuleIdx != 1 {
			t.Fatalf("protocol %d: %+v", proto, v)
		}
	}
	if m.RuleName(1) != "net[api.example:443]" {
		t.Fatalf("RuleName(1) = %q", m.RuleName(1))
	}
	if m.RuleName(0) != "" || m.RuleName(99) != "" {
		t.Fatalf("unnamed indexes must resolve to the empty name")
	}
}

// TestBuildRuleMapsProtocolNarrowing asserts an explicit tcp or udp entry produces only its own rows.
func TestBuildRuleMapsProtocolNarrowing(t *testing.T) {
	t.Parallel()
	cases := []struct {
		proto string
		want  []uint8
	}{
		{agent.ProtoTCP, []uint8{bpf.ProtoTCP}},
		{agent.ProtoUDP, []uint8{bpf.ProtoUDP}},
		{agent.ProtoInet, []uint8{bpf.ProtoTCP, bpf.ProtoUDP}},
	}
	for _, tc := range cases {
		t.Run(tc.proto, func(t *testing.T) {
			r := inet("x:53", 53, "192.0.2.1")
			r.Proto = tc.proto
			m, err := BuildRuleMaps(table(r), 0, nil, nil)
			if err != nil {
				t.Fatalf("BuildRuleMaps: %v", err)
			}
			seen := map[uint8]bool{}
			for _, row := range m.Exact {
				seen[row.Key.Proto] = true
			}
			if len(seen) != len(tc.want) {
				t.Fatalf("protocols %v, want %v", seen, tc.want)
			}
			for _, p := range tc.want {
				if !seen[p] {
					t.Fatalf("missing protocol %d", p)
				}
			}
		})
	}
}

// TestBuildRuleMapsAskCompilesRefused pins enforce-cgroup-observe.md §5 R3: P0 has no gate, so an ask entry is a refusal in the kernel.
func TestBuildRuleMapsAskCompilesRefused(t *testing.T) {
	t.Parallel()
	for _, v := range []agent.Verdict{agent.VerdictAsk, agent.VerdictRefused} {
		r := inet("x:443", 443, "192.0.2.1")
		r.Verdict = v
		m, err := BuildRuleMaps(table(r), 0, nil, nil)
		if err != nil {
			t.Fatalf("BuildRuleMaps: %v", err)
		}
		got, ok := lookup(t, m, bpf.ProtoTCP, "192.0.2.1", 443)
		if !ok {
			t.Fatalf("no row for %s", v)
		}
		if got.Verdict != uint8(bpf.VerdictRefused) || got.Reason != uint8(bpf.ReasonNetNotAllowed) {
			t.Fatalf("%s compiled to %+v, want refused with net-not-allowed", v, got)
		}
	}
}

// TestBuildRuleMapsRefusalWinsOnCollision asserts the fail-closed merge: two entries that key the same row
// resolve to the refusal whichever order they were declared in.
func TestBuildRuleMapsRefusalWinsOnCollision(t *testing.T) {
	t.Parallel()
	allow := inet("a:443", 443, "192.0.2.1")
	deny := inet("b:443", 443, "192.0.2.1")
	deny.Verdict = agent.VerdictRefused

	for _, order := range [][]agent.NetRule{{allow, deny}, {deny, allow}} {
		m, err := BuildRuleMaps(table(order...), 0, nil, nil)
		if err != nil {
			t.Fatalf("BuildRuleMaps: %v", err)
		}
		got, ok := lookup(t, m, bpf.ProtoTCP, "192.0.2.1", 443)
		if !ok {
			t.Fatal("no row")
		}
		if got.Verdict != uint8(bpf.VerdictRefused) {
			t.Fatalf("order %v: verdict %+v, want refused", order[0].RuleName(), got)
		}
	}
}

// TestBuildRuleMapsCIDR covers the prefix path, including the mapped IPv4 form's widened prefix.
func TestBuildRuleMapsCIDR(t *testing.T) {
	t.Parallel()
	p := netip.MustParsePrefix("10.0.0.0/8")
	r := agent.NetRule{Raw: "10.0.0.0/8:443", Port: 443, Proto: agent.ProtoTCP,
		Verdict: agent.VerdictAllow, CIDR: &p}
	m, err := BuildRuleMaps(table(r), 2, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if len(m.Exact) != 0 {
		t.Fatalf("a cidr entry produced %d exact rows", len(m.Exact))
	}
	if len(m.CIDR) != 2 {
		t.Fatalf("%d cidr rows, want the v4 form and its mapped v6 form", len(m.CIDR))
	}
	if m.CIDR[0].Key.PrefixLen != bpf.LPMHeaderBits+8 {
		t.Fatalf("v4 prefixlen = %d", m.CIDR[0].Key.PrefixLen)
	}
	if m.CIDR[1].Key.PrefixLen != bpf.LPMHeaderBits+104 {
		t.Fatalf("mapped prefixlen = %d, want %d", m.CIDR[1].Key.PrefixLen, bpf.LPMHeaderBits+104)
	}
	for _, row := range m.CIDR {
		if row.Key.RunIdx != 2 {
			t.Fatalf("row carries slot %d, want 2", row.Key.RunIdx)
		}
	}
}

// TestBuildRuleMapsOverlappingExactAndCIDRKeepBothTablesInAnyOrder is enforce-cgroup-observe.md §5 R3 and §6 E8:
// an exact host:port and a CIDR that covers the same address land in different tables, and the kernel consults
// the exact one first, so the exact row carries the composition of every entry covering its address (SEMANTICS
// §5): the refusing prefix decides it whichever was declared first, as Evaluate decides it. The CIDR row is
// still written (it decides every other address in its prefix).
func TestBuildRuleMapsOverlappingExactAndCIDRKeepBothTablesInAnyOrder(t *testing.T) {
	t.Parallel()
	p := netip.MustParsePrefix("198.51.100.0/24")
	exact := inet("api.example:443", 443, "198.51.100.4")
	exact.Proto = agent.ProtoTCP
	wide := agent.NetRule{Raw: "198.51.100.0/24:443", Port: 443, Proto: agent.ProtoTCP, Verdict: agent.VerdictRefused, CIDR: &p}
	for name, entries := range map[string][]agent.NetRule{
		"exact first": {exact, wide},
		"cidr first":  {wide, exact},
	} {
		t.Run(name, func(t *testing.T) {
			m, err := BuildRuleMaps(table(entries...), 0, nil, nil)
			if err != nil {
				t.Fatalf("BuildRuleMaps: %v", err)
			}
			v, ok := lookup(t, m, bpf.ProtoTCP, "198.51.100.4", 443)
			if !ok {
				t.Fatalf("no exact row for the host entry's address: %+v", m.Exact)
			}
			if v.Verdict != uint8(bpf.VerdictRefused) || m.RuleName(v.RuleIdx) != "net[198.51.100.0/24:443]" {
				t.Fatalf("the exact row is %+v (%q); the covering refusing prefix decides it", v, m.RuleName(v.RuleIdx))
			}
			if len(m.CIDR) == 0 {
				t.Fatalf("the covering prefix wrote no row: it still decides the rest of its range")
			}
			for _, row := range m.CIDR {
				if row.Val.Verdict != uint8(bpf.VerdictRefused) || m.RuleName(row.Val.RuleIdx) != "net[198.51.100.0/24:443]" {
					t.Fatalf("cidr row %+v (%q)", row.Val, m.RuleName(row.Val.RuleIdx))
				}
			}
		})
	}
}

// TestBuildRuleMapsSkips covers every entry no cgroup hook can decide, and asserts each is reported rather
// than dropped: a port-0 entry and a host that compiled to no address. A unix entry is not one of them any
// more: it becomes a name row connect_unix and sendmsg_unix decide by (§5 R7).
func TestBuildRuleMapsSkips(t *testing.T) {
	t.Parallel()
	entries := []agent.NetRule{
		{Raw: "unix:/run/pg.sock", Proto: agent.ProtoUnix, UnixPath: "/run/pg.sock", Verdict: agent.VerdictAllow},
		{Raw: "198.51.100.1:0", Proto: agent.ProtoInet, Port: 0, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{netip.MustParseAddr("198.51.100.1")}},
		{Raw: "unresolved.example:443", Proto: agent.ProtoInet, Port: 443, Verdict: agent.VerdictAllow},
	}
	m, err := BuildRuleMaps(table(entries...), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if len(m.Exact) != 0 || len(m.CIDR) != 0 {
		t.Fatalf("skipped entries produced rows: %d exact, %d cidr", len(m.Exact), len(m.CIDR))
	}
	if len(m.Unix) != 1 || m.Unix[0].Val.RuleIdx != 1 {
		t.Fatalf("the unix entry produced %d name rows (%+v), want its one row naming rule 1", len(m.Unix), m.Unix)
	}
	want := []string{SkipAnyPort, SkipUnresolved}
	if len(m.Skipped) != len(want) {
		t.Fatalf("%d skipped, want %d: %+v", len(m.Skipped), len(want), m.Skipped)
	}
	for i, why := range want {
		if m.Skipped[i].Why != why {
			t.Errorf("skip %d: %q, want %q", i, m.Skipped[i].Why, why)
		}
		if m.Skipped[i].Rule == "" || m.Skipped[i].Raw == "" {
			t.Errorf("skip %d has no rule name or declaration: %+v", i, m.Skipped[i])
		}
	}
	// Every entry is still named, so an event that carries its index resolves.
	if m.RuleName(3) != "net[unresolved.example:443]" {
		t.Fatalf("RuleName(3) = %q", m.RuleName(3))
	}
}

// TestBuildRuleMapsDeterministic asserts two compilations of one table produce byte-identical row sequences,
// which is what makes a partial insert failure reproducible.
func TestBuildRuleMapsDeterministic(t *testing.T) {
	t.Parallel()
	rt := table(
		inet("a:443", 443, "198.51.100.4", "2001:db8::1"),
		inet("b:80", 80, "192.0.2.9"),
	)
	first, err := BuildRuleMaps(rt, 1, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	for i := 0; i < 20; i++ {
		again, err := BuildRuleMaps(rt, 1, nil, nil)
		if err != nil {
			t.Fatalf("BuildRuleMaps: %v", err)
		}
		if len(again.Exact) != len(first.Exact) {
			t.Fatalf("row count changed between runs")
		}
		for j := range first.Exact {
			if again.Exact[j] != first.Exact[j] {
				t.Fatalf("row %d differs between runs", j)
			}
		}
	}
}

// TestBuildRuleMapsRejects covers the inputs Prepare must refuse before it creates anything.
func TestBuildRuleMapsRejects(t *testing.T) {
	t.Parallel()
	if _, err := BuildRuleMaps(nil, 0, nil, nil); !errors.Is(err, ErrNoTable) {
		t.Fatalf("nil table = %v, want ErrNoTable", err)
	}
	if _, err := BuildRuleMaps(table(), bpf.MaxSlots, nil, nil); !errors.Is(err, ErrSlotsExhausted) {
		t.Fatalf("out-of-range slot = %v, want ErrSlotsExhausted", err)
	}
	many := make([]agent.NetRule, bpf.MaxRules+1)
	if _, err := BuildRuleMaps(table(many...), 0, nil, nil); !errors.Is(err, ErrMapFull) {
		t.Fatalf("too many entries = %v, want ErrMapFull", err)
	}
	// More distinct destinations than the map holds.
	var wide []agent.NetRule
	for i := 0; i < bpf.NetRowsMax; i++ {
		wide = append(wide, inet("r", 1+i%60000, netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}).String()))
	}
	if _, err := BuildRuleMaps(table(wide...), 0, nil, nil); !errors.Is(err, ErrMapFull) {
		t.Fatalf("oversized table = %v, want ErrMapFull", err)
	}
}

// TestBuildRuleMapsEmpty asserts a contract with no net entries refuses everything by omission: no rows at
// all, so every destination misses both maps and the hook refuses (§5 R3).
func TestBuildRuleMapsEmpty(t *testing.T) {
	t.Parallel()
	m, err := BuildRuleMaps(table(), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if len(m.Exact) != 0 || len(m.CIDR) != 0 || len(m.Skipped) != 0 {
		t.Fatalf("empty table produced %+v", m)
	}
	if len(m.Rules) != 1 || m.Rules[0] != "" {
		t.Fatalf("Rules = %v, want just the empty index 0", m.Rules)
	}
}

// TestBuildRuleMapsCollidingNames is the case rule indexes were hiding. A rule index names the entry its
// author declared (agent.NetRule.RuleName), not its position, so two entries written the same way carry one
// name. The map is index -> name and never the reverse, so both indexes resolve and the event names the
// entry a reader of the contract wrote; the rows they produce still merge fail-closed by key (R3).
func TestBuildRuleMapsCollidingNames(t *testing.T) {
	t.Parallel()
	// `net.allow: ["api:443", "api:443"]` — Load warns about the duplicate and admits it.
	m, err := BuildRuleMaps(table(inet("api:443", 443, "198.51.100.4"), inet("api:443", 443, "198.51.100.9")), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if m.RuleName(1) != "net[api:443]" || m.RuleName(2) != "net[api:443]" {
		t.Fatalf("names = %q, %q; both indexes must resolve to the declared entry",
			m.RuleName(1), m.RuleName(2))
	}
	// Each entry still keys its own destination, so nothing is lost to the shared name.
	for _, addr := range []string{"198.51.100.4", "198.51.100.9"} {
		if _, ok := lookup(t, m, bpf.ProtoTCP, addr, 443); !ok {
			t.Errorf("no row for %s", addr)
		}
	}
}

// TestBuildRuleMapsResolverRows pins the kernel half of supervisor R14. The supervisor admits the machine's
// resolvers on port 53, over UDP and TCP, before it looks at any entry, and relays the connect on the agent's
// socket, which the run's connect4/6 decides again (§5 R1, R5). A contract that names only its API host
// therefore still needs rows for the resolvers, or glibc's and Go's connected UDP query sockets meet EPERM in
// the kernel while the ledger records net.resolver allowed. Verified the other way round as root: without
// these rows a relayed UDP connect to 127.0.0.53:53 under a contract naming only 127.0.0.1:443 was refused.
func TestBuildRuleMapsResolverRows(t *testing.T) {
	t.Parallel()
	ask := inet("127.0.0.53:53", 53, "127.0.0.53")
	ask.Verdict = agent.VerdictAsk
	resolvers := []netip.AddrPort{
		netip.MustParseAddrPort("127.0.0.53:53"),
		netip.MustParseAddrPort("[::ffff:127.0.0.53]:53"), // the same server, mapped: one set of rows
		netip.MustParseAddrPort("[2001:db8::53]:53"),
		netip.MustParseAddrPort("192.0.2.9:5353"), // not on 53: the supervisor's exception does not cover it
	}
	m, err := BuildRuleMaps(table(inet("api:443", 443, "198.51.100.4"), ask), 0, resolvers, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	const resolverIdx = 3 // after the two declared entries
	if m.RuleName(resolverIdx) != agent.ResolverRule {
		t.Fatalf("RuleName(%d) = %q, want %q", resolverIdx, m.RuleName(resolverIdx), agent.ResolverRule)
	}
	for _, proto := range []uint8{bpf.ProtoTCP, bpf.ProtoUDP} {
		for _, addr := range []string{"127.0.0.53", "::ffff:127.0.0.53", "2001:db8::53"} {
			v, ok := lookup(t, m, proto, addr, 53)
			if !ok {
				t.Fatalf("protocol %d: no row for resolver %s:53", proto, addr)
			}
			// The ask entry on the same key compiled as refused; the supervisor asks the resolver exception
			// first, so the kernel must allow here too.
			if v.Verdict != uint8(bpf.VerdictAllow) || v.RuleIdx != resolverIdx {
				t.Fatalf("protocol %d, %s:53 = %+v, want allow under %s", proto, addr, v, agent.ResolverRule)
			}
		}
		for _, addr := range []string{"192.0.2.9"} {
			for _, port := range []uint16{53, 5353} {
				if v, ok := lookup(t, m, proto, addr, port); ok {
					t.Fatalf("protocol %d: %s:%d has a row %+v; an endpoint off port 53 is no resolver", proto, addr, port, v)
				}
			}
		}
	}
	// api:443's four rows, and two protocols times three keys for the two port-53 resolvers.
	if len(m.Exact) != 4+6 {
		t.Fatalf("%d exact rows, want 10: %+v", len(m.Exact), m.Exact)
	}

	none, err := BuildRuleMaps(table(inet("api:443", 443, "198.51.100.4")), 0, nil, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if len(none.Exact) != 4 || len(none.Rules) != 2 {
		t.Fatalf("no resolvers: %d rows and names %v; an empty list is no exception (supervisor E32)",
			len(none.Exact), none.Rules)
	}

	// The resolver's name takes a rule index, so it counts against the space an event can name.
	full := make([]agent.NetRule, bpf.MaxRules)
	if _, err := BuildRuleMaps(table(full...), 0, nil, nil); err != nil {
		t.Fatalf("%d entries without a resolver: %v", bpf.MaxRules, err)
	}
	if _, err := BuildRuleMaps(table(full...), 0, resolvers[:1], nil); !errors.Is(err, ErrMapFull) {
		t.Fatalf("%d entries plus the resolver = %v, want ErrMapFull", bpf.MaxRules, err)
	}
}

// TestBuildRuleMapsMappedOnlyResolver: a resolver the runtime was given only in its IPv4-mapped form
// ([::ffff:10.0.0.1]:53, which netip parses a config or resolv.conf line into when written that way) is the
// IPv4 server the supervisor compares it as (its canonical form unwraps the mapping). Its rows must include the
// AF_INET key, or connect4 to 10.0.0.1:53 is refused with EPERM while the supervisor admits it. The same holds
// for an entry's own address, which the supervisor's set unwraps too.
func TestBuildRuleMapsMappedOnlyResolver(t *testing.T) {
	t.Parallel()
	m, err := BuildRuleMaps(table(inet("api:443", 443, "::ffff:198.51.100.4")), 0,
		[]netip.AddrPort{netip.MustParseAddrPort("[::ffff:10.0.0.1]:53")}, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	for _, proto := range []uint8{bpf.ProtoTCP, bpf.ProtoUDP} {
		for _, addr := range []string{"10.0.0.1", "::ffff:10.0.0.1"} {
			v, ok := lookup(t, m, proto, addr, 53)
			if !ok || v.Verdict != uint8(bpf.VerdictAllow) || m.RuleName(v.RuleIdx) != agent.ResolverRule {
				t.Fatalf("protocol %d, %s:53 = %+v (present %v), want allow named %s", proto, addr, v, ok,
					agent.ResolverRule)
			}
		}
		// An entry's own address in its mapped spelling is the same IPv4 destination to the supervisor.
		for _, addr := range []string{"198.51.100.4", "::ffff:198.51.100.4"} {
			if v, ok := lookup(t, m, proto, addr, 443); !ok || v.Verdict != uint8(bpf.VerdictAllow) {
				t.Fatalf("protocol %d, %s:443 = %+v (present %v), want the entry's allow", proto, addr, v, ok)
			}
		}
	}
}

// TestBuildRuleMapsNoNetSectionDeniesNothing pins SEMANTICS §1 for tier 2: a contract with no net: section
// denies nothing, and the supervisor admits every destination under it (agent.RuleTable.NetUnrestricted). Its
// rows are none and Attach attaches no deciding program (RuleMaps.Unrestricted); zero rows under attached
// programs refused every connect the supervisor relayed. A present but empty net: section, and a hand-built
// table with no contract at all, stay restricted, which is how the supervisor and the Landlock builder read
// them too.
func TestBuildRuleMapsNoNetSectionDeniesNothing(t *testing.T) {
	t.Parallel()
	capture := inet("127.0.0.1:8123", 8123, "127.0.0.1")
	capture.Runtime = agent.CaptureGrant // the runtime adds its loopback grant even to a contract without net:
	resolvers := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}

	open := table(capture)
	open.Contract = &agent.Contract{}
	m, err := BuildRuleMaps(open, 0, resolvers, nil)
	if err != nil {
		t.Fatalf("BuildRuleMaps: %v", err)
	}
	if !m.Unrestricted || len(m.Exact) != 0 || len(m.CIDR) != 0 {
		t.Fatalf("no net: section = unrestricted %v with %d exact and %d cidr rows; want unrestricted and none",
			m.Unrestricted, len(m.Exact), len(m.CIDR))
	}

	for name, rt := range map[string]*agent.RuleTable{
		"an empty net: section": func() *agent.RuleTable {
			rt := table(capture)
			rt.Contract = &agent.Contract{Net: &agent.NetSection{}}
			return rt
		}(),
		"no contract": table(capture),
	} {
		m, err := BuildRuleMaps(rt, 0, resolvers, nil)
		if err != nil {
			t.Fatalf("%s: BuildRuleMaps: %v", name, err)
		}
		if m.Unrestricted || len(m.Exact) != 4+4 {
			t.Fatalf("%s: unrestricted %v with %d exact rows; want restricted with the grant's 4 and the "+
				"resolver's 4", name, m.Unrestricted, len(m.Exact))
		}
	}
}
