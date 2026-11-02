// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestExecLineDoesNotConsumeSiblingRead(t *testing.T) {
	l := &Loop{}
	id := fileID{dev: 7, ino: 11}
	l.execLines.put(4201, id)
	if l.ExecLine(4202, id.dev, id.ino) {
		t.Fatal("sibling read consumed the exec line")
	}
	if !l.ExecLine(4201, id.dev, id.ino) {
		t.Fatal("exec lost its deduplication entry")
	}
	if l.ExecLine(4201, id.dev, id.ino) {
		t.Fatal("entry consumed twice")
	}
}

func TestLocalModelGuardsAssignedHostAddresses(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	host := &fakeHostAddrs{addrs: []string{"192.0.2.1", "2001:db8::1"}}
	useHostAddrs(t, host, func() time.Time { return now })
	for _, name := range []string{"127.0.0.1", "::1", "localhost", "192.0.2.1", "2001:db8::1"} {
		g := newModelGuard([]agent.ModelEndpoint{{Host: name, Port: 8443}}, dns.Options{Lookup: &stubLookup{addrs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}}})
		for _, address := range []string{"192.0.2.1:8443", "[2001:db8::1]:8443", "[::ffff:192.0.2.1]:8443", "127.0.0.1:8443", "[::1]:8443", "0.0.0.0:8443"} {
			if _, ok := g.match(netip.MustParseAddrPort(address)); !ok {
				t.Errorf("%s model allowed host address %s", name, address)
			}
		}
		for _, address := range []string{"192.0.2.1:8444", "203.0.113.1:8443"} {
			if _, ok := g.match(netip.MustParseAddrPort(address)); ok {
				t.Errorf("%s model refused unrelated address %s", name, address)
			}
		}
	}
	g := newModelGuard([]agent.ModelEndpoint{{Host: "127.0.0.1", Port: 8443}}, dns.Options{})
	host.set(nil, "192.0.2.2")
	// No clock advance: a new interface must not wait for the cached snapshot to expire.
	if _, ok := g.match(netip.MustParseAddrPort("192.0.2.2:8443")); !ok {
		t.Fatal("newly assigned host address bypassed guard")
	}
	useHostAddrs(t, &fakeHostAddrs{err: errors.New("netlink failed")}, func() time.Time { return now })
	if d, ok := g.match(netip.MustParseAddrPort("203.0.113.1:8443")); !ok || d.rule != ruleUnresolved {
		t.Fatal("unknown locality did not fail closed")
	}
	remote := newModelGuard([]agent.ModelEndpoint{{Host: "203.0.113.1", Port: 8443}}, dns.Options{})
	if d, ok := remote.match(netip.MustParseAddrPort("198.51.100.1:8443")); !ok || d.rule != ruleUnresolved {
		t.Fatal("unclassified literal endpoint did not fail closed")
	}
}

// TestModelGuardReadsTheLocalTable: the guard's locality is the reading a live block and a net gate take of this host
// (hostAddrs.Own), the interfaces' addresses and every address of a `local` route of the local table. An address of an
// AnyIP range reaches a model server bound to all interfaces as the host's LAN address does, so a local model guards
// it, and a model declared on one guards loopback and the host's other addresses. Read from the interfaces alone, both
// were open to the guard while a block on the model's address refused them. A table the guard cannot read leaves
// locality unknown, refused as a failed address enumeration is.
func TestModelGuardReadsTheLocalTable(t *testing.T) {
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	thisHost = newHostAddrs(hostList("192.0.2.10"), hostTable, time.Now)
	for _, name := range []string{"127.0.0.1", "192.0.2.10", "198.51.100.7"} {
		g := newModelGuard([]agent.ModelEndpoint{{Host: name, Port: 8443}}, dns.Options{})
		for _, address := range []string{"198.51.100.7:8443", "198.51.100.200:8443", "[::ffff:198.51.100.7]:8443", "127.0.0.1:8443", "192.0.2.10:8443"} {
			if d, ok := g.match(netip.MustParseAddrPort(address)); !ok || d.rule == ruleUnresolved {
				t.Errorf("a model on %s left %s open: %+v, %v", name, address, d, ok)
			}
		}
		for _, address := range []string{"198.51.101.7:8443", "198.51.100.7:8444"} {
			if d, ok := g.match(netip.MustParseAddrPort(address)); ok {
				t.Errorf("a model on %s refused %s: %+v", name, address, d)
			}
		}
	}
	thisHost = newHostAddrs(hostList("192.0.2.10"), func() (hostaddr.LocalTable, error) {
		return hostaddr.LocalTable{}, errors.New("netlink: no buffer space")
	}, time.Now)
	g := newModelGuard([]agent.ModelEndpoint{{Host: "127.0.0.1", Port: 8443}}, dns.Options{})
	if d, ok := g.match(netip.MustParseAddrPort("203.0.113.1:8443")); !ok || d.rule != ruleUnresolved {
		t.Fatalf("an unreadable local table did not fail closed: %+v, %v", d, ok)
	}
}

// TestThisHostReadsTheSameToTheGuardAndABlock: a spelling of this host the models[] guard leaves open, a live block on
// the same address leaves open, and the other way round, through the loop under a contract with no net: section, so a
// block on a local model's address and the guard close the same doors. An address of an AnyIP range was closed to the
// block alone (GAPS C46): `connect 198.51.100.7:8443` was refused live.block[net:127.0.0.1:8443] and admitted unmatched
// under models[127.0.0.1:8443].
func TestThisHostReadsTheSameToTheGuardAndABlock(t *testing.T) {
	const addr, port = 0x40000, 8443
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	thisHost = newHostAddrs(hostList("192.0.2.10"), hostTable, time.Now)
	for _, c := range []struct {
		on, dst string // the model's address and the block's; the connect's
		refused bool
	}{
		{"127.0.0.1", "127.0.0.2", true},
		{"127.0.0.1", "192.0.2.10", true},
		{"127.0.0.1", "198.51.100.7", true},
		{"127.0.0.1", "::ffff:198.51.100.7", true},
		{"127.0.0.1", "198.51.101.7", false},
		{"127.0.0.1", "203.0.113.9", false},
		{"198.51.100.7", "127.0.0.1", true},
		{"198.51.100.7", "::1", true},
		{"198.51.100.7", "192.0.2.10", true},
		{"198.51.100.7", "198.51.100.8", true},
		{"198.51.100.7", "203.0.113.9", false},
	} {
		on := netip.AddrPortFrom(netip.MustParseAddr(c.on), port).String()
		sa := sockaddrIn6(c.dst, port)
		if netip.MustParseAddr(c.dst).Is4() {
			sa = sockaddrIn4(c.dst, port)
		}
		for _, by := range []string{"guard", "block"} {
			t.Run(on+" "+by+" "+c.dst, func(t *testing.T) {
				f := newFake()
				f.put(addr, sa)
				var l *Loop
				var sink *testSink
				var rule string
				if by == "guard" {
					rule = "models[" + on + "]"
					l, sink = newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, agent.ModelEndpoint{Provider: "local", Host: c.on, Port: port}))
				} else {
					rule = "live.block[net:" + on + "]"
					set := liveSet(t, "net", on)
					pol := contractPolicy(&agent.Contract{}, nil, nil)
					pol.Rules.Record = agent.RecordFull
					l, sink = newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
				}
				l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
				ev := sink.one(t)
				if refused := ev.Verdict == record.VerdictRefused && ev.Rule == rule; refused != c.refused || refused == (len(f.connects) > 0) {
					t.Errorf("%s/%s, %d connects; want refused %s: %v", ev.Verdict, ev.Rule, len(f.connects), rule, c.refused)
				}
			})
		}
	}
}

func TestModelGuardDoesNotTrustLastSnapshotAfterError(t *testing.T) {
	host := &fakeHostAddrs{addrs: []string{"192.0.2.1"}}
	useHostAddrs(t, host, time.Now)
	g := newModelGuard([]agent.ModelEndpoint{{Host: "127.0.0.1", Port: 8443}}, dns.Options{})
	ap := netip.MustParseAddrPort("192.0.2.2:8443")
	if _, blocked := g.match(ap); blocked {
		t.Fatal("unassigned remote address refused before enumeration failure")
	}
	host.set(errors.New("netlink failed"), "192.0.2.2")
	if d, blocked := g.matchAllowed(ap, true); !blocked || d.rule != ruleUnresolved {
		t.Fatalf("stale successful snapshot admitted new alias: %+v, %v", d, blocked)
	}
}

func TestForwarderGuardWithExplicitNetworkPolicy(t *testing.T) {
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "model.example", Port: 443}
	lookup := &stubLookup{addrs: []netip.Addr{netip.MustParseAddr("203.0.113.1")}}
	capture := netRule("127.0.0.1:443", "127.0.0.1", 443, "127.0.0.1")
	capture.Runtime = agent.CaptureGrant
	rules := []agent.NetRule{
		netRule("203.0.113.1:443", "203.0.113.1", 443, "203.0.113.1"),
		netRule("198.51.100.1:443", "198.51.100.1", 443, "198.51.100.1"), capture,
	}
	pol := guardPolicy("landlock", rules, model)
	pol.Rules.Contract.Net = &agent.NetSection{}
	l, _ := guardLoop(t, newFake(), pol, lookup)
	c := l.table.Load()
	for _, tc := range []struct {
		address, rule string
		allow         bool
	}{
		{"203.0.113.1:443", "models[model.example:443]", false},
		{"203.0.113.2:443", "models.port[model.example:443]", false},
		{"198.51.100.1:443", "net[198.51.100.1:443]", true},
		{"127.0.0.1:443", "net.capture[127.0.0.1:443]", true},
		{"198.51.100.1:444", ruleUnmatched, false},
	} {
		ap := netip.MustParseAddrPort(tc.address)
		for _, proto := range []string{"tcp", "udp"} {
			d := l.decideGuarded(c, dest{ap: ap, family: 2, ok: true}, proto, true)
			if d.allowed != tc.allow || d.rule != tc.rule {
				t.Errorf("%s %s = %+v, want allowed=%v rule=%s", proto, tc.address, d, tc.allow, tc.rule)
			}
		}
	}
}

func TestModelLocalitySurvivesInterfaceRemoval(t *testing.T) {
	for _, name := range []string{"192.0.2.1", "model.example"} {
		t.Run(name, func(t *testing.T) {
			host := &fakeHostAddrs{addrs: []string{"192.0.2.1"}}
			useHostAddrs(t, host, time.Now)
			g := newModelGuard([]agent.ModelEndpoint{{Host: name, Port: 8443}}, dns.Options{Lookup: &stubLookup{addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}}})
			host.set(nil, "192.0.2.2")
			for _, address := range []string{"127.0.0.1:8443", "[::1]:8443", "192.0.2.2:8443"} {
				if _, blocked := g.matchAllowed(netip.MustParseAddrPort(address), true); !blocked {
					t.Errorf("interface removal reopened model alias %s", address)
				}
			}
		})
	}
}
