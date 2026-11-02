// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveSet is a Set of the blocks given as kind, value pairs.
func liveSet(t *testing.T, kv ...string) *liveblock.Set {
	t.Helper()
	o := liveblock.New("r-test")
	for i := 0; i+1 < len(kv); i += 2 {
		if _, _, err := o.Add(liveblock.Kind(kv[i]), kv[i+1], "t", time.Now()); err != nil {
			t.Fatal(err)
		}
	}
	return liveblock.Compile(o, liveblock.Resolved{})
}

// TestLiveBlockRefusesAGrantedExec: an exec the contract grants is refused live.block[...] while a block names it,
// with the loop's own EACCES (never CONTINUE), and allowed again once the block is gone.
func TestLiveBlockRefusesAGrantedExec(t *testing.T) {
	const pathAddr, argvAddr = 0x10000, 0x20000
	nr := nrFor(t, "execve")
	var set *liveblock.Set
	for _, c := range []struct {
		blocks   *liveblock.Set
		wantRule string
		wantVerd record.Verdict
	}{
		{liveSet(t, "exec", "curl"), "live.block[exec:curl]", record.VerdictRefused},
		{liveSet(t, "exec", "/usr/bin/curl"), "live.block[exec:/usr/bin/curl]", record.VerdictRefused},
		{liveSet(t, "exec", "wget"), "exec[/usr/bin/curl]", record.VerdictAllow},
		{nil, "exec[/usr/bin/curl]", record.VerdictAllow},
	} {
		f := newFake()
		f.put(pathAddr, cstr("/usr/bin/curl"))
		execFixture(f, argvAddr, []string{"curl", "x"})
		pol := testPolicy(nil, nil, nil)
		pol.Rules.Exec = []agent.ExecRule{{Path: "/usr/bin/curl", Source: agent.ExecSourceAllow}}
		set = c.blocks
		l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
		l.handle(notifFor(nr, 4242, pathAddr, argvAddr, 0))
		wantExecAnswer(t, f, c.wantVerd)
		ev := sink.one(t)
		if ev.Rule != c.wantRule || ev.Verdict != c.wantVerd {
			t.Errorf("rule/verdict = %s/%s, want %s/%s", ev.Rule, ev.Verdict, c.wantRule, c.wantVerd)
		}
		if c.wantVerd == record.VerdictRefused && ev.Reason != record.ReasonExecNotAllowed {
			t.Errorf("reason = %s", ev.Reason)
		}
	}
}

// TestLiveBlockRefusesAnAllowedConnect: a connect the contract allows is refused live.block[...] while a block names
// its address or the declared host it was admitted under, never performed; a refusal the contract makes keeps its
// own rule.
func TestLiveBlockRefusesAnAllowedConnect(t *testing.T) {
	const addr = 0x40000
	rules := []agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34")}
	for _, c := range []struct {
		name      string
		blocks    *liveblock.Set
		sa        []byte
		wantRule  string
		connected bool
	}{
		{"by address", liveSet(t, "net", "93.184.216.34:443"), sockaddrIn4("93.184.216.34", 443), "live.block[net:93.184.216.34:443]", false},
		{"by host", liveSet(t, "net", "api.example.com"), sockaddrIn4("93.184.216.34", 443), "live.block[net:api.example.com]", false},
		{"other port", liveSet(t, "net", "93.184.216.34:80"), sockaddrIn4("93.184.216.34", 443), "net[api.example.com:443]", true},
		{"contract refuses first", liveSet(t, "net", "203.0.113.9"), sockaddrIn4("203.0.113.9", 443), ruleUnmatched, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, c.sa)
			f.sockType = unix.SOCK_STREAM
			set := c.blocks
			l, sink := newTestLoopOpts(t, f, testPolicy(rules, nil, []netip.AddrPort{}), Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(c.sa))))
			got, _ := f.lastResp()
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatal("a connect was answered CONTINUE")
			}
			if connected := len(f.connects) > 0; connected != c.connected {
				t.Errorf("connected = %v, want %v", connected, c.connected)
			}
			ev := sink.one(t)
			if ev.Rule != c.wantRule {
				t.Errorf("rule = %s, want %s", ev.Rule, c.wantRule)
			}
			if !c.connected && (ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed) {
				t.Errorf("verdict/reason = %s/%s", ev.Verdict, ev.Reason)
			}
		})
	}
}

// TestLiveBlockReachesEverySpellingOfThisHost: under a contract with no net: section, which leaves every destination
// open, a block on this host is the only refusal, and it refuses the host however a connect spells it. A connect to
// 0.0.0.0 lands on loopback or the socket's bound source, and a server on all interfaces answers on every loopback
// address and on the host's own. While the host's addresses cannot be read, a destination on the block's port is refused.
func TestLiveBlockReachesEverySpellingOfThisHost(t *testing.T) {
	const addr, port = 0x40000, 39511
	const rule = "live.block[net:127.0.0.1:39511]"
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	set := liveSet(t, "net", "127.0.0.1:39511")
	for _, c := range []struct {
		name    string
		sa      []byte
		list    func() ([]net.Addr, error)
		refused bool
	}{
		{"the block's own", sockaddrIn4("127.0.0.1", port), hostList("192.0.2.10"), true},
		{"unspecified", sockaddrIn4("0.0.0.0", port), hostList("192.0.2.10"), true},
		{"unspecified, mapped", sockaddrIn6("::ffff:0.0.0.0", port), hostList("192.0.2.10"), true},
		{"unspecified, IPv6", sockaddrIn6("::", port), hostList("192.0.2.10"), true},
		{"another loopback address", sockaddrIn4("127.0.0.2", port), hostList("192.0.2.10"), true},
		{"IPv6 loopback", sockaddrIn6("::1", port), hostList("192.0.2.10"), true},
		{"this host's LAN address", sockaddrIn4("192.0.2.10", port), hostList("192.0.2.10"), true},
		{"its subnet's broadcast", sockaddrIn4("192.0.2.255", port), hostList("192.0.2.10"), true},
		{"the limited broadcast", sockaddrIn4("255.255.255.255", port), hostList("192.0.2.10"), true},
		{"a multicast group", sockaddrIn4("224.0.0.1", port), hostList("192.0.2.10"), true},
		{"a multicast group, mapped", sockaddrIn6("::ffff:224.0.0.1", port), hostList("192.0.2.10"), true},
		{"an IPv6 multicast group", sockaddrIn6("ff02::1", port), hostList("192.0.2.10"), true},
		{"another subnet's broadcast", sockaddrIn4("192.0.3.255", port), hostList("192.0.2.10"), false},
		{"another host", sockaddrIn4("203.0.113.7", port), hostList("192.0.2.10"), false},
		{"the host unknown", sockaddrIn4("203.0.113.7", port), func() ([]net.Addr, error) { return nil, errors.New("no netlink") }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			thisHost = newHostAddrs(c.list, nil, time.Now)
			f := newFake()
			f.put(addr, c.sa)
			f.sockType = unix.SOCK_STREAM
			pol := contractPolicy(&agent.Contract{}, nil, nil)
			pol.Rules.Record = agent.RecordFull
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(c.sa))))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 && c.refused {
				t.Fatalf("a connect the block names was continued: %+v", got)
			}
			if connected := len(f.connects) > 0; connected == c.refused {
				t.Errorf("connected = %v, want %v", connected, !c.refused)
			}
			ev := sink.one(t)
			if refused := ev.Verdict == record.VerdictRefused && ev.Rule == rule; refused != c.refused {
				t.Errorf("line %s %s, want refused under the block: %v", ev.Verdict, ev.Rule, c.refused)
			}
		})
	}
}

func hostList(addrs ...string) func() ([]net.Addr, error) {
	return func() ([]net.Addr, error) {
		var out []net.Addr
		for _, a := range addrs {
			out = append(out, &net.IPNet{IP: net.ParseIP(a), Mask: net.CIDRMask(24, 32)})
		}
		return out, nil
	}
}

// hostTable is the local routing table of hostList("192.0.2.10")'s host as the kernel keeps it once an AnyIP range is
// routed to loopback (`ip route add local 198.51.100.0/24 dev lo`), the address's broadcast is also set by hand to
// 192.0.2.100 (`ip addr ... brd`), and IPv6 forwarding is on, so the host joined its subnet's router anycast address.
func hostTable() (hostaddr.LocalTable, error) {
	p := netip.MustParsePrefix
	return hostaddr.LocalTable{
		Local:     []netip.Prefix{p("127.0.0.0/8"), p("127.0.0.1/32"), p("192.0.2.10/32"), p("198.51.100.0/24")},
		Broadcast: []netip.Prefix{p("127.255.255.255/32"), p("192.0.2.100/32"), p("192.0.2.255/32")},
		Anycast:   []netip.Prefix{p("2001:db8:1::/128")},
	}, nil
}

// TestLiveBlockReachesWhatTheLocalTableSendsHere: what the kernel's local routing table sends to this host is this host
// to a block on it, under a contract with no net: section: an address of an AnyIP range, which a server on all
// interfaces answers on, and a broadcast address set by hand or an IPv6 anycast address the host joined, which such a
// server hears. Read from the interfaces' addresses alone, each went through a block on loopback. A block on an AnyIP
// address names this host too, so it refuses loopback on its port; an anycast address names no host, as a group or a
// broadcast address does not.
func TestLiveBlockReachesWhatTheLocalTableSendsHere(t *testing.T) {
	const addr, port = 0x40000, 39512
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	thisHost = newHostAddrs(hostList("192.0.2.10"), hostTable, time.Now)
	for _, c := range []struct {
		name, block string
		sa          []byte
		refused     bool
	}{
		{"an AnyIP range's address", "127.0.0.1:39512", sockaddrIn4("198.51.100.7", port), true},
		{"an AnyIP range's address, mapped", "127.0.0.1:39512", sockaddrIn6("::ffff:198.51.100.7", port), true},
		{"a broadcast address set by hand", "127.0.0.1:39512", sockaddrIn4("192.0.2.100", port), true},
		{"an IPv6 anycast address the host joined", "[::1]:39512", sockaddrIn6("2001:db8:1::", port), true},
		{"past the AnyIP range", "127.0.0.1:39512", sockaddrIn4("198.51.101.7", port), false},
		{"a block on an AnyIP address, loopback", "198.51.100.7:39512", sockaddrIn4("127.0.0.1", port), true},
		{"a block on an AnyIP address, the host's LAN address", "198.51.100.7:39512", sockaddrIn4("192.0.2.10", port), true},
		{"a block on an anycast address, loopback", "[2001:db8:1::]:39512", sockaddrIn6("::1", port), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			set := liveSet(t, "net", c.block)
			f := newFake()
			f.put(addr, c.sa)
			f.sockType = unix.SOCK_STREAM
			pol := contractPolicy(&agent.Contract{}, nil, nil)
			pol.Rules.Record = agent.RecordFull
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(c.sa))))
			if connected := len(f.connects) > 0; connected == c.refused {
				t.Errorf("connected = %v, want %v", connected, !c.refused)
			}
			ev := sink.one(t)
			if refused := ev.Verdict == record.VerdictRefused && ev.Rule == "live.block[net:"+c.block+"]"; refused != c.refused {
				t.Errorf("line %s %s, want refused under the block: %v", ev.Verdict, ev.Rule, c.refused)
			}
		})
	}
}

// newTestLoopOpts is newTestLoop with opts beside the fake kernel and one worker.
func newTestLoopOpts(t *testing.T, f *fakeKernel, pol *Policy, opts Options) (*Loop, *testSink) {
	t.Helper()
	sink := &testSink{}
	opts.kernel, opts.Workers = f, 1
	l, err := New(testListener(), pol, sink, opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, sink
}
