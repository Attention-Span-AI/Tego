// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/internal/platform/hostaddr"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// rebindResolver answers every lookup with whatever addrs holds at the time, so a test can change a
// name's answer between compile and a refresh, as a rebinding DNS server does.
type rebindResolver struct {
	mu    sync.Mutex
	addrs []netip.Addr
}

func (r *rebindResolver) LookupNetIP(context.Context, string, string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.Addr(nil), r.addrs...), nil
}

// connectOnce drives one connect to sa through a loop over pol and returns the response and the one event.
func connectOnce(t *testing.T, pol *Policy, sa []byte) (sysResp, *record.Event, *fakeKernel) {
	t.Helper()
	const addr = 0x40000
	f := newFake()
	f.put(addr, sa)
	f.sockType = unix.SOCK_STREAM
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	return got, sink.one(t), f
}

// TestConnectRefusesDeniedResolvedAddress is R7's resolved-address check (agent-contract R18): a host
// entry that a TTL refresh re-pointed at the cloud metadata endpoint does not admit it, and the refusal
// names the entry; an address Compile already dropped is refused under the same name; a literal entry for
// the same address, a localhost name on loopback and the entry's other addresses still connect.
func TestConnectRefusesDeniedResolvedAddress(t *testing.T) {
	lookup := &rebindResolver{addrs: []netip.Addr{netip.MustParseAddr("93.184.216.34")}}
	now := time.Unix(1_700_000_000, 0)
	host := netRule("rebind.example:80", "rebind.example", 80, "93.184.216.34")
	host.Static, host.ResolvedAt = false, now
	dropped := netRule("dev.example:3000", "dev.example", 3000)
	dropped.Denied = []netip.Addr{netip.MustParseAddr("127.0.0.1")}
	rules := []agent.NetRule{
		host, dropped,
		netRule("169.254.169.254:8080", "169.254.169.254", 8080, "169.254.169.254"),
		netRule("localhost:11434", "localhost", 11434, "127.0.0.1"),
	}
	set := dns.NewSet(rules, nil, dns.Options{Lookup: lookup, MinTTL: time.Second, Now: func() time.Time { return now }})
	pol := testPolicy(rules, nil, nil)
	pol.Resolver = staticResolver{set: set}

	// The rebinding answer arrives on the next refresh, after compile saw only the public address.
	lookup.mu.Lock()
	lookup.addrs = []netip.Addr{netip.MustParseAddr("169.254.169.254"), netip.MustParseAddr("93.184.216.34")}
	lookup.mu.Unlock()
	now = now.Add(time.Hour)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := set.Match(netip.MustParseAddrPort("169.254.169.254:80"), protoTCP); m == nil {
		t.Fatal("the fixture needs the refresh to have brought the metadata address into the set")
	}

	cases := []struct {
		name, dst, rule, host string
		allowed               bool
	}{
		{"refreshed metadata address", "169.254.169.254:80", agent.DeniedResolvedRule("rebind.example:80"), "rebind.example", false},
		{"the entry's public address", "93.184.216.34:80", "net[rebind.example:80]", "rebind.example", true},
		{"an address compile dropped", "127.0.0.1:3000", agent.DeniedResolvedRule("dev.example:3000"), "dev.example", false},
		{"a declared literal", "169.254.169.254:8080", "net[169.254.169.254:8080]", "169.254.169.254", true},
		{"a localhost name on loopback", "127.0.0.1:11434", "net[localhost:11434]", "localhost", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ap := netip.MustParseAddrPort(c.dst)
			resp, ev, f := connectOnce(t, pol, sockaddrIn4(ap.Addr().String(), ap.Port()))
			if c.allowed != (len(f.connects) == 1) {
				t.Fatalf("connect performed = %v, want %v", len(f.connects) == 1, c.allowed)
			}
			if !c.allowed && resp.Error != -int32(unix.EACCES) {
				t.Errorf("errno %d, want EACCES", resp.Error)
			}
			wantVerdict, wantReason := record.VerdictAllow, record.Reason("")
			if !c.allowed {
				wantVerdict, wantReason = record.VerdictRefused, record.ReasonNetNotAllowed
			}
			if ev.Rule != c.rule || ev.Verdict != wantVerdict || ev.Reason != wantReason {
				t.Errorf("event %s/%s/%s, want %s/%s/%s", ev.Rule, ev.Verdict, ev.Reason, c.rule, wantVerdict, wantReason)
			}
			var p record.NetPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.Host != c.host || p.Dst != c.dst {
				t.Errorf("payload %+v, want host %s dst %s", p, c.host, c.dst)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("event does not validate: %v", err)
			}
		})
	}

	// Another entry that admits the address on its own admits it behind the refused one: a declared localhost
	// name on loopback, read with its live addresses from the resolver (the set itself, as the runtime hands it).
	withLocal := []agent.NetRule{dropped, netRule("localhost:3000", "localhost", 3000, "127.0.0.1")}
	polLocal := testPolicy(withLocal, nil, nil)
	if _, ev, f := connectOnce(t, polLocal, sockaddrIn4("127.0.0.1", 3000)); len(f.connects) != 1 || ev.Rule != "net[localhost:3000]" {
		t.Errorf("a declared localhost entry behind a name compile dropped loopback from: connects %d, rule %s", len(f.connects), ev.Rule)
	}

	// A literal entry on the same port as the host entry that refused the address admits it: the author
	// wrote that address, and dns.Set.Match returning the host entry first must not hide the literal.
	both := append([]agent.NetRule{host}, netRule("169.254.169.254:80", "169.254.169.254", 80, "169.254.169.254"))
	pol2 := testPolicy(both, nil, nil)
	pol2.Resolver = staticResolver{set: set}
	if _, ev, f := connectOnce(t, pol2, sockaddrIn4("169.254.169.254", 80)); len(f.connects) != 1 || ev.Rule != "net[169.254.169.254:80]" {
		t.Errorf("a declared literal behind a refused host entry: connects %d, rule %s", len(f.connects), ev.Rule)
	}
}

// nameResolver answers each name from its own entry of table, which a test can change between compile and a
// refresh, as a rebinding DNS server does for one name and not another.
type nameResolver struct {
	mu    sync.Mutex
	table map[string][]netip.Addr
}

func (r *nameResolver) set(name string, addrs ...string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var as []netip.Addr
	for _, a := range addrs {
		as = append(as, netip.MustParseAddr(a))
	}
	r.table[name] = as
}

func (r *nameResolver) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]netip.Addr(nil), r.table[host]...), nil
}

// hostRule is a host entry the resolver re-resolves on refresh, as compile leaves one.
func hostRule(raw, host string, port int, now time.Time, ips ...string) agent.NetRule {
	r := netRule(raw, host, port, ips...)
	r.Static, r.ResolvedAt = false, now
	return r
}

// TestConnectAdmitsAnotherEntryBehindARefusedName: dns.Set.Match returns the first entry whose live addresses
// hold a destination. When a refresh rebinds an earlier host entry to loopback, that entry may not admit it,
// and a later entry that does — here a declared localhost name, which keeps the loopback class (R18) — must
// still admit it, as Evaluate does. The search read only literal and CIDR entries, so the connect was
// refused as net.denied_resolved[dev.example:3000] although localhost:3000 was declared.
func TestConnectAdmitsAnotherEntryBehindARefusedName(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lookup := &nameResolver{table: map[string][]netip.Addr{}}
	lookup.set("dev.example", "93.184.216.34")
	lookup.set("localhost", "127.0.0.1")
	rules := []agent.NetRule{
		hostRule("dev.example:3000", "dev.example", 3000, now, "93.184.216.34"),
		hostRule("localhost:3000", "localhost", 3000, now, "127.0.0.1"),
	}
	set := dns.NewSet(rules, nil, dns.Options{Lookup: lookup, MinTTL: time.Second, Now: func() time.Time { return now }})
	pol := testPolicy(rules, nil, nil)
	pol.Resolver = set

	if _, ev, f := connectOnce(t, pol, sockaddrIn4("127.0.0.1", 3000)); len(f.connects) != 1 || ev.Rule != "net[localhost:3000]" {
		t.Fatalf("before the refresh: connects %d, rule %s, want the localhost entry", len(f.connects), ev.Rule)
	}
	lookup.set("dev.example", "127.0.0.1")
	now = now.Add(time.Hour)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if m := set.Match(netip.MustParseAddrPort("127.0.0.1:3000"), protoTCP); m == nil || m.Raw != "dev.example:3000" {
		t.Fatalf("the fixture needs dev.example first in the set for loopback, got %+v", m)
	}
	resp, ev, f := connectOnce(t, pol, sockaddrIn4("127.0.0.1", 3000))
	if len(f.connects) != 1 || ev.Rule != "net[localhost:3000]" || ev.Verdict != record.VerdictAllow {
		t.Fatalf("after the refresh: connects %d, errno %d, event %s/%s, want the declared localhost entry to admit it",
			len(f.connects), resp.Error, ev.Rule, ev.Verdict)
	}
	// Another host name is searched as well, and admits the address only when its own check allows it: a
	// second ordinary name rebound to loopback is refused like the first, under the first entry's name.
	lookup.set("mirror.example", "127.0.0.1")
	rules2 := []agent.NetRule{rules[0], hostRule("mirror.example:3000", "mirror.example", 3000, now, "127.0.0.1")}
	set2 := dns.NewSet(rules2, nil, dns.Options{Lookup: lookup, MinTTL: time.Second, Now: func() time.Time { return now }})
	if err := set2.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	pol2 := testPolicy(rules2, nil, nil)
	pol2.Resolver = set2
	if _, ev, f := connectOnce(t, pol2, sockaddrIn4("127.0.0.1", 3000)); len(f.connects) != 0 || ev.Rule != agent.DeniedResolvedRule("dev.example:3000") {
		t.Errorf("a second name on loopback is refused like the first: connects %d, rule %s", len(f.connects), ev.Rule)
	}
}

// TestConnectRefusesAPrivateRebindOfAPublicName is R18's private class: a name whose compile-time answer was
// public only (NetRule.PublicAnswer) stands for a service on the internet, and a refresh that rebinds it to a
// private address (DNS rebinding towards the host's own network) is refused under the entry's name. A name
// whose first answer was already private (split-horizon DNS) keeps private addresses, and a declared CIDR
// admits the address on purpose.
func TestConnectRefusesAPrivateRebindOfAPublicName(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	lookup := &nameResolver{table: map[string][]netip.Addr{}}
	lookup.set("api.example", "93.184.216.34")
	lookup.set("git.corp", "10.0.0.7")
	public := hostRule("api.example:443", "api.example", 443, now, "93.184.216.34")
	public.PublicAnswer = true
	internal := hostRule("git.corp:443", "git.corp", 443, now, "10.0.0.7")
	rules := []agent.NetRule{public, internal}
	set := dns.NewSet(rules, nil, dns.Options{Lookup: lookup, MinTTL: time.Second, Now: func() time.Time { return now }})
	pol := testPolicy(rules, nil, nil)
	pol.Resolver = set

	lookup.set("api.example", "10.0.0.5")
	lookup.set("git.corp", "10.0.0.8")
	now = now.Add(time.Hour)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	resp, ev, f := connectOnce(t, pol, sockaddrIn4("10.0.0.5", 443))
	if len(f.connects) != 0 || resp.Error != -int32(unix.EACCES) || ev.Rule != agent.DeniedResolvedRule("api.example:443") {
		t.Errorf("a public name rebound to 10.0.0.5: connects %d, errno %d, rule %s; want refused under the entry",
			len(f.connects), resp.Error, ev.Rule)
	}
	if _, ev, f := connectOnce(t, pol, sockaddrIn4("10.0.0.8", 443)); len(f.connects) != 1 || ev.Rule != "net[git.corp:443]" {
		t.Errorf("a split-horizon name keeps private addresses: connects %d, rule %s", len(f.connects), ev.Rule)
	}
	withCIDR := append(append([]agent.NetRule(nil), rules...), agent.NetRule{
		Raw: "10.0.0.0/8:443", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true,
		CIDR: func() *netip.Prefix { p := netip.MustParsePrefix("10.0.0.0/8"); return &p }(),
	})
	pol2 := testPolicy(withCIDR, nil, nil)
	pol2.Resolver = set
	if _, ev, f := connectOnce(t, pol2, sockaddrIn4("10.0.0.5", 443)); len(f.connects) != 1 || ev.Rule != "net[10.0.0.0/8:443]" {
		t.Errorf("a declared CIDR admits the address on purpose: connects %d, rule %s", len(f.connects), ev.Rule)
	}

	// When both names come to resolve to the same private address, the public one refuses it and the
	// split-horizon one, searched behind it with its live answer, admits it.
	lookup.set("git.corp", "10.0.0.5")
	now = now.Add(time.Hour)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ev, f := connectOnce(t, pol, sockaddrIn4("10.0.0.5", 443)); len(f.connects) != 1 || ev.Rule != "net[git.corp:443]" {
		t.Errorf("another name whose own check allows the address admits it: connects %d, rule %s", len(f.connects), ev.Rule)
	}
}

// The package's tests start from a snapshot of this host's addresses that holds none, so no test's verdict
// depends on the addresses of the machine it runs on (a test name answered with 10.0.0.5 would be refused on
// a machine that holds 10.0.0.5). A test of the snapshot itself installs its own (useHostAddrs).
func init() {
	thisHost = newHostAddrs(func() ([]net.Addr, error) { return nil, nil }, nil, time.Now)
}

// fakeHostAddrs is a list of this host's addresses a test can change, or make fail, between two snapshots.
type fakeHostAddrs struct {
	mu    sync.Mutex
	addrs []string
	err   error
	calls int
}

func (f *fakeHostAddrs) list() ([]net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	var out []net.Addr
	for _, a := range f.addrs {
		ip := netip.MustParseAddr(a)
		bits := 32
		if ip.Is6() {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: net.IP(ip.AsSlice()), Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

func (f *fakeHostAddrs) set(err error, addrs ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs, f.err = addrs, err
}

// useHostAddrs installs a snapshot over f, read at the time now returns, for the rest of the test.
func useHostAddrs(t *testing.T, f *fakeHostAddrs, now func() time.Time) {
	t.Helper()
	prev := thisHost
	thisHost = newHostAddrs(f.list, nil, now)
	t.Cleanup(func() { thisHost = prev })
}

// TestConnectRefusesThisHostsAddress is R7's resolved-address check for this host's own addresses
// (agent-contract R18): a name that resolves to the host's LAN or global address reaches every service
// bound to all interfaces, as loopback does, so a host entry does not admit one, IPv4 or IPv6, and the
// refusal names the entry. A localhost name keeps the loopback class, and a literal or CIDR entry the author
// wrote admits the address on purpose. The entry's other, remote, addresses still connect.
func TestConnectRefusesThisHostsAddress(t *testing.T) {
	host := &fakeHostAddrs{addrs: []string{"127.0.0.1", "::1", "192.0.2.10", "2001:db8::10"}}
	useHostAddrs(t, host, time.Now)
	cidr := netip.MustParsePrefix("192.0.2.0/24")
	rules := []agent.NetRule{
		netRule("mirror.example:8080", "mirror.example", 8080, "192.0.2.10", "93.184.216.34"),
		netRule("v6.example:8080", "v6.example", 8080, "2001:db8::10"),
		netRule("localhost:9000", "localhost", 9000, "192.0.2.10"),
		netRule("192.0.2.10:7000", "192.0.2.10", 7000, "192.0.2.10"),
		{Raw: "192.0.2.0/24:6000", Port: 6000, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true, CIDR: &cidr},
	}
	pol := testPolicy(rules, nil, nil)
	cases := []struct {
		name string
		sa   []byte
		rule string
		ok   bool
	}{
		{"a name on this host's IPv4 address", sockaddrIn4("192.0.2.10", 8080), agent.DeniedResolvedRule("mirror.example:8080"), false},
		{"the same name's remote address", sockaddrIn4("93.184.216.34", 8080), "net[mirror.example:8080]", true},
		{"a name on this host's global IPv6 address", sockaddrIn6("2001:db8::10", 8080), agent.DeniedResolvedRule("v6.example:8080"), false},
		{"a localhost name", sockaddrIn4("192.0.2.10", 9000), "net[localhost:9000]", true},
		{"a declared literal", sockaddrIn4("192.0.2.10", 7000), "net[192.0.2.10:7000]", true},
		{"a declared CIDR", sockaddrIn4("192.0.2.10", 6000), "net[192.0.2.0/24:6000]", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp, ev, f := connectOnce(t, pol, c.sa)
			if c.ok != (len(f.connects) == 1) || ev.Rule != c.rule {
				t.Fatalf("connects %d, errno %d, rule %s; want allowed %v under %s", len(f.connects), resp.Error, ev.Rule, c.ok, c.rule)
			}
			if !c.ok && (resp.Error != -int32(unix.EACCES) || ev.Reason != record.ReasonNetNotAllowed) {
				t.Errorf("errno %d, reason %s; want EACCES, %s", resp.Error, ev.Reason, record.ReasonNetNotAllowed)
			}
		})
	}
}

// TestConnectRefusesAnAddressTheLocalTableSendsHere is R18's this-host class read as a live block, a net gate and the
// models[] guard read this host: an address of an AnyIP range the local routing table sends here
// (`ip route add local 198.51.100.0/24 dev lo`) reaches every service bound to all interfaces as the host's LAN
// address does, so a host entry rebound into the range does not admit it, plain or v4-mapped, and the refusal names
// the entry. Read from the interfaces alone it was admitted. A localhost name, a declared literal and a declared CIDR
// keep it, and an address past the range still connects.
func TestConnectRefusesAnAddressTheLocalTableSendsHere(t *testing.T) {
	prev := thisHost
	t.Cleanup(func() { thisHost = prev })
	thisHost = newHostAddrs(hostList("192.0.2.10"), hostTable, time.Now)
	cidr := netip.MustParsePrefix("198.51.100.0/24")
	rules := []agent.NetRule{
		netRule("anyip.example:8080", "anyip.example", 8080, "198.51.100.7", "198.51.101.7"),
		netRule("localhost:9000", "localhost", 9000, "198.51.100.7"),
		netRule("198.51.100.7:7000", "198.51.100.7", 7000, "198.51.100.7"),
		{Raw: "198.51.100.0/24:6000", Port: 6000, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, Static: true, CIDR: &cidr},
	}
	pol := testPolicy(rules, nil, nil)
	for _, c := range []struct {
		name string
		sa   []byte
		rule string
		ok   bool
	}{
		{"a name rebound into the AnyIP range", sockaddrIn4("198.51.100.7", 8080), agent.DeniedResolvedRule("anyip.example:8080"), false},
		{"the same, v4-mapped", sockaddrIn6("::ffff:198.51.100.7", 8080), agent.DeniedResolvedRule("anyip.example:8080"), false},
		{"the same name past the range", sockaddrIn4("198.51.101.7", 8080), "net[anyip.example:8080]", true},
		{"a localhost name", sockaddrIn4("198.51.100.7", 9000), "net[localhost:9000]", true},
		{"a declared literal", sockaddrIn4("198.51.100.7", 7000), "net[198.51.100.7:7000]", true},
		{"a declared CIDR", sockaddrIn4("198.51.100.7", 6000), "net[198.51.100.0/24:6000]", true},
	} {
		t.Run(c.name, func(t *testing.T) {
			resp, ev, f := connectOnce(t, pol, c.sa)
			if c.ok != (len(f.connects) == 1) || ev.Rule != c.rule {
				t.Fatalf("connects %d, errno %d, rule %s; want allowed %v under %s", len(f.connects), resp.Error, ev.Rule, c.ok, c.rule)
			}
		})
	}
}

// TestThisHostSnapshot pins how the snapshot of this host's addresses is kept: retaken once it is older
// than maxAge, so an address the host gains (a VPN coming up) is refused within a second; kept when a retake
// fails, since the host's addresses rarely change; and, while no snapshot was ever taken, refusing every
// host entry's destination (fail-closed), while a literal entry and a localhost name still connect.
func TestThisHostSnapshot(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	host := &fakeHostAddrs{addrs: []string{"127.0.0.1"}}
	useHostAddrs(t, host, func() time.Time { return now })
	rules := []agent.NetRule{
		netRule("mirror.example:8080", "mirror.example", 8080, "198.51.100.7"),
		netRule("other.example:8080", "other.example", 8080, "203.0.113.9"),
		netRule("198.51.100.7:7000", "198.51.100.7", 7000, "198.51.100.7"),
		netRule("localhost:9000", "localhost", 9000, "127.0.0.1"),
	}
	pol := testPolicy(rules, nil, nil)
	connects := func(ip string, port uint16) bool {
		t.Helper()
		_, _, f := connectOnce(t, pol, sockaddrIn4(ip, port))
		return len(f.connects) == 1
	}
	if !connects("198.51.100.7", 8080) {
		t.Fatal("before the host holds 198.51.100.7 the name connects")
	}
	host.set(nil, "127.0.0.1", "198.51.100.7")
	if !connects("198.51.100.7", 8080) {
		t.Error("within maxAge the snapshot is not retaken")
	}
	now = now.Add(2 * time.Second)
	if connects("198.51.100.7", 8080) {
		t.Error("once the snapshot is older than maxAge it is retaken, and the host's new address refused")
	}
	host.set(errors.New("netlink: no buffer space"))
	now = now.Add(2 * time.Second)
	if connects("198.51.100.7", 8080) || !connects("203.0.113.9", 8080) {
		t.Error("a failed retake keeps the last snapshot: the host's address refused, a remote one admitted")
	}

	failing := &fakeHostAddrs{err: errors.New("socket: permission denied")}
	useHostAddrs(t, failing, func() time.Time { return now })
	if connects("198.51.100.7", 8080) {
		t.Error("with no snapshot ever taken a host entry's destination is refused")
	}
	if !connects("198.51.100.7", 7000) || !connects("127.0.0.1", 9000) {
		t.Error("a literal entry and a localhost name need no snapshot")
	}
	calls := failing.calls
	connects("198.51.100.7", 8080)
	if failing.calls != calls {
		t.Error("a failed first snapshot is retried after maxAge, not on every connect")
	}
}

// TestThisHostSnapshotReal takes the snapshot the supervisor takes, through netlink, as whoever runs the test:
// it needs no privilege, so it must be known. The resolved-address check reads the local routing table with the
// addresses: 127.0.0.2 is no interface's address, and it is this host's own by the `local 127.0.0.0/8` route the
// kernel keeps for loopback, as an AnyIP range's addresses are by theirs.
func TestThisHostSnapshotReal(t *testing.T) {
	h := newHostAddrs(net.InterfaceAddrs, hostaddr.ReadLocalTable, time.Now)
	local, known := h.has(netip.MustParseAddr("127.0.0.1"))
	if !known {
		t.Fatal("net.InterfaceAddrs failed unprivileged; every host entry would be refused")
	}
	t.Logf("127.0.0.1 held by this host: %v", local)
	if local, _ := h.has(netip.MustParseAddr("127.0.0.2")); !local {
		t.Error("127.0.0.2, in the local table's 127.0.0.0/8, is not this host's own to the resolved-address check")
	}
}
