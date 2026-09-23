// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestTheRunsDNSWorkerNeverHandsTheTierARefusedAddress is agent-contract R18 at tier 2: the worker
// startNotifyLoop starts builds its set with the run's own resolved-address check, so a refresh that rebinds a
// host name to the cloud metadata endpoint moves the tier's rows to the public address alone. Without the check
// the rows followed every answer, and a kernel row admitted 169.254.169.254 for the name while the supervisor
// refused each connect it saw there.
func TestTheRunsDNSWorkerNeverHandsTheTierARefusedAddress(t *testing.T) {
	h := &refreshingHandle{called: make(chan struct{}, 1)}
	r := dnsRunner(h)
	r.log = slog.New(slog.DiscardHandler)
	r.dnsTick = time.Millisecond
	r.dnsOptions = dns.Options{MinTTL: time.Millisecond, Lookup: &rotatingLookup{answers: [][]netip.Addr{
		{netip.MustParseAddr("203.0.113.9"), netip.MustParseAddr("169.254.169.254")}}}}
	startedNotifyLoop(t, r)
	select {
	case <-h.called:
	case <-time.After(5 * time.Second):
		t.Fatal("the run's DNS worker never handed the tier a refresh that moved a host's addresses")
	}
	got := h.got()[0].Net[0]
	if want := []netip.Addr{netip.MustParseAddr("203.0.113.9")}; !slices.Equal(got.IPs, want) {
		t.Fatalf("the tier was handed %v for the host entry, want %v: the metadata endpoint reached a kernel row", got.IPs, want)
	}
	if !slices.Contains(got.Denied, netip.MustParseAddr("169.254.169.254")) {
		t.Errorf("the refused address is not in the entry's Denied: %v", got.Denied)
	}
	if m := r.dnsSet.Match(netip.MustParseAddrPort("169.254.169.254:443"), dns.ProtoTCP); m == nil {
		t.Error("the supervisor's set no longer matches the entry, so its refusal would read unmatched, not net.denied_resolved")
	}
}

// fakeHost is a host whose interface addresses a test sets, and changes, for hostAddrs.
type fakeHost struct {
	mu    sync.Mutex
	addrs []string // CIDR notation, as an interface carries them
	err   error
}

func (h *fakeHost) set(addrs ...string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.addrs = addrs
}

func (h *fakeHost) list() ([]net.Addr, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.err != nil {
		return nil, h.err
	}
	var out []net.Addr
	for _, s := range h.addrs {
		ip, ipn, err := net.ParseCIDR(s)
		if err != nil {
			panic(err)
		}
		ipn.IP = ip
		out = append(out, ipn)
	}
	return out, nil
}

// handedUntil waits for the tier to be handed a table whose first entry holds exactly want, and fails the test
// with every table it was handed when none does within 5 s.
func handedUntil(t *testing.T, h *refreshingHandle, want ...string) *agent.RuleTable {
	t.Helper()
	var addrs []netip.Addr
	for _, s := range want {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		for _, rt := range h.got() {
			if sameNetAddrs(rt.Net[:1], []agent.NetRule{{IPs: addrs}}) {
				return rt
			}
		}
		if time.Now().After(deadline) {
			var seen [][]netip.Addr
			for _, rt := range h.got() {
				seen = append(seen, rt.Net[0].IPs)
			}
			t.Fatalf("the tier was never handed %v for the host entry; it was handed %v", addrs, seen)
		}
	}
}

// TestTheRunsDNSWorkerKeepsThisHostsAddressesOutOfTheTiersRows is agent-contract R18's last class at tier 2: a
// host name that resolves, or is rebound, to one of this host's own interface addresses never becomes a kernel
// row admitting it, in each way the address can reach the rows. Without refreshDenied's snapshot the set's filter
// knew only the table's classes, so the host's LAN address stayed a row that decided a datagram a sibling thread
// rewrote after the supervisor read it (supervisor R13b), while the supervisor refused every connect it saw there.
func TestTheRunsDNSWorkerKeepsThisHostsAddressesOutOfTheTiersRows(t *testing.T) {
	start := func(t *testing.T, host *fakeHost, answers ...[]netip.Addr) (*refreshingHandle, *runner) {
		t.Helper()
		h := &refreshingHandle{called: make(chan struct{}, 1)}
		r := dnsRunner(h)
		r.dnsTick = time.Millisecond
		r.hostAddrs = newHostAddrs(host.list, time.Now, time.Millisecond)
		r.dnsOptions = dns.Options{MinTTL: time.Millisecond, Lookup: &rotatingLookup{answers: answers}}
		return h, r
	}
	a := netip.MustParseAddr

	t.Run("a refresh that brings one in", func(t *testing.T) {
		host := &fakeHost{addrs: []string{"127.0.0.1/8", "198.51.100.77/24"}}
		h, r := start(t, host, []netip.Addr{a("203.0.113.9"), a("198.51.100.77")})
		startedNotifyLoop(t, r)
		got := handedUntil(t, h, "203.0.113.9").Net[0]
		if !slices.Contains(got.Denied, a("198.51.100.77")) {
			t.Errorf("this host's address is not in the entry's Denied: %v", got.Denied)
		}
		for _, rt := range h.got() {
			if slices.Contains(rt.Net[0].IPs, a("198.51.100.77")) {
				t.Fatalf("the tier was handed this host's own address for the host entry: %v", rt.Net[0].IPs)
			}
		}
	})

	t.Run("the host takes an address the name already holds", func(t *testing.T) {
		host := &fakeHost{addrs: []string{"127.0.0.1/8", "10.9.9.9/8"}}
		h, r := start(t, host, []netip.Addr{a("203.0.113.9"), a("198.51.100.77")})
		startedNotifyLoop(t, r)
		handedUntil(t, h, "203.0.113.9", "198.51.100.77")
		// The DNS answer stays as it is; only the host changes, so only a worker that follows the snapshot moves
		// the rows.
		host.set("127.0.0.1/8", "198.51.100.77/24")
		handedUntil(t, h, "203.0.113.9")
		host.set("127.0.0.1/8", "10.9.9.9/8")
		handedUntil(t, h, "203.0.113.9", "198.51.100.77")
	})

	t.Run("the compile-time answer held one", func(t *testing.T) {
		host := &fakeHost{addrs: []string{"127.0.0.1/8", "198.51.100.4/24"}}
		h, r := start(t, host, []netip.Addr{a("198.51.100.4"), a("203.0.113.9")})
		r.rt.Net[0].IPs = []netip.Addr{a("198.51.100.4"), a("203.0.113.9")}
		startedNotifyLoop(t, r)
		handedUntil(t, h, "203.0.113.9")
	})

	t.Run("no snapshot of the host's addresses", func(t *testing.T) {
		host := &fakeHost{err: errors.New("netlink: EPERM")}
		h, r := start(t, host, []netip.Addr{a("203.0.113.9")})
		startedNotifyLoop(t, r)
		handedUntil(t, h)
		for _, rt := range h.got() {
			if len(rt.Net[0].IPs) != 0 {
				t.Fatalf("with no snapshot the tier was handed %v for the host entry, want nothing", rt.Net[0].IPs)
			}
		}
	})

	t.Run("a localhost name keeps loopback", func(t *testing.T) {
		host := &fakeHost{addrs: []string{"127.0.0.1/8", "::1/128"}}
		h, r := start(t, host, []netip.Addr{a("127.0.0.1"), a("::1")})
		r.rt.Net[0] = agent.NetRule{Raw: "localhost:3000", Host: "localhost", Port: 3000, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{a("127.0.0.1")}, TTL: time.Millisecond}
		startedNotifyLoop(t, r)
		handedUntil(t, h, "127.0.0.1", "::1")
	})
}

// TestSameNetAddrs: the worker hands the tier a table only when an entry's addresses differ as the rows key them,
// in any order and with an IPv4 address and its v4-mapped form as one.
func TestSameNetAddrs(t *testing.T) {
	e := func(addrs ...string) agent.NetRule {
		var r agent.NetRule
		for _, s := range addrs {
			r.IPs = append(r.IPs, netip.MustParseAddr(s))
		}
		return r
	}
	cases := []struct {
		a, b []agent.NetRule
		same bool
	}{
		{[]agent.NetRule{e("192.0.2.1", "192.0.2.2")}, []agent.NetRule{e("192.0.2.2", "192.0.2.1")}, true},
		{[]agent.NetRule{e("192.0.2.1")}, []agent.NetRule{e("::ffff:192.0.2.1")}, true},
		{[]agent.NetRule{e("192.0.2.1")}, []agent.NetRule{e("192.0.2.1", "192.0.2.2")}, false},
		{[]agent.NetRule{e("192.0.2.1")}, []agent.NetRule{e()}, false},
		{[]agent.NetRule{e("192.0.2.1"), e()}, []agent.NetRule{e("192.0.2.1")}, false},
		{[]agent.NetRule{e(), e("192.0.2.3")}, []agent.NetRule{e(), e("192.0.2.3")}, true},
	}
	for i, tc := range cases {
		if got := sameNetAddrs(tc.a, tc.b); got != tc.same {
			t.Errorf("case %d: sameNetAddrs = %v, want %v", i, got, tc.same)
		}
	}
}

// TestTheTierIsPreparedWithoutThisHostsAddresses: the table tier 2 writes its first rows from holds none of this
// host's own addresses for a host name, so a compile-time answer that held one (Compile cannot know them) is never
// a row, not even until the DNS worker's first pass, and an entry whose every address is one gets no row rather
// than keeping it for the run, as tier 2 does with an entry a refresh leaves empty. A literal entry and a
// localhost name keep theirs, and the run's own table is not changed. The worker then starts from the rows the
// tier was prepared with, so it hands nothing while neither the answers nor the host move.
func TestTheTierIsPreparedWithoutThisHostsAddresses(t *testing.T) {
	a := netip.MustParseAddr
	h := &refreshingHandle{called: make(chan struct{}, 1)}
	b := &handoffBackend{tier: backend.TierCgroup, handle: h}
	r := handoffRunner(b, Build{})
	host := &fakeHost{addrs: []string{"127.0.0.1/8", "198.51.100.4/24", "192.0.2.1/24", "198.51.100.5/24"}}
	r.hostAddrs = newHostAddrs(host.list, time.Now, time.Millisecond)
	r.rt.Net = []agent.NetRule{
		{Raw: "api.example:443", Host: "api.example", Port: 443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{a("198.51.100.4"), a("203.0.113.9")}, TTL: time.Millisecond},
		{Raw: "192.0.2.1:22", Host: "192.0.2.1", Port: 22, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{a("192.0.2.1")}, Static: true},
		{Raw: "localhost:3000", Host: "localhost", Port: 3000, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{a("127.0.0.1")}, TTL: time.Millisecond},
		{Raw: "lan.example:80", Host: "lan.example", Port: 80, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{a("198.51.100.5")}, TTL: time.Millisecond},
	}
	compiled := slices.Clone(r.rt.Net)
	if err := r.prepareEnforcement(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := b.gotRT.Net
	if want := []netip.Addr{a("203.0.113.9")}; !slices.Equal(got[0].IPs, want) || !slices.Contains(got[0].Denied, a("198.51.100.4")) {
		t.Errorf("host entry prepared with IPs %v Denied %v, want IPs %v and this host's address denied", got[0].IPs, got[0].Denied, want)
	}
	if !slices.Equal(got[1].IPs, compiled[1].IPs) || !slices.Equal(got[2].IPs, compiled[2].IPs) {
		t.Errorf("a literal entry or a localhost name lost an address: %v, %v", got[1].IPs, got[2].IPs)
	}
	if len(got[3].IPs) != 0 {
		t.Errorf("an entry whose only address is this host's was prepared with %v, want none", got[3].IPs)
	}
	for i := range compiled {
		if !slices.Equal(r.rt.Net[i].IPs, compiled[i].IPs) || !slices.Equal(r.rt.Net[i].Denied, compiled[i].Denied) {
			t.Fatalf("the run's own table was changed at entry %d: %+v", i, r.rt.Net[i])
		}
	}

	r.log = slog.New(slog.DiscardHandler)
	r.dnsTick = time.Millisecond
	lk := &hostLookup{answers: map[string][]netip.Addr{
		"api.example": {a("198.51.100.4"), a("203.0.113.9")}, "localhost": {a("127.0.0.1")},
		"lan.example": {a("198.51.100.5")}}}
	r.dnsOptions = dns.Options{MinTTL: time.Millisecond, Lookup: lk}
	startedNotifyLoop(t, r)
	for deadline := time.Now().Add(5 * time.Second); lk.count() < 10; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("%d lookups, want 10 ticks to have re-resolved the hosts", lk.count())
		}
	}
	if tables := h.got(); len(tables) != 0 {
		t.Fatalf("the worker handed the tier %d tables while nothing moved, first %v", len(tables), tables[0].Net)
	}
}

// hostLookup answers each host name with its own fixed addresses, and counts the lookups made.
type hostLookup struct {
	mu      sync.Mutex
	answers map[string][]netip.Addr
	calls   int
}

func (l *hostLookup) LookupNetIP(_ context.Context, _, host string) ([]netip.Addr, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.calls++
	if a, ok := l.answers[host]; ok {
		return a, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
}

func (l *hostLookup) count() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.calls
}
