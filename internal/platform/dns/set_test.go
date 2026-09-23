// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// fakeLookup is a scripted resolver: each host maps to a queue of answers, the last one repeating.
type fakeLookup struct {
	mu      sync.Mutex
	answers map[string][][]netip.Addr
	errs    map[string]error
	calls   map[string]int
	block   chan struct{}
}

func newLookup() *fakeLookup {
	return &fakeLookup{answers: map[string][][]netip.Addr{}, errs: map[string]error{}, calls: map[string]int{}}
}

func (f *fakeLookup) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if f.block != nil {
		select {
		case <-f.block:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls[host]++
	if err := f.errs[host]; err != nil {
		return nil, err
	}
	q := f.answers[host]
	if len(q) == 0 {
		return nil, errors.New("no answer scripted")
	}
	out := q[0]
	if len(q) > 1 {
		f.answers[host] = q[1:]
	}
	return out, nil
}

func (f *fakeLookup) callCount(host string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls[host]
}

func (f *fakeLookup) setErr(host string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.errs[host] = err
}

// addrs parses a list of literals.
func addrs(ss ...string) []netip.Addr {
	out := make([]netip.Addr, len(ss))
	for i, s := range ss {
		out[i] = netip.MustParseAddr(s)
	}
	return out
}

// hostRule is a compiled host entry that a refresh will re-resolve. It carries no name of its own:
// agent.NetRule.RuleName derives one from Raw, which is the entry as the contract declared it.
func hostRule(host string, port int, ips ...string) agent.NetRule {
	return agent.NetRule{
		Raw: host, Host: host, Port: port, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow,
		IPs: addrs(ips...), TTL: time.Minute,
	}
}

// TestMatch covers R7's matching: exact ip:port, cidr:port, port 0 for ICMP/raw, and no default allow.
func TestMatch(t *testing.T) {
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	rules := []agent.NetRule{
		{
			Raw: "api.example.com:443", Host: "api.example.com", Port: 443, Proto: agent.ProtoInet,
			IPs: addrs("93.184.216.34", "2606:2800:220::1"), Verdict: agent.VerdictAllow,
			TTL: time.Hour, ResolvedAt: time.Now(),
		},
		{
			Raw: "10.0.0.0/8:8080", Port: 8080, Proto: agent.ProtoInet, CIDR: &cidr, Static: true,
			Verdict: agent.VerdictAllow,
		},
		{
			Raw: "ping.example.com:0", Host: "ping.example.com", Port: 0, Proto: agent.ProtoInet,
			IPs: addrs("198.51.100.7"), Verdict: agent.VerdictAllow,
		},
		{Raw: "unix:/run/x.sock", Proto: agent.ProtoUnix, UnixPath: "/run/x.sock"},
	}
	s := NewSet(rules, nil, Options{Lookup: newLookup()})
	tests := []struct {
		dst   string
		proto string
		want  string
	}{
		{dst: "93.184.216.34:443", proto: "tcp", want: "net[api.example.com:443]"},
		{dst: "[2606:2800:220::1]:443", proto: "tcp", want: "net[api.example.com:443]"},
		{dst: "93.184.216.34:80", proto: "tcp", want: ""},
		{dst: "10.1.2.3:8080", proto: "udp", want: "net[10.0.0.0/8:8080]"},
		{dst: "11.1.2.3:8080", proto: "tcp", want: ""},
		{dst: "198.51.100.7:0", proto: "raw", want: "net[ping.example.com:0]"},
		{dst: "198.51.100.7:0", proto: "udp", want: "net[ping.example.com:0]"},
		// A port-0 entry is how SEMANTICS §5 spells an ICMP or raw destination. It must not turn into
		// "every port on this host" for a stream or datagram connect.
		{dst: "198.51.100.7:22", proto: "tcp", want: ""},
		{dst: "198.51.100.7:53", proto: "udp", want: ""},
		{dst: "198.51.100.7:65535", proto: "raw", want: "net[ping.example.com:0]"},
		{dst: "203.0.113.1:443", proto: "tcp", want: ""},
		{dst: "[::ffff:93.184.216.34]:443", proto: "tcp", want: "net[api.example.com:443]"},
	}
	for _, tc := range tests {
		got := s.Match(netip.MustParseAddrPort(tc.dst), tc.proto)
		name := ""
		if got != nil {
			name = got.Rule
		}
		if name != tc.want {
			t.Errorf("Match(%s) = %q, want %q", tc.dst, name, tc.want)
		}
	}
	if s.Match(netip.AddrPort{}, "tcp") != nil {
		t.Error("an invalid destination matched")
	}
	if got := s.Match(netip.MustParseAddrPort("93.184.216.34:443"), "tcp"); got.Host != "api.example.com" ||
		got.Raw != "api.example.com:443" || got.Verdict != agent.VerdictAllow {
		t.Errorf("match = %+v, want the declared entry's host, text and verdict", got)
	}
}

// TestRefreshReplacesAndKeepsStale is R8/R8a/E29: a successful lookup replaces the address set, a failing
// one keeps the previous one and leaves the entry due so the next tick retries.
func TestRefreshReplacesAndKeepsStale(t *testing.T) {
	lk := newLookup()
	lk.answers["api.example.com"] = [][]netip.Addr{addrs("203.0.113.5")}
	now := time.Now()
	clock := func() time.Time { return now }
	rules := []agent.NetRule{hostRule("api.example.com", 443, "93.184.216.34")}
	rules[0].ResolvedAt = now
	rules[0].TTL = time.Minute
	s := NewSet(rules, nil, Options{Lookup: lk, Now: clock, MinTTL: time.Second})

	if s.Due() {
		t.Fatal("a freshly resolved rule is due")
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lk.callCount("api.example.com") != 0 {
		t.Error("a rule inside its TTL was re-resolved")
	}

	now = now.Add(2 * time.Minute)
	if !s.Due() {
		t.Fatal("a rule past its TTL is not due")
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Match(netip.MustParseAddrPort("93.184.216.34:443"), "tcp") != nil {
		t.Error("the old address still matches after a successful re-resolution")
	}
	if s.Match(netip.MustParseAddrPort("203.0.113.5:443"), "tcp") == nil {
		t.Error("the new address does not match")
	}

	// A failing lookup keeps what the rule has (R8a).
	now = now.Add(2 * time.Minute)
	lk.setErr("api.example.com", errors.New("SERVFAIL"))
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatalf("a DNS failure surfaced as an error: %v", err)
	}
	if s.Match(netip.MustParseAddrPort("203.0.113.5:443"), "tcp") == nil {
		t.Error("a failed re-resolution emptied the rule's address set (R8a)")
	}
	if !s.Due() {
		t.Error("a failed rule is not due again")
	}
	st := s.Stats()
	if st.Failures != 1 || st.Replaced != 1 || st.Refreshes != 3 {
		t.Errorf("stats = %+v, want one failure, one replacement, three refreshes", st)
	}
}

// TestRefreshEmptyAnswerKeepsStale: NOERROR with no addresses is a failure for matching purposes.
func TestRefreshEmptyAnswerKeepsStale(t *testing.T) {
	lk := newLookup()
	lk.answers["api"] = [][]netip.Addr{{}}
	now := time.Now()
	rules := []agent.NetRule{hostRule("api", 443, "10.0.0.1")}
	s := NewSet(rules, nil, Options{Lookup: lk, Now: func() time.Time { return now }, MinTTL: time.Second})
	now = now.Add(time.Hour)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if s.Match(netip.MustParseAddrPort("10.0.0.1:443"), "tcp") == nil {
		t.Error("an empty answer emptied the address set")
	}
}

// TestRefreshSharesOneLookupPerHost: two entries for one host cost one lookup and both are updated.
func TestRefreshSharesOneLookupPerHost(t *testing.T) {
	lk := newLookup()
	lk.answers["api"] = [][]netip.Addr{addrs("10.0.0.9")}
	now := time.Now()
	rules := []agent.NetRule{hostRule("api", 443, "10.0.0.1"), hostRule("api", 8443, "10.0.0.1")}
	s := NewSet(rules, nil, Options{Lookup: lk, Now: func() time.Time { return now }})
	now = now.Add(time.Hour)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if lk.callCount("api") != 1 {
		t.Errorf("lookups = %d, want one per host", lk.callCount("api"))
	}
	for _, dst := range []string{"10.0.0.9:443", "10.0.0.9:8443"} {
		if s.Match(netip.MustParseAddrPort(dst), "tcp") == nil {
			t.Errorf("%s does not match after the refresh", dst)
		}
	}
}

// TestStaticRulesAreNeverResolved: a literal address or a cidr has no name to look up.
func TestStaticRulesAreNeverResolved(t *testing.T) {
	lk := newLookup()
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	rules := []agent.NetRule{
		{Raw: "10.0.0.1:443", Host: "10.0.0.1", Port: 443, Proto: agent.ProtoInet, Static: true,
			IPs: addrs("10.0.0.1")},
		{Raw: "10.0.0.0/8:80", Port: 80, Proto: agent.ProtoInet, CIDR: &cidr, Static: true},
	}
	s := NewSet(rules, nil, Options{Lookup: lk})
	if s.Due() {
		t.Fatal("a static rule is due")
	}
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(lk.calls) != 0 {
		t.Errorf("static rules caused lookups: %v", lk.calls)
	}
}

// TestMatchIsLockFreeDuringRefresh runs matches while a refresh swaps the table; run with -race.
func TestMatchIsLockFreeDuringRefresh(t *testing.T) {
	lk := newLookup()
	lk.answers["api"] = [][]netip.Addr{addrs("10.0.0.1"), addrs("10.0.0.2"), addrs("10.0.0.3")}
	var mu sync.Mutex
	now := time.Now()
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Hour)
		return now
	}
	s := NewSet([]agent.NetRule{hostRule("api", 443, "10.0.0.1")}, nil, Options{Lookup: lk, Now: clock})
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				s.Match(netip.MustParseAddrPort("10.0.0.2:443"), "tcp")
			}
		}()
	}
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := s.Refresh(context.Background()); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}

// TestRunRefreshesUntilCancelled drives the background loop in a synctest bubble, where the ticker runs
// on the bubble's clock: one interval is exactly one refresh however loaded the machine is, the address is
// checked absent while the refresher is provably idle before its first tick (Run refreshes on every tick,
// not at start), and the bubble itself fails the test if Run leaves a goroutine behind, which its doc
// comment says it never does. Polling a real clock for up to three seconds proved none of the three.
func TestRunRefreshesUntilCancelled(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lk := newLookup()
		lk.answers["api"] = [][]netip.Addr{addrs("10.0.0.2")}
		now := time.Now()
		s := NewSet([]agent.NetRule{hostRule("api", 443, "10.0.0.1")}, nil, Options{
			Lookup: lk,
			Now:    func() time.Time { return now.Add(time.Hour) },
		})
		fresh := netip.MustParseAddrPort("10.0.0.2:443")
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		const every = time.Minute
		done := make(chan error, 1)
		go func() { done <- s.Run(ctx, every) }()
		synctest.Wait()
		if s.Match(fresh, "tcp") != nil {
			t.Fatal("the set admitted the new address before the refresher's first tick")
		}
		time.Sleep(every)
		synctest.Wait()
		if s.Match(fresh, "tcp") == nil {
			t.Fatal("a tick passed and the background refresher did not pick the new address up")
		}
		cancel()
		synctest.Wait()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Run = %v, want nil on cancellation", err)
			}
		default:
			t.Fatal("Run did not return after cancellation")
		}
	})
}

// TestRefreshHonoursContext: a cancelled context stops a refresh instead of hanging on DNS. In a synctest
// bubble the cancel lands exactly when every lookup is blocked on the resolver, which is the case the
// test is about; a 10 ms sleep on the real clock could fire before Refresh had started a lookup at all.
func TestRefreshHonoursContext(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		lk := newLookup()
		lk.block = make(chan struct{})
		lk.answers["api"] = [][]netip.Addr{addrs("10.0.0.2")}
		now := time.Now()
		s := NewSet([]agent.NetRule{hostRule("api", 443, "10.0.0.1")}, nil, Options{
			Lookup: lk, Now: func() time.Time { return now.Add(time.Hour) },
		})
		ctx, cancel := context.WithCancel(t.Context())
		go func() {
			time.Sleep(10 * time.Millisecond)
			cancel()
		}()
		if err := s.Refresh(ctx); !errors.Is(err, context.Canceled) {
			t.Errorf("Refresh = %v, want context.Canceled", err)
		}
		close(lk.block)
	})
}

// TestResolverAddrsSnapshot keeps the caller from mutating the set's own slice.
func TestResolverAddrsSnapshot(t *testing.T) {
	in := []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}
	s := NewSet(nil, in, Options{Lookup: newLookup()})
	in[0] = netip.MustParseAddrPort("8.8.8.8:53")
	if got := s.ResolverAddrs(); len(got) != 1 || got[0] != netip.MustParseAddrPort("127.0.0.53:53") {
		t.Errorf("ResolverAddrs = %v, want the snapshot taken at construction", got)
	}
}

// TestRefreshedFollowsTheLiveSet: Refreshed hands a second enforcer of the same entries the addresses the set
// admits now. Tier 2's kernel rows decide every connect the supervisor relays, so rows left at the addresses of
// run start refused, with EPERM, each connect to an address a host rotated to while the supervisor and the
// ledger said allowed (enforce-cgroup-observe §6 E7). A literal address, a cidr and a unix entry are never
// re-resolved and come back as given; so does an entry that is not where NewSet found it; base is not touched.
func TestRefreshedFollowsTheLiveSet(t *testing.T) {
	lk := newLookup()
	lk.answers["api.example.com"] = [][]netip.Addr{addrs("203.0.113.5", "::ffff:203.0.113.6")}
	now := time.Now()
	cidr := netip.MustParsePrefix("10.0.0.0/8")
	base := []agent.NetRule{
		{Raw: "unix:/run/x.sock", Proto: agent.ProtoUnix, UnixPath: "/run/x.sock"},
		{Raw: "198.51.100.4:443", Host: "198.51.100.4", Port: 443, Proto: agent.ProtoInet, Static: true,
			IPs: addrs("::ffff:198.51.100.4"), Verdict: agent.VerdictAllow}, // as given: even its spelling
		{Raw: "10.0.0.0/8:8080", Port: 8080, Proto: agent.ProtoInet, CIDR: &cidr, Static: true,
			Verdict: agent.VerdictAllow},
		hostRule("api.example.com", 443, "93.184.216.34"),
	}
	base[3].ResolvedAt = now
	s := NewSet(base, nil, Options{Lookup: lk, Now: func() time.Time { return now }, MinTTL: time.Second})

	if got := s.Refreshed(base); !slices.Equal(got[3].IPs, base[3].IPs) {
		t.Fatalf("before any refresh: %v, want the compiled %v", got[3].IPs, base[3].IPs)
	}
	now = now.Add(2 * time.Minute)
	if err := s.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := s.Refreshed(base)
	if want := addrs("203.0.113.5", "203.0.113.6"); !slices.Equal(got[3].IPs, want) || !got[3].ResolvedAt.Equal(now) {
		t.Fatalf("host entry after a refresh: %v at %v, want %v at %v", got[3].IPs, got[3].ResolvedAt, want, now)
	}
	for i := range 3 {
		if !slices.Equal(got[i].IPs, base[i].IPs) || got[i].Raw != base[i].Raw {
			t.Errorf("entry %d (%s) changed: %+v", i, base[i].Raw, got[i])
		}
	}
	if !slices.Equal(base[3].IPs, addrs("93.184.216.34")) {
		t.Errorf("Refreshed modified base: %v", base[3].IPs)
	}
	// Another table that does not line up with the set gets nothing moved into it.
	other := []agent.NetRule{hostRule("other.example.com", 443, "192.0.2.1")}
	if got := s.Refreshed(other); !slices.Equal(got[0].IPs, other[0].IPs) {
		t.Errorf("an entry NewSet never saw was given %v", got[0].IPs)
	}
}

// TestChangedCountsOnlyNewAddresses: Changed is the counter a kernel copy of the set follows, so it moves only
// when a lookup brings a different address set, never for the same answer again or for a failed lookup (R8a).
func TestChangedCountsOnlyNewAddresses(t *testing.T) {
	lk := newLookup()
	lk.answers["api"] = [][]netip.Addr{addrs("93.184.216.34"), addrs("93.184.216.34"), addrs("203.0.113.5")}
	now := time.Now()
	s := NewSet([]agent.NetRule{hostRule("api", 443, "93.184.216.34")}, nil,
		Options{Lookup: lk, Now: func() time.Time { return now }, MinTTL: time.Second})
	step := func() Stats {
		t.Helper()
		now = now.Add(2 * time.Minute)
		if err := s.Refresh(context.Background()); err != nil {
			t.Fatal(err)
		}
		return s.Stats()
	}
	if st := step(); st.Replaced != 1 || st.Changed != 0 {
		t.Fatalf("the compiled address again: %+v, want one replacement and no change", st)
	}
	if st := step(); st.Changed != 0 {
		t.Fatalf("the same answer twice: %+v, want no change", st)
	}
	if st := step(); st.Changed != 1 {
		t.Fatalf("a rotated address: %+v, want one change", st)
	}
	lk.setErr("api", errors.New("SERVFAIL"))
	if st := step(); st.Changed != 1 || st.Failures != 1 {
		t.Fatalf("a failed lookup: %+v, want no further change", st)
	}
}

// TestMatchRefusesAnUnspecifiedDestination: a connect to 0.0.0.0 or :: reaches this host, not the address
// written, so an entry wide enough to hold them (::/0, 0.0.0.0/0) must not admit it as though it were that
// address.
func TestMatchRefusesAnUnspecifiedDestination(t *testing.T) {
	v6, v4 := netip.MustParsePrefix("::/0"), netip.MustParsePrefix("0.0.0.0/0")
	s := NewSet([]agent.NetRule{
		{Raw: "::/0:8443", Port: 8443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, CIDR: &v6, Static: true},
		{Raw: "0.0.0.0/0:8443", Port: 8443, Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, CIDR: &v4, Static: true},
	}, nil, Options{})
	for _, dst := range []string{"[::]:8443", "[::ffff:0.0.0.0]:8443", "0.0.0.0:8443"} {
		if m := s.Match(netip.MustParseAddrPort(dst), ProtoTCP); m != nil {
			t.Errorf("%s matched %s", dst, m.Raw)
		}
	}
	for _, dst := range []string{"[2001:db8::1]:8443", "192.0.2.1:8443"} {
		if s.Match(netip.MustParseAddrPort(dst), ProtoTCP) == nil {
			t.Errorf("%s did not match", dst)
		}
	}
}

// TestCompiledTTLExpiryIndependentOfRefreshFloor covers agent-contract.md E19
// and network-controls.md R5: lookup pacing never extends compiled authority.
func TestCompiledTTLExpiryIndependentOfRefreshFloor(t *testing.T) {
	for _, ttl := range []time.Duration{agent.MinDNSTTL, agent.DefaultDNSTTL} {
		t.Run(ttl.String(), func(t *testing.T) {
			dir := t.TempDir()
			start := time.Unix(1_700_000_000, 0)
			now := start
			lookup := newLookup()
			lookup.answers["api.example.test"] = [][]netip.Addr{addrs("93.184.216.34")}
			contract, diags, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"),
				[]byte("version: 0\nname: dns-ttl\ncommand: [/bin/true]\nnet:\n  allow: [api.example.test:443]\n  dns: {max_stale: 0s}\n"), nil)
			if err != nil {
				t.Fatalf("load: %v %v", err, diags)
			}
			machine := config.Builtin()
			machine.LedgerRoot.Value = filepath.Join(dir, "runs")
			table, diags, err := agent.Compile(contract, machine,
				agent.WithDNSTTL(ttl), agent.WithClock(func() time.Time { return now }),
				agent.WithResolver(lookup), agent.WithCwd(dir), agent.WithHome(dir), agent.WithMountInfo(""))
			if err != nil {
				t.Fatalf("compile supported TTL: %v %v", err, diags)
			}
			deadline := start.Add(ttl)
			if len(table.Net) != 1 || table.Net[0].TTL != ttl || !table.Net[0].ExpiresAt.Equal(deadline) {
				t.Fatalf("compiled TTL/deadline: %+v", table.Net)
			}
			zero := time.Duration(0)
			set := NewSet(table.Net, nil, Options{Lookup: lookup, Now: func() time.Time { return now }, MaxStale: &zero})
			dst := netip.MustParseAddrPort("93.184.216.34:443")
			if row := set.Refreshed(table.Net)[0]; !row.ExpiresAt.Equal(deadline) || set.Match(dst, ProtoTCP) == nil {
				t.Fatalf("initial compiled grant changed: %+v", row)
			}
			now = deadline
			if set.Match(dst, ProtoTCP) != nil || len(set.Refreshed(table.Net)[0].IPs) != 0 {
				t.Fatal("compiled grant remains usable at its expiry boundary")
			}
			if wantDue := ttl >= DefaultMinTTL; set.Due() != wantDue {
				t.Fatalf("refresh floor changed: due=%t want=%t", set.Due(), wantDue)
			}
			lookup.setErr("api.example.test", errors.New("owned resolver unavailable"))
			now = start.Add(max(ttl, DefaultMinTTL))
			if err := set.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			if set.Match(dst, ProtoTCP) != nil || len(set.Refreshed(table.Net)[0].IPs) != 0 || lookup.callCount("api.example.test") != 2 {
				t.Fatal("a failed refresh renewed expired authority or did not perform the due lookup")
			}
			lookup.setErr("api.example.test", nil)
			now = now.Add(time.Second)
			if err := set.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			renewed := now.Add(ttl)
			if row := set.Refreshed(table.Net)[0]; !row.ExpiresAt.Equal(renewed) || set.Match(dst, ProtoTCP) == nil {
				t.Fatalf("successful refresh changed grant duration: %+v", row)
			}
			if !table.Net[0].ExpiresAt.Equal(deadline) {
				t.Fatal("runtime mutated the original compiled table")
			}
			now = renewed
			if set.Match(dst, ProtoTCP) != nil {
				t.Fatal("renewed grant survives its compiled TTL")
			}
		})
	}
}
