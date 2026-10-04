// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestStaleDeadlineAppliesWithoutRefreshAndRecoveryRestoresGrant(t *testing.T) {
	now := time.Now()
	start := now
	lookup := newLookup()
	lookup.setErr("api.example.com", errors.New("resolver unavailable"))
	host := hostRule("api.example.com", 443, "203.0.113.4")
	host.ResolvedAt, host.TTL = now, time.Second
	static := agent.NetRule{Raw: "tcp://192.0.2.7:443", Proto: agent.ProtoTCP, Port: 443, IPs: addrs("192.0.2.7"), Static: true, Verdict: agent.VerdictAllow}
	base := []agent.NetRule{host, static}
	stale := 2 * time.Second
	set := NewSet(base, nil, Options{Lookup: lookup, Now: func() time.Time { return now }, MinTTL: time.Second, MaxStale: &stale})
	old := netip.MustParseAddrPort("203.0.113.4:443")
	now = start.Add(2 * time.Second)
	if err := set.Refresh(context.Background()); err != nil || set.Match(old, ProtoTCP) == nil {
		t.Fatalf("transient failure within stale allowance: %v", err)
	}
	now = start.Add(3 * time.Second)
	if set.Match(old, ProtoTCP) != nil {
		t.Fatal("expired grant stayed active until the next refresh")
	}
	rows := set.Refreshed(base)
	if len(rows[0].IPs) != 0 || !rows[0].ExpiresAt.Equal(now) || !rows[1].ExpiresAt.IsZero() || len(rows[1].IPs) != 1 {
		t.Fatalf("kernel snapshot expiry/static preservation: %+v", rows)
	}
	if len(base[0].IPs) != 1 || !base[0].ExpiresAt.IsZero() {
		t.Fatal("snapshot altered immutable base")
	}
	lookup.setErr("api.example.com", nil)
	lookup.answers["api.example.com"] = [][]netip.Addr{addrs("203.0.113.5")}
	now = start.Add(4 * time.Second)
	if err := set.Refresh(context.Background()); err != nil {
		t.Fatal(err)
	}
	if set.Match(old, ProtoTCP) != nil || set.Match(netip.MustParseAddrPort("203.0.113.5:443"), ProtoTCP) == nil {
		t.Fatal("successful recovery did not replace expired addresses")
	}
	if deadline := set.Refreshed(base)[0].ExpiresAt; !deadline.Equal(start.Add(7 * time.Second)) {
		t.Fatalf("new successful-answer deadline: %v", deadline)
	}
}

func TestStaleExpiryKeepsIndependentGrantAndCompatibilityDefault(t *testing.T) {
	now := time.Now()
	host := hostRule("api.example.com", 443, "203.0.113.4")
	host.ResolvedAt, host.TTL = now, time.Second
	static := agent.NetRule{Raw: "tcp://203.0.113.4:443", Proto: agent.ProtoTCP, Port: 443, IPs: addrs("203.0.113.4"), Static: true, Verdict: agent.VerdictAllow}
	stale := time.Second
	rules := []agent.NetRule{host, static}
	expiring := NewSet(rules, nil, Options{Now: func() time.Time { return now }, MinTTL: time.Second, MaxStale: &stale})
	compat := NewSet(rules[:1], nil, Options{Now: func() time.Time { return now }, MinTTL: time.Second})
	now = now.Add(24 * time.Hour)
	dst := netip.MustParseAddrPort("203.0.113.4:443")
	if got := expiring.Match(dst, ProtoTCP); got == nil || got.Rule != static.RuleName() {
		t.Fatalf("expired hostname shadowed independent literal grant: %+v", got)
	}
	if compat.Match(dst, ProtoTCP) == nil || !compat.Refreshed(rules[:1])[0].ExpiresAt.IsZero() {
		t.Fatal("absent max-stale changed compatibility behavior")
	}
}

// pacedLookup answers every lookup with the same address after latency on the test's virtual clock, sampling
// the grant while the lookup is in flight: the old snapshot is the one in force until Refresh returns.
type pacedLookup struct {
	addr    netip.Addr
	latency time.Duration
	during  func(time.Duration) // advances the clock by the latency, sampling as it goes; nil while compiling
	calls   int
}

func (p *pacedLookup) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	p.calls++
	if p.during != nil {
		p.during(p.latency)
	}
	return []netip.Addr{p.addr}, nil
}

// A bounded hostname grant whose address never changes is renewed before it lapses, at production's TTL,
// refresh floor and lookup timeout, with the poller's tick out of phase with the grant and a slow resolver:
// renewal starts early enough that a tick's wait and a lookup's latency both fit before the deadline. Due and
// deadline used to coincide at max_stale 0s, so every renewal left the destination refused until the next
// tick's lookup had finished.
func TestBoundedGrantRenewedBeforeItLapses(t *testing.T) {
	for _, tc := range []struct {
		name  string
		tick  time.Duration
		every time.Duration // Options.RefreshEvery
	}{{"runtime tick", 5 * time.Second, 5 * time.Second}, {"default interval", 5 * time.Second, 0}, {"Run default", DefaultInterval, 0}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			start := time.Unix(1_700_000_000, 0)
			now := start
			addr := netip.MustParseAddr("93.184.216.34")
			lookup := &pacedLookup{addr: addr, latency: agent.DefaultDNSTimeout - 100*time.Millisecond}
			contract, diags, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"),
				[]byte("version: 0\nname: dns-renew\ncommand: [/bin/true]\nnet:\n  allow: [api.example.test:443]\n  dns: {max_stale: 0s}\n"), nil)
			if err != nil {
				t.Fatalf("load: %v %v", err, diags)
			}
			machine := config.Builtin()
			machine.LedgerRoot.Value = filepath.Join(dir, "runs")
			table, diags, err := agent.Compile(contract, machine, agent.WithClock(func() time.Time { return now }),
				agent.WithResolver(lookup), agent.WithCwd(dir), agent.WithHome(dir), agent.WithMountInfo(""))
			if err != nil || len(table.Net) != 1 || table.Net[0].TTL != agent.DefaultDNSTTL {
				t.Fatalf("compile: %v %v %+v", err, diags, table)
			}
			zero := time.Duration(0)
			set := NewSet(table.Net, nil, Options{
				Lookup: lookup, Now: func() time.Time { return now }, MaxStale: &zero, RefreshEvery: tc.every,
			})
			dst := netip.AddrPortFrom(addr, 443)
			const step = 100 * time.Millisecond
			var refused []time.Duration
			sample := func() {
				if set.Match(dst, ProtoTCP) == nil || len(set.Refreshed(table.Net)[0].IPs) == 0 {
					refused = append(refused, now.Sub(start))
				}
			}
			lookup.during = func(d time.Duration) {
				for end := now.Add(d); now.Before(end); now = now.Add(step) {
					sample()
				}
			}
			const span = 10 * time.Minute
			next := start.Add(700 * time.Millisecond) // the poller starts after the compile, out of phase
			for now.Before(start.Add(span)) {
				if !now.Before(next) {
					next = next.Add(tc.tick)
					if err := set.Refresh(context.Background()); err != nil {
						t.Fatal(err)
					}
				}
				sample()
				now = now.Add(step)
			}
			if len(refused) > 0 {
				t.Fatalf("unchanged hostname refused at %d of %d samples, first at %s, last at %s",
					len(refused), int(span/step), refused[0], refused[len(refused)-1])
			}
			if floor := int(span/DefaultMinTTL) + 1; lookup.calls-1 > floor {
				t.Fatalf("%d renewal lookups in %s exceed the refresh floor's %d", lookup.calls-1, span, floor)
			}
		})
	}
}
