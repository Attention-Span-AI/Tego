// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/dns"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// A successful lookup renews a bounded hostname grant even when its IP does not
// change. The backend must receive that deadline, rather than keep an expired
// kernel row while the supervisor continues to admit the same destination.
func TestDNSRefreshRenewsSameAddressKernelDeadline(t *testing.T) {
	for _, tc := range []struct {
		name  string
		stale time.Duration
		retry bool
	}{{"ttl", 0, false}, {"stale allowance", 20 * time.Second, false}, {"failed renewal retried", 0, true}} {
		t.Run(tc.name, func(t *testing.T) {
			stale := tc.stale
			dir := t.TempDir()
			start := time.Unix(1_700_000_000, 0)
			now := start
			addr := netip.MustParseAddr("93.184.216.34")
			lookup := &rotatingLookup{answers: [][]netip.Addr{{addr}}}
			contract, diags, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), []byte(
				"version: 0\nname: dns-renewal\ncommand: [/bin/true]\nnet:\n  allow: [api.example.test:443]\n  dns: {max_stale: "+stale.String()+"}\n"), nil)
			if err != nil {
				t.Fatalf("load: %v %v", err, diags)
			}
			machine := config.Builtin()
			machine.LedgerRoot.Value = filepath.Join(dir, "runs")
			rt, diags, err := agent.Compile(contract, machine,
				agent.WithClock(func() time.Time { return now }), agent.WithResolver(lookup),
				agent.WithCwd(dir), agent.WithHome(dir), agent.WithMountInfo(""))
			if err != nil {
				t.Fatalf("compile: %v %v", err, diags)
			}
			if len(rt.Net) != 1 || rt.Net[0].TTL != agent.DefaultDNSTTL {
				t.Fatalf("default compiled hostname: %+v", rt.Net)
			}
			original := rt.Net[0].ExpiresAt
			set := dns.NewSet(rt.Net, nil, dns.Options{
				Lookup: lookup, Now: func() time.Time { return now }, MaxStale: &stale,
			})
			now = start.Add(agent.DefaultDNSTTL)
			if err := set.Refresh(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := now.Add(agent.DefaultDNSTTL + stale)
			if snapshot := set.Refreshed(rt.Net); !snapshot[0].ExpiresAt.Equal(want) ||
				set.Match(netip.AddrPortFrom(addr, 443), dns.ProtoTCP) == nil {
				t.Fatalf("supervisor grant did not renew: %+v", snapshot)
			}
			h := &refreshingHandle{called: make(chan struct{}, 1)}
			interval := time.Hour
			if tc.retry {
				h.fail = errors.New("owned backend renewal failure")
				interval = time.Millisecond
			}
			r := dnsRunner(h)
			r.rt = rt
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			done := make(chan error, 1)
			go func() { done <- r.refreshDNS(ctx, set, interval) }()
			select {
			case <-h.called:
			case <-ctx.Done():
			}
			if tc.retry {
				h.mu.Lock()
				h.fail = nil
				h.mu.Unlock()
				// Wait for a call answered after fail was cleared: the signal already buffered can be a failed try's.
				for ctx.Err() == nil {
					if a := h.answers(); len(a) > 0 && !a[len(a)-1] {
						break
					}
					select {
					case <-h.called:
					case <-ctx.Done():
					}
				}
			}
			cancel()
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			// One renewal, handed once; a failed one is retried each interval until one is taken, and none is handed
			// after that. How many failed tries come first is the scheduler's: at a 1 ms interval the refresher can try
			// again before this goroutine clears h.fail (3 tables, 30 of 1000 runs at -cpu 1,2, under load).
			tables, failed := h.got(), h.answers()
			wantFailed := []bool{false}
			if tc.retry {
				wantFailed = append(slices.Repeat([]bool{true}, max(len(failed)-1, 1)), false)
			}
			if !slices.Equal(failed, wantFailed) {
				t.Fatalf("same-address renewal handed backend %d tables answered fail %v, want %v; original kernel deadline %s, renewed supervisor deadline %s", len(tables), failed, wantFailed, original, want)
			}
			got := tables[len(tables)-1].Net[0]
			if !got.ExpiresAt.Equal(want) || !slices.Equal(got.IPs, rt.Net[0].IPs) || !got.ExpiresAt.After(original) {
				t.Fatalf("backend renewal changed addresses or kept the old deadline: %+v", got)
			}
			if !rt.Net[0].ExpiresAt.Equal(original) {
				t.Fatal("refresh mutated the compiled table")
			}
		})
	}
}
