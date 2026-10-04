// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type cancelResolver struct {
	cancel context.CancelFunc
	calls  atomic.Int32
	active atomic.Int32
}

func (r *cancelResolver) LookupNetIP(ctx context.Context, _, _ string) ([]netip.Addr, error) {
	r.calls.Add(1)
	r.active.Add(1)
	defer r.active.Add(-1)
	r.cancel()
	<-ctx.Done()
	return nil, ctx.Err()
}

// TestCompileCancellationStopsDNS: R29's first signal cancels lookups already running and the bounded
// queue, even with Offline; cancellation must not become a warning followed by a usable table.
func TestCompileCancellationStopsDNS(t *testing.T) {
	for _, offline := range []bool{false, true} {
		t.Run(fmt.Sprint(offline), func(t *testing.T) {
			f := newFixture(t)
			var hosts strings.Builder
			for i := range 32 {
				fmt.Fprintf(&hosts, "    - example-%d.test:443\n", i)
			}
			c := f.load("version: 0\nname: cancelled\ncommand: [static-tool]\nnet:\n  allow:\n" + hosts.String())
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			r := &cancelResolver{cancel: cancel}
			opts := []CompileOption{WithContext(ctx), WithResolver(r)}
			if offline {
				opts = append(opts, Offline())
			}
			start := time.Now()
			rt, ds, err := Compile(c, f.machine, f.opts(opts...)...)
			if rt != nil || !errors.Is(err, context.Canceled) {
				t.Fatalf("table=%v err=%v, want no table and context.Canceled", rt, err)
			}
			if elapsed := time.Since(start); elapsed >= DefaultDNSTimeout {
				t.Errorf("cancelled compile took %s (the per-host timeout is %s)", elapsed, DefaultDNSTimeout)
			}
			if r.calls.Load() >= 32 || r.active.Load() != 0 {
				t.Errorf("lookups: started=%d active=%d; queued work must stop and all started work finish", r.calls.Load(), r.active.Load())
			}
			for _, d := range ds {
				if d.Code == CodeHostUnresolvable {
					t.Errorf("cancellation reported as a bad hostname: %v", d)
				}
			}
		})
	}
}
