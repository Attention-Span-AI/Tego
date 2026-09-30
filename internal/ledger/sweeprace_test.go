// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestConcurrentSweepsKillAndEndALostRunOnce is runtime-launch.md §6 case 10 at the ledger: of N passes racing
// for one lost run, exactly one wins its lock, kills its tree (the sweep hook) and appends run_end; the others
// neither kill nor end it, and none of them reports it swept. Before the lock came ahead of the hook, every
// racer ran the hook, and every racer that then lost the lock still counted the run as swept. Both passes are
// raced: GC, which `gc` makes, and SweepLive, which `run` and `stop` make.
func TestConcurrentSweepsKillAndEndALostRunOnce(t *testing.T) {
	const racers = 16
	for _, pass := range []struct {
		name string
		run  func(root string, opts ...GCOption) (Report, error)
	}{
		{"GC", func(root string, opts ...GCOption) (Report, error) {
			return GC(context.Background(), root, keepAll, false, opts...)
		}},
		{"SweepLive", func(root string, opts ...GCOption) (Report, error) {
			return SweepLive(context.Background(), root, opts...)
		}},
	} {
		t.Run(pass.name, func(t *testing.T) {
			root := t.TempDir()
			w, ref := openLive(t, root, fixedStart, "race01")
			if err := MarkLive(root, ref.ID); err != nil {
				t.Fatal(err)
			}
			startRun(t, w, 3)
			die(w)

			var hooks atomic.Int64
			hook := func(_ context.Context, _ sys.Lender, r record.RunRef) error {
				if r.ID == ref.ID {
					hooks.Add(1)
					time.Sleep(20 * time.Millisecond) // a kill that waits for the tree to empty
				}
				return nil
			}
			start := make(chan struct{})
			reps := make([]Report, racers)
			errs := make([]error, racers)
			var wg sync.WaitGroup
			for i := range racers {
				wg.Add(1)
				go func() {
					defer wg.Done()
					<-start
					reps[i], errs[i] = pass.run(root, WithSweepHook(hook), WithWriterOptions(WithAnchor(&memAnchor{})))
				}()
			}
			close(start)
			wg.Wait()

			swept := 0
			for i := range racers {
				if errs[i] != nil {
					t.Errorf("racer %d: %v", i, errs[i])
				}
				for _, id := range reps[i].Swept {
					if id == ref.ID {
						swept++
					}
				}
			}
			if swept != 1 {
				t.Errorf("%d racers reported the run swept, want one", swept)
			}
			if n := hooks.Load(); n != 1 {
				t.Errorf("the sweep hook killed the run's tree %d times, want once", n)
			}
			if st := stateOf(t, w.Dir()); st != StateEnded {
				t.Fatalf("the run is %v after the race, want ended", st)
			}
		})
	}
}
