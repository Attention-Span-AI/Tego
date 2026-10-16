// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTickReadsActivityBeforeTheStallCheck is limits-check-doctor-cli.md R4's pulled half: a source added with
// AddActivity is read on every Tick before the stall comparison, so activity no event and no Touch announced
// (a kernel stamp the recorder keeps no line for) holds the stall window open, and the window closes once the
// source stops advancing.
func TestTickReadsActivityBeforeTheStallCheck(t *testing.T) {
	const s = uint64(time.Second)
	w, _, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
	var stamp atomic.Uint64
	w.AddActivity(stamp.Load)
	w.Observe(runStart(1 * s))
	for at := 2 * s; at <= 30*s; at += 4 * s {
		stamp.Store(at)
		clk.set(at + 4*s)
		if b, _ := w.Tick(t.Context()); b != nil {
			t.Fatalf("stalled at %ds with the source advancing every 4s under a 5s stall_after: %+v", (at+4*s)/s, *b)
		}
	}
	if got := w.Snapshot().LastEventMonoNS; got != 30*s {
		t.Fatalf("LastEventMonoNS = %d, want the last pulled stamp %d", got, 30*s)
	}
	if killer.kills.Load() != 0 {
		t.Fatal("a run whose activity source advanced was killed")
	}
	clk.set(30*s + 6*s)
	if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitStallAfter {
		t.Fatalf("6s after the source last advanced, Tick = %v, want a stall", b)
	}
}

// TestActivityBelowStartIsIgnored is R4's guard on a pulled stamp: a value below the run's monotonic origin is
// another run's (a slot's previous holder) and counts for nothing, a value before there is an origin gives none,
// and a value past the clock's own reading is clamped to it, so a bogus stamp can never hold the window open
// for good.
func TestActivityBelowStartIsIgnored(t *testing.T) {
	const s = uint64(time.Second)
	t.Run("below the origin", func(t *testing.T) {
		w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
		w.AddActivity(func() uint64 { return 5 * s })
		w.Observe(runStart(10 * s))
		clk.set(16 * s)
		if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitStallAfter {
			t.Fatalf("Tick = %v, want a stall: the stale 5s stamp predates the run's 10s origin", b)
		}
	})
	t.Run("no origin yet", func(t *testing.T) {
		w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{Wall: 5 * time.Second}, nil)
		w.AddActivity(func() uint64 { return 3 * s })
		clk.set(4 * s)
		if b, _ := w.Tick(t.Context()); b != nil {
			t.Fatalf("Tick before run_start = %+v, want nothing", *b)
		}
		if got := w.Snapshot(); got.StartMonoNS != 0 || got.LastEventMonoNS != 0 {
			t.Fatalf("a pulled stamp before run_start set start %d, last %d; want neither", got.StartMonoNS, got.LastEventMonoNS)
		}
	})
	t.Run("past the clock", func(t *testing.T) {
		w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
		var stamp atomic.Uint64
		w.AddActivity(stamp.Load)
		w.Observe(runStart(1 * s))
		stamp.Store(1000 * s)
		clk.set(2 * s)
		if b, _ := w.Tick(t.Context()); b != nil {
			t.Fatalf("Tick = %+v, want nothing", *b)
		}
		if got := w.Snapshot().LastEventMonoNS; got != 2*s {
			t.Fatalf("LastEventMonoNS = %d, want the stamp clamped to the clock's %d", got, 2*s)
		}
		stamp.Store(0)
		clk.set(8 * s)
		if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitStallAfter {
			t.Fatalf("Tick = %v, want a stall 6s after the clamped reading", b)
		}
	})
}

// TestActivityNeverLowersLastEvent is R4's raise-only rule for a pulled stamp, as Touch's: a stamp older than
// the newest line or touch moves nothing, and a source that answers 0 is "nothing".
func TestActivityNeverLowersLastEvent(t *testing.T) {
	const s = uint64(time.Second)
	w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 50 * time.Second}, nil)
	w.AddActivity(func() uint64 { return 15 * s })
	w.AddActivity(func() uint64 { return 0 })
	w.Observe(runStart(1 * s))
	w.Observe(decision(20*s, 1, "", ""))
	clk.set(25 * s)
	if _, err := w.Tick(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := w.Snapshot().LastEventMonoNS; got != 20*s {
		t.Fatalf("LastEventMonoNS = %d, want the decision's %d (a 15s stamp and a 0 move nothing)", got, 20*s)
	}
}

// TestGapStillDoesNotCountAsActivity is R4's gap rule beside a pulled source: a gap after the last stamp does not
// reset the window, and the run stalls on the stamp's reading.
func TestGapStillDoesNotCountAsActivity(t *testing.T) {
	const s = uint64(time.Second)
	w, _, _, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 5 * time.Second}, nil)
	w.AddActivity(func() uint64 { return 3 * s })
	w.Observe(runStart(1 * s))
	clk.set(4 * s)
	if b, _ := w.Tick(t.Context()); b != nil {
		t.Fatalf("Tick = %+v, want nothing", *b)
	}
	w.Observe(gapEvent(7 * s))
	clk.set(9 * s)
	if b, _ := w.Tick(t.Context()); b == nil || b.Which != record.LimitStallAfter {
		t.Fatalf("Tick = %v, want a stall measured from the 3s stamp, not the 7s gap", b)
	}
}

// TestActivityRace runs Observe, Touch and Tick with an AddActivity source together under the race detector:
// the source is called outside the watcher's lock (it may call back into the watcher), and the stall window only
// ever moves forward.
func TestActivityRace(t *testing.T) {
	clk := &fakeClock{}
	w := NewWatcher(agent.ResolvedLimits{StallAfter: time.Hour}, nil, &fakeKiller{},
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, &fakeSink{})
	var stamp atomic.Uint64
	w.AddActivity(func() uint64 {
		_ = w.Snapshot() // takes w.mu: a source called under it would deadlock here
		return stamp.Load()
	})
	w.Observe(runStart(1))
	var (
		wg    sync.WaitGroup
		start = make(chan struct{})
		seen  atomic.Uint64
	)
	for g := range 6 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := range 300 {
				at := uint64(g*1000 + i + 2)
				switch g % 3 {
				case 0:
					w.Observe(decision(at, 1, "", ""))
				case 1:
					w.Touch(at)
				default:
					stamp.Store(at)
					clk.set(at)
					if _, err := w.Tick(t.Context()); err != nil {
						t.Errorf("Tick: %v", err)
					}
				}
				got := w.Snapshot().LastEventMonoNS
				for prev := seen.Load(); got > prev && !seen.CompareAndSwap(prev, got); prev = seen.Load() {
				}
			}
		}()
	}
	close(start)
	wg.Wait()
	if got, max := w.Snapshot().LastEventMonoNS, seen.Load(); got < max {
		t.Fatalf("LastEventMonoNS = %d went below a reading already seen, %d", got, max)
	}
}

// TestRunPublishesActivityWithoutALine is R9's watcher half: what the stall check counted without a ledger line
// (a Touch, a pulled reading) is handed to WithActivityPublisher from Run's loop, at most once per tick and only
// when it moved, so status can measure the idle the watcher measures. A line is not published (status reads the
// ledger itself), nor is a held tick (status ranks a pending approval on its own).
func TestRunPublishesActivityWithoutALine(t *testing.T) {
	const s = uint64(time.Second)
	var (
		mu  sync.Mutex
		got []uint64
	)
	published := func() []uint64 {
		mu.Lock()
		defer mu.Unlock()
		return append([]uint64(nil), got...)
	}
	waitFor := func(n int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for len(published()) < n && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if p := published(); len(p) < n {
			t.Fatalf("published %v, want %d readings", p, n)
		}
	}
	var held atomic.Bool
	clk := &fakeClock{}
	w := NewWatcher(agent.ResolvedLimits{StallAfter: time.Hour}, nil, &fakeKiller{},
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, &fakeSink{},
		WithTickInterval(2*time.Millisecond), WithHeld(held.Load),
		WithActivityPublisher(func(v uint64) {
			mu.Lock()
			got = append(got, v)
			mu.Unlock()
		}))
	var stamp atomic.Uint64
	w.AddActivity(stamp.Load)
	clk.set(100 * s)
	w.Observe(runStart(1 * s))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run: %v", err)
		}
	}()

	time.Sleep(20 * time.Millisecond)
	if p := published(); len(p) != 0 {
		t.Fatalf("published %v before any activity without a line", p)
	}
	w.Touch(2 * s)
	waitFor(1)
	w.Observe(decision(3*s, 1, "", ""))
	held.Store(true)
	time.Sleep(20 * time.Millisecond)
	held.Store(false)
	if p := published(); len(p) != 1 || p[0] != 2*s {
		t.Fatalf("published %v, want only the touch's %d: a line, a held tick and an unchanged reading are not published", p, 2*s)
	}
	stamp.Store(4 * s)
	waitFor(2)
	time.Sleep(20 * time.Millisecond)
	if p := published(); len(p) != 2 || p[1] != 4*s {
		t.Fatalf("published %v, want the touch's then the pulled reading's, once each", p)
	}
}
