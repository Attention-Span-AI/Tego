// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A source can copy a stamp, then lose the CPU while the agent keeps advancing it.
// C73: that local copy must not be aged against a clock read after the pause.
func TestTickPauseDoesNotAgeActivitySnapshot(t *testing.T) {
	const s = uint64(time.Second)
	for _, firstTick := range []bool{true, false} {
		name := "later tick"
		if firstTick {
			name = "first tick after start"
		}
		t.Run(name, func(t *testing.T) {
			w, sink, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 3 * time.Second}, nil)
			w.Observe(runStart(s))
			if !firstTick {
				clk.set(2 * s)
				if b, err := w.Tick(t.Context()); b != nil || err != nil {
					t.Fatalf("initial Tick = %v, %v", b, err)
				}
			}
			clk.set(10 * s)
			stamp := 10*s - uint64(400*time.Millisecond)
			paused := false
			w.AddActivity(func() uint64 {
				sampled := stamp
				if !paused {
					paused = true
					// No sleep: model four seconds off CPU after copying the stamp.
					clk.add(4 * time.Second)
					stamp += 4 * s
				}
				return sampled
			})
			for range 2 {
				if b, err := w.Tick(t.Context()); b != nil || err != nil {
					t.Fatalf("Tick with fresh activity = %v, %v; latest data is only 0.4s old", b, err)
				}
			}
			if got := w.Snapshot().LastEventMonoNS; got != stamp {
				t.Fatalf("last activity = %d, want fresh stamp %d", got, stamp)
			}
			if killer.kills.Load() != 0 || len(sink.kinds(record.KindLimit)) != 0 {
				t.Fatal("a progressing run was stopped")
			}

			// Once progress stops, the first tick beyond the limit must trip.
			clk.set(stamp + 3*s + 1)
			b, err := w.Tick(t.Context())
			want := Breach{Which: record.LimitStallAfter, Value: seconds(3*s + 1), Ceiling: 3}
			if err != nil || b == nil || *b != want {
				t.Fatalf("first Tick past a real stall = %v, %v; want %+v", b, err, want)
			}
			if killer.kills.Load() != 1 || len(sink.kinds(record.KindLimit)) != 1 {
				t.Fatal("a real stall must emit one limit and kill once")
			}
			assertLimitEvent(t, sink.kinds(record.KindLimit)[0], want)
		})
	}
}

// A scheduling pause must not grant a silent run a fresh activity stamp. If the
// pause follows this tick's clock sample, the next tick detects the full idle.
func TestTickPauseWithoutActivityStillStalls(t *testing.T) {
	const s = uint64(time.Second)
	for _, duringPull := range []bool{false, true} {
		name := "pause before tick"
		if duringPull {
			name = "pause during activity pull"
		}
		t.Run(name, func(t *testing.T) {
			w, sink, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 3 * time.Second}, nil)
			w.Observe(runStart(s))
			clk.set(2 * s)
			paused := false
			w.AddActivity(func() uint64 {
				if duringPull && !paused {
					paused = true
					clk.add(4 * time.Second)
				}
				return 0 // No activity at all since run_start.
			})
			if !duringPull {
				clk.add(4 * time.Second)
			}
			b, err := w.Tick(t.Context())
			if err != nil {
				t.Fatal(err)
			}
			if duringPull && b == nil {
				b, err = w.Tick(t.Context())
			}
			want := Breach{Which: record.LimitStallAfter, Value: 5, Ceiling: 3}
			if err != nil || b == nil || *b != want {
				t.Fatalf("Tick after a silent pause = %v, %v; want %+v", b, err, want)
			}
			if got := w.Snapshot().LastEventMonoNS; got != s {
				t.Fatalf("pause fabricated activity at %d, want run_start %d", got, s)
			}
			if killer.kills.Load() != 1 || len(sink.kinds(record.KindLimit)) != 1 {
				t.Fatal("a silent run must emit one limit and kill once")
			}
			assertLimitEvent(t, sink.kinds(record.KindLimit)[0], want)
		})
	}
}

// The held-state reading must use the same ordering: a false sample can become
// stale while a newly published ask holds the agent during a scheduling pause.
func TestTickPauseDoesNotAgeHeldSnapshot(t *testing.T) {
	const s = uint64(time.Second)
	w, sink, killer, clk, _ := newTestWatcher(t, agent.ResolvedLimits{StallAfter: 3 * time.Second}, nil)
	w.Observe(runStart(s))
	w.Touch(10*s - uint64(400*time.Millisecond))
	clk.set(10 * s)
	held := false
	WithHeld(func() bool {
		sampled := held
		if !held {
			held = true
			clk.add(4 * time.Second)
		}
		return sampled
	})(w)
	for range 2 {
		if b, err := w.Tick(t.Context()); b != nil || err != nil {
			t.Fatalf("Tick with a newly held ask = %v, %v", b, err)
		}
	}
	if got := w.Snapshot().LastEventMonoNS; got != 14*s {
		t.Fatalf("last activity = %d, want the held tick's %d", got, 14*s)
	}
	if killer.kills.Load() != 0 || len(sink.kinds(record.KindLimit)) != 0 {
		t.Fatal("a held run was stopped")
	}
}
