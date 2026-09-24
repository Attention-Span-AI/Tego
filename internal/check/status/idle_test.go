// SPDX-License-Identifier: Apache-2.0

package status

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// zeroMonoClock stamps events with an unknown monotonic reading, E20's case.
type zeroMonoClock struct{ t time.Time }

func (c zeroMonoClock) Now() time.Time { return c.t }
func (zeroMonoClock) Mono() uint64     { return 0 }

// writeWithClock builds a one-event live run stamped by the given clock and leaves the lock held.
func writeWithClock(t *testing.T, c ledger.Clock) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "r-00000000-000000000000a-aaaaaa")
	w, err := ledger.Open(dir, record.RunRef{ID: filepath.Base(dir), Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}), ledger.WithClock(c))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	runStart("")(w)
	t.Cleanup(func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) })
	return dir
}

func deriveMono(t *testing.T, dir string, now time.Time, stall time.Duration, mono uint64) *Snapshot {
	t.Helper()
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer func() { _ = r.Close() }()
	s, err := Derive(r, true, now, stall, WithMonoNow(func() uint64 { return mono }))
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	return s
}

// TestIdleIgnoresAWallClockStep is the reason R4 measures the stall monotonically. An NTP correction or a
// laptop resuming from suspend moves the wall clock by hours while the agent is working normally; reading
// the stall off that clock would report a healthy run as stalled and, worse, disagree with the limits
// watcher, which measures the same stall on MonoNS and is what actually kills a run.
// (limits-check-doctor-cli.md E7: a clock step mid-run.)
func TestIdleIgnoresAWallClockStep(t *testing.T) {
	dir := writeWithClock(t, fixedClock{base})
	eventMono := uint64(base.UnixNano())

	// One monotonic second has passed. The wall clock says two hours, and the ceiling is one.
	s := deriveMono(t, dir, base.Add(2*time.Hour), time.Hour, eventMono+uint64(time.Second))
	if s.IdleClock != ClockMonotonic {
		t.Fatalf("idle read from the %s clock, want %s", s.IdleClock, ClockMonotonic)
	}
	if s.Idle != time.Second {
		t.Errorf("idle %s, want 1s: the wall step is not elapsed time", s.Idle)
	}
	if s.St != Running {
		t.Errorf("state %q, want %q: a wall-clock step is not a stall", s.St, Running)
	}
}

// TestIdleStallsOnRealElapsedTime is the other half: when the monotonic clock really has advanced past the
// ceiling, the run is stalled.
// (limits-check-doctor-cli.md E27: stall counts the monotonic clock.)
func TestIdleStallsOnRealElapsedTime(t *testing.T) {
	dir := writeWithClock(t, fixedClock{base})
	s := deriveMono(t, dir, base, time.Hour, uint64(base.UnixNano())+uint64(90*time.Minute))
	if s.IdleClock != ClockMonotonic || s.Idle != 90*time.Minute {
		t.Fatalf("idle %s from the %s clock, want 1h30m monotonic", s.Idle, s.IdleClock)
	}
	if s.St != Stalled {
		t.Errorf("state %q, want %q", s.St, Stalled)
	}
}

// TestIdleFallsBackWhenReadingsAreNotComparable covers a ledger written on another boot or another host: its
// MonoNS cannot be subtracted from this host's, so idle is reported on the wall clock and says so.
func TestIdleFallsBackWhenReadingsAreNotComparable(t *testing.T) {
	dir := writeWithClock(t, fixedClock{base})
	s := deriveMono(t, dir, base.Add(30*time.Minute), time.Hour, 1) // nowMono far below the event's
	if s.IdleClock != ClockWall {
		t.Fatalf("idle read from the %s clock, want %s", s.IdleClock, ClockWall)
	}
	if s.Idle != 30*time.Minute {
		t.Errorf("idle %s, want 30m from the wall clock", s.Idle)
	}
}

// TestIdleFallsBackWhenMonoIsUnknown is E20: a producer that could not read CLOCK_MONOTONIC stamps 0.
func TestIdleFallsBackWhenMonoIsUnknown(t *testing.T) {
	dir := writeWithClock(t, zeroMonoClock{base})
	s := deriveMono(t, dir, base.Add(10*time.Minute), time.Hour, uint64(time.Hour))
	if s.IdleClock != ClockWall || s.Idle != 10*time.Minute {
		t.Errorf("idle %s from the %s clock, want 10m wall", s.Idle, s.IdleClock)
	}
}

// TestIdleIsNeverNegative covers the wall clock stepping backward behind the last event. A negative idle
// would compare below every ceiling and hide a stall that is real.
func TestIdleIsNeverNegative(t *testing.T) {
	dir := writeWithClock(t, zeroMonoClock{base})
	s := deriveMono(t, dir, base.Add(-time.Hour), time.Hour, 0)
	if s.Idle < 0 {
		t.Errorf("idle %s is negative", s.Idle)
	}
	if s.St != Running {
		t.Errorf("state %q, want %q", s.St, Running)
	}
}
