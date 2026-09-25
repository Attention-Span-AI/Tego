// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// TestRecorderReadingIsWhetherItRecordsTheRun: the supervisor leaves a continued IP connect to this recorder
// only while Reading holds (supervisor.md R7), so it must hold exactly while connects reach the run's record:
// not before Start, not for a recorder that found no row of its run, and not once the drain has failed.
func TestRecorderReadingIsWhetherItRecordsTheRun(t *testing.T) {
	start := func(t *testing.T, ring *fakeRing, rs RunSet, cg uint64) *Recorder {
		t.Helper()
		f := newFixture(t)
		r, err := New(Options{Rules: f.rules, Reader: ring, Proc: f.procFS, FlushInterval: time.Hour, RunSet: rs})
		if err != nil {
			t.Fatal(err)
		}
		if r.Reading() {
			t.Error("Reading before Start")
		}
		if err := r.Start(context.Background(), source.RunRef{ID: "r-A", Agent: "a", CgroupID: cg}, &fakeSink{}); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = r.Stop() })
		return r
	}
	t.Run("scoped to its run", func(t *testing.T) {
		if r := start(t, newFakeRing(), &fakeRunSet{rows: map[uint64]uint32{41: 3}}, 41); !r.Reading() {
			t.Error("Reading = false for a recorder that reads its run's ring")
		}
	})
	t.Run("no row of its run", func(t *testing.T) {
		if r := start(t, newFakeRing(), &fakeRunSet{rows: map[uint64]uint32{999: 9}}, 41); r.Reading() {
			t.Error("Reading = true for a recorder that reads nothing")
		}
	})
	t.Run("drain failed", func(t *testing.T) {
		ring := newFakeRing()
		ring.readErr = errors.New("ring buffer went away")
		r := start(t, ring, nil, 0)
		waitFor(t, func() bool { return !r.Reading() }, "Reading still true after the drain failed")
	})
}
