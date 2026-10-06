// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestIdleUsesTheWallClockWithoutTheLock: a ledger whose lock is gone may come from another boot, and a mono
// stamp that happens to sit below this boot's clock must not be read as elapsed time (R9). 48h of wall time
// passed, and this boot's clock reads only 10s past the old stamp.
func TestIdleUsesTheWallClockWithoutTheLock(t *testing.T) {
	dir := writeWithClock(t, fixedClock{base})
	r, err := ledger.OpenReader(dir)
	if err != nil {
		t.Fatalf("open reader: %v", err)
	}
	defer func() { _ = r.Close() }()
	mono := uint64(base.UnixNano()) + uint64(10*time.Second)
	s, err := Derive(r, false, base.Add(48*time.Hour), time.Hour, WithMonoNow(func() uint64 { return mono }))
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if s.IdleClock != ClockWall || s.Idle != 48*time.Hour {
		t.Errorf("idle %s from the %s clock, want 48h wall", s.Idle, s.IdleClock)
	}
}

// TestStatusStepCountsDecisionSteps: a decision carries the model's turn counter and gets no attribution, so
// a run of decisions alone still has a step, as measure's Steps reads it (R18).
func TestStatusStepCountsDecisionSteps(t *testing.T) {
	dir := write(t, true, func(w *ledger.Writer) {
		runStart("")(w)
		appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 1})
		appendEvent(w, record.KindDecision, record.DecisionPayload{Step: 2})
	}, nil)
	if s := derive(t, dir, true, base, time.Hour); s.Step != 2 {
		t.Errorf("step %d, want 2", s.Step)
	}
}
