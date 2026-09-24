// SPDX-License-Identifier: Apache-2.0

package status

import (
	"testing"
	"time"
)

// TestDeriveHonoursAZeroStallAfter is R12 reading run_start.limits the way the runtime now writes it: a key is
// present exactly when the run had that budget, and "0s" is a budget (E16) — the tightest one, which
// limits.Watcher ends the run on at its first idle tick. Falling back to the machine's hour would show such a
// run as running for as long as it lasted; only a run_start with no stall_after at all takes the default.
func TestDeriveHonoursAZeroStallAfter(t *testing.T) {
	dir := write(t, true, runStart("0s"), nil)
	s := derive(t, dir, true, base.Add(time.Second), 0)
	if s.StallAfter != 0 || s.StallAfterSource != SourceRunStart {
		t.Fatalf("stall_after %v from %s, want the run's own 0 from run_start", s.StallAfter, s.StallAfterSource)
	}
	if s.St != Stalled {
		t.Fatalf("state %s, want stalled: any idle is past a stall_after of 0 (R9)", s.St)
	}

	open := write(t, true, runStart(""), nil)
	if s := derive(t, open, true, base.Add(time.Second), 0); s.StallAfter != DefaultStallAfter || s.StallAfterSource != SourceMachine {
		t.Fatalf("no stall_after gave %v from %s, want the machine default", s.StallAfter, s.StallAfterSource)
	}
}
