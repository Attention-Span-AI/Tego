// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// TestExecIDAgreesAcrossPrecisions is the reason ExecID exists: the supervisor builds an exec id from
// /proc's tick count and the tier-2 recorder from the kernel's exact start, and for one process the two
// must be one id, or parent_exec_id written by one never matches exec_id written by the other.
func TestExecIDAgreesAcrossPrecisions(t *testing.T) {
	const run = identity.RunID("r-0123abcd-0000000000000-abcdef")
	st, err := ParseStat([]byte(statLine(4242, "python3", 1, 1, 98765)))
	if err != nil {
		t.Fatal(err)
	}
	fromProc := ExecID(run, 4242, st.StartBootNS())
	for _, exact := range []uint64{
		98765 * NanosPerTick,                  // the process started on a tick boundary
		98765*NanosPerTick + 1,                // just after one
		98765*NanosPerTick + 3_000_000,        // 3 ms into the tick
		98765*NanosPerTick + NanosPerTick - 1, // the last nanosecond /proc rounds down
	} {
		if got := ExecID(run, 4242, exact); got != fromProc {
			t.Errorf("exact start %d gives %q, /proc gives %q: one process, two exec ids", exact, got, fromProc)
		}
	}
	if want := identity.NewExecID(run, 4242, 98765*NanosPerTick); fromProc != want {
		t.Errorf("ExecID = %q, want %q (RUN-IDENTITY's <run>/<pid>/<start-boot-ns>)", fromProc, want)
	}
	// The next tick is a different process: pid reuse stays distinguishable (E14, E30).
	if next := ExecID(run, 4242, 98766*NanosPerTick); next == fromProc {
		t.Errorf("a process starting one tick later shares the exec id %q", next)
	}
}

func TestExecStartNS(t *testing.T) {
	for _, tc := range []struct{ in, want uint64 }{
		{0, 0}, {1, 0}, {NanosPerTick - 1, 0}, {NanosPerTick, NanosPerTick}, {3*NanosPerTick + 7, 3 * NanosPerTick},
	} {
		if got := ExecStartNS(tc.in); got != tc.want {
			t.Errorf("ExecStartNS(%d) = %d, want %d", tc.in, got, tc.want)
		}
	}
}
