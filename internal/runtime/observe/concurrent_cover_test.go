// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
)

// coveredBySkips judges one run's count of a kind of action against what its agent did. A run on a kernel that
// preempts kernel code may have a recorder program skipped before it can name the run (GAPS C53 (c)), and the
// recorder says so with the shared-build skip count of its window (GapTrampolineMiss), which no run's shortfall
// may exceed: the run's record is exact when nothing was skipped, and short by at most the skips it reports when
// something was. More than the agent did is never right, and a shortfall with no skip reported is a silent loss.
func coveredBySkips(got, want, skips int) bool {
	return got <= want && got+skips >= want
}

// sharedSkips sums the shared-build skip count the gaps carry.
func sharedSkips(gaps []source.Gap) int {
	n := 0
	for _, g := range gaps {
		if g.Why == GapTrampolineMiss {
			n += int(g.Count)
		}
	}
	return n
}

func TestCoveredBySkips(t *testing.T) {
	for _, tc := range []struct {
		name            string
		got, want, skip int
		ok              bool
	}{
		{"exact, nothing skipped", 3000, 3000, 0, true},
		{"exact, skips elsewhere", 3000, 3000, 7, true},
		{"short, covered by the reported skips", 1854, 3000, 1146, true},
		{"short, covered with room to spare", 1854, 3000, 5000, true},
		{"short, silent: no skip reported", 1854, 3000, 0, false},
		{"short, more than the skips cover", 1854, 3000, 1145, false},
		{"more than the agent did", 3001, 3000, 9, false},
		{"exec lost to a reported skip", 0, 1, 2, true},
		{"exec lost silently", 0, 1, 0, false},
		{"exec twice", 2, 1, 2, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := coveredBySkips(tc.got, tc.want, tc.skip); got != tc.ok {
				t.Fatalf("coveredBySkips(%d, %d, %d) = %v, want %v", tc.got, tc.want, tc.skip, got, tc.ok)
			}
		})
	}
}

func TestSharedSkipsSumsOnlyTheSharedBuildGap(t *testing.T) {
	gaps := []source.Gap{{Why: GapTrampolineMiss, Count: 7}, {Why: GapRingbufFull, Count: 100}, {Why: GapTrampolineMiss, Count: 2}}
	if got := sharedSkips(gaps); got != 9 {
		t.Fatalf("sharedSkips = %d, want 9", got)
	}
	if got := sharedSkips(nil); got != 0 {
		t.Fatalf("sharedSkips(nil) = %d, want 0", got)
	}
}
