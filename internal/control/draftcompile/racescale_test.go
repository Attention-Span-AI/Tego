// SPDX-License-Identifier: Apache-2.0

package draftcompile

import (
	"testing"
	"time"
)

// The draft compiler's deadlines are their written values in an ordinary build and ten times them in a race build
// only (racescale.go): under -race a builder request's draft compiles outran the 3 s budget and internal/cli and
// internal/control/web failed with "draft compilation stopped: context deadline exceeded".
func TestDeadlinesScaleOnlyUnderRace(t *testing.T) {
	want := map[string][2]time.Duration{
		"Budget":        {Budget, 3 * time.Second},
		"AdmissionWait": {AdmissionWait, 100 * time.Millisecond},
	}
	for name, c := range want {
		if got, base := c[0], c[1]; got != base*time.Duration(raceScale) || raceEnabled != (raceScale != 1) {
			t.Errorf("%s = %v, want %v times %d (race build %v)", name, got, base, raceScale, raceEnabled)
		}
	}
	if raceEnabled && raceScale != 10 {
		t.Errorf("a race build scales by %d, want the measured 10", raceScale)
	}
}
