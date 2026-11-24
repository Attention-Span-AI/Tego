// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"testing"
	"time"
)

// The helper check's deadlines are their written values in an ordinary build and ten times them in a race build only
// (racescale.go), as the draft compiler's are.
func TestDeadlinesScaleOnlyUnderRace(t *testing.T) {
	want := map[string][2]time.Duration{
		"CheckTimeout": {CheckTimeout, 5 * time.Second},
		"StartTimeout": {StartTimeout, 30 * time.Second},
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
