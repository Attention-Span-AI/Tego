// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/contracts"
	"github.com/attention-span-ai/tego/internal/control/draftcompile"
)

// TestOuterDeadlinesWrapTheScaledOnes: in every build each deadline that wraps another is strictly longer than the one
// it wraps, so a race build (where the inner ones are scaled) cuts a page at the same place an ordinary build does.
// An ordinary build keeps the written values exactly.
func TestOuterDeadlinesWrapTheScaledOnes(t *testing.T) {
	for _, c := range []struct {
		name         string
		outer, inner time.Duration
	}{
		{"guide computation over a contract check", guideCompute, contracts.CheckTimeout},
		{"write timeout over the guide computation", writeTimeout, guideCompute},
		{"write timeout over a draft compile", writeTimeout, draftcompile.Budget + draftcompile.AdmissionWait},
		{"write timeout over a contract check", writeTimeout, contracts.CheckTimeout},
		{"write timeout over the bound of a page's checks", writeTimeout, requestBound},
		{"the bound of a page's checks over a contract check", requestBound, contracts.CheckTimeout},
		{"an answer's exchange over a contract check", answerTimeout, contracts.CheckTimeout},
	} {
		if c.outer <= c.inner {
			t.Errorf("%s: %v does not wrap %v", c.name, c.outer, c.inner)
		}
	}
	if !raceEnabled && (guideCompute != 20*time.Second || writeTimeout != 30*time.Second || answerTimeout != 10*time.Second) {
		t.Errorf("an ordinary build changed a deadline: guide %v, write %v, answer %v", guideCompute, writeTimeout, answerTimeout)
	}
	if raceEnabled && raceScale != testRaceScale {
		t.Errorf("raceScale %d, testRaceScale %d", raceScale, testRaceScale)
	}
}
