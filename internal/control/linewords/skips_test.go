// SPDX-License-Identifier: Apache-2.0

package linewords

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSkippedProgramGapWordsSayTheRulesMayNotHaveHeld (ADR 0148): each why has words, they say the rules may not have
// held, and a count's words keep the shared scope.
func TestSkippedProgramGapWordsSayTheRulesMayNotHaveHeld(t *testing.T) {
	for _, why := range []string{record.GapDecidingSkip, record.GapTrackingSkip, record.GapSkipCounterUnavailable} {
		words, ok := GapWhy(why)
		if !ok || !strings.Contains(words, "may not have held") {
			t.Errorf("GapWhy(%s) = %q, %v", why, words, ok)
		}
		if why != record.GapSkipCounterUnavailable && !strings.Contains(words, "other runs or ungoverned tasks") {
			t.Errorf("GapWhy(%s) loses the shared scope: %q", why, words)
		}
	}
}
