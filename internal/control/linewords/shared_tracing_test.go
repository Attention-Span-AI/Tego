// SPDX-License-Identifier: Apache-2.0

package linewords

import (
	"strings"
	"testing"
)

func TestSharedTracingGapWordsKeepCoverageUncertain(t *testing.T) {
	for _, why := range []string{"bpf-trampoline-miss/shared-build", "bpf-trampoline-counter-unavailable"} {
		words, ok := GapWhy(why)
		if !ok || !strings.Contains(words, "uncertain") || strings.Contains(words, "events lost") {
			t.Errorf("gap explanation %q = %q (%v), want uncertainty rather than a known missing action", why, words, ok)
		}
		if why == "bpf-trampoline-miss/shared-build" && !strings.Contains(words, "other runs or ungoverned tasks") {
			t.Errorf("gap explanation loses shared scope: %q", words)
		}
	}
}
