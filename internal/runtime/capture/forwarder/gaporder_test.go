// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// A listener's gap report is ordered by reason, as every other source's is, so the gap lines run_end
// writes come in the same order on every run. It was built by ranging over a map.
func TestListenerGapsAreOrderedByReason(t *testing.T) {
	l, err := NewListener(agent.ModelEndpoint{Provider: "anthropic", Host: "api.anthropic.com"}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	for _, why := range []string{GapSizeCap, GapMalformed, GapEmitQueueFull, "z-reason", "a-reason", "m-reason"} {
		l.note(why, 1)
	}
	for range 50 {
		got := l.Gaps()
		if !slices.IsSortedFunc(got, func(a, b source.Gap) int { return strings.Compare(a.Why, b.Why) }) {
			t.Fatalf("gaps not ordered by reason: %+v", got)
		}
	}
}
