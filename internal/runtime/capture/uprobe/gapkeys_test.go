// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"fmt"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
)

// TestAgentNamedGapKeysAreCapped: the binary of a size-cap gap is a path the agent chose (an open past
// MaxOpenAttach), so one gap event per name was one event per file it opened. Past derive.MaxCoverageKeys
// the count goes into one binary-less entry per reason, and the total is kept (R37).
func TestAgentNamedGapKeysAreCapped(t *testing.T) {
	u, _ := newTestUprobe(t, nil, Options{})
	const n = derive.MaxCoverageKeys + 300
	for i := range n {
		u.gap(GapSizeCap, fmt.Sprintf("/tmp/x%d/libssl.so.3", i), 1, "")
	}
	gaps := u.Gaps()
	if len(gaps) > derive.MaxCoverageKeys+1 {
		t.Fatalf("%d gap entries for %d distinct names, want at most %d", len(gaps), n, derive.MaxCoverageKeys+1)
	}
	if got := gapCount(gaps, GapSizeCap); got != n {
		t.Errorf("size-cap total = %d, want %d", got, n)
	}
}
