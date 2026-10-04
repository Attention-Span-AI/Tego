// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestFinalDrainWritesTheCaptureGapItReports: capture drops that only the final drain reports, after the run
// quiesced, still leave gap what=capture why=unmetered-after-exit in the record: the gap that report queues is
// handled by the drain, not left on a queue nobody reads.
func TestFinalDrainWritesTheCaptureGapItReports(t *testing.T) {
	r, cgroups, sink, _ := budgetRunner(t, agent.ResolvedLimits{CostUSD: 1})
	r.quiesced.Store(true)
	r.pipe.onCaptureLost = r.captureLost
	r.queue.dropped[LaneCapture].Add(3)
	r.pipe.drain()
	if cgroups.killed != 0 {
		t.Fatalf("a drop after quiesce killed the tree %d times", cgroups.killed)
	}
	if !hasUnmeteredAfterExitGap(t, sink, 3) {
		t.Errorf("no gap what=capture why=%s count=3 after the final drain", GapUnmeteredAfterExit)
	}
}
