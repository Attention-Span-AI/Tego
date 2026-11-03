// SPDX-License-Identifier: Apache-2.0

package web

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// TestReceiptLiveSinceMarksOnlyARunningRunsTime: the Receipt tab's time taken is a clock (data-since, data-ck, so
// the region's hash leaves it out) only while it is measured to now; an ended run's time and one measured to its
// last line are fixed text. Before, a running run's tab was re-sent whenever its seconds changed, and
// TestRegionRequest failed when two requests straddled a second (race job, PR 20).
func TestReceiptLiveSinceMarksOnlyARunningRunsTime(t *testing.T) {
	start := time.Date(2026, 11, 3, 9, 0, 0, 0, time.UTC)
	rc := func(soFar bool, note string, started *time.Time) *receiptView {
		r := &ledgerview.Receipt{Started: started}
		r.Time.SoFar, r.Time.Note = soFar, note
		return &receiptView{R: r}
	}
	for name, c := range map[string]struct {
		v    *receiptView
		want string
	}{
		"running":           {rc(true, "", &start), "2026-11-03T09:00:00Z"},
		"to its last line":  {rc(true, "no run_end line: measured to the last line", &start), ""},
		"ended":             {rc(false, "", &start), ""},
		"no start recorded": {rc(true, "", nil), ""},
		"no receipt":        {&receiptView{Err: "x"}, ""},
	} {
		if got := c.v.LiveSince(); got != c.want {
			t.Errorf("%s: LiveSince() = %q, want %q", name, got, c.want)
		}
	}
}
