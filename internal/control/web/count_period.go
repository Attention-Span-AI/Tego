// SPDX-License-Identifier: Apache-2.0

package web

import (
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
)

// dailyRefusals uses complete run totals when all their refusal timestamps fall
// in today. A run spanning midnight needs its events; an incomplete window can
// only establish a lower bound. Bounds use timestamps, not start/end ordering,
// since a clock change can move a refusal outside the run's start/end interval.
func dailyRefusals(snap *ledgerview.Snapshot, now time.Time) (n int, lower bool, records []*ledgerview.Run) {
	start := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	c := snap.RefusalBuckets([]time.Time{start, start.AddDate(0, 0, 1)})
	return c.Counts[0], c.Lower, c.Records
}
