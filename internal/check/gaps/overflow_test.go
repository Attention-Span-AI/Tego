// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestTallySaturatesLargeRecordedGapCounts(t *testing.T) {
	maximum := int(^uint(0) >> 1)
	for _, binary := range []string{"", "/usr/bin/helper"} {
		t.Run(binary, func(t *testing.T) {
			var tally Tally
			for _, count := range []int{maximum, 1} {
				e := &record.Event{Kind: record.KindGap}
				if err := e.SetPayload(record.GapPayload{What: "record", Why: "channel-full", Count: count, Binary: binary}); err != nil {
					t.Fatal(err)
				}
				tally.Add(e)
			}
			counts := tally.Counts()
			if len(counts) != 1 || counts[0].Events != 2 {
				t.Fatalf("counts = %+v", counts)
			}
			got := counts[0].Lost
			if binary != "" {
				got = counts[0].Processes
			}
			if got != maximum {
				t.Fatalf("total = %d, want saturated %d", got, maximum)
			}
			if binary == "" && !strings.Contains(Line(counts), "events lost") {
				t.Fatalf("lost-event detail hidden: %s", Line(counts))
			}
		})
	}
}

func TestMergeSaturatesGapTotals(t *testing.T) {
	maximum := int(^uint(0) >> 1)
	base := Count{What: "record", Why: "channel-full", Events: maximum, Lost: maximum, Processes: maximum}
	extra := Count{What: base.What, Why: base.Why, Events: 1, Lost: 1, Processes: 1}
	got := Merge([]Count{base}, []Count{extra})
	if len(got) != 1 || got[0].Events != maximum || got[0].Lost != maximum || got[0].Processes != maximum {
		t.Fatalf("merged totals = %+v, want saturated %d", got, maximum)
	}
}
