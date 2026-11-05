// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestSharedTracingSkipsAreNotLostEvents(t *testing.T) {
	var tally Tally
	tally.Add(gap(t, record.GapPayload{What: record.GapRecord, Why: "bpf-trampoline-miss/shared-build", Count: 17}))
	counts := tally.Counts()
	if counts[0].Lost != 0 {
		t.Errorf("shared skipped executions counted as %d lost events", counts[0].Lost)
	}
	for _, text := range []string{Line(counts), Words(counts, false), Line(Merge(counts))} {
		if strings.Contains(text, "events lost") || !strings.Contains(text, "17") ||
			!strings.Contains(text, "shared tracing") || !strings.Contains(text, "other runs or ungoverned tasks") {
			t.Errorf("shared skip count lost its scope: %q", text)
		}
	}
}

func TestTracingCounterUnavailableIsUncertainCoverage(t *testing.T) {
	var tally Tally
	tally.Add(gap(t, record.GapPayload{What: record.GapRecord, Why: "bpf-trampoline-counter-unavailable", Count: 1}))
	counts := tally.Counts()
	if counts[0].Lost != 0 || strings.Contains(Line(counts), "events lost") || !strings.Contains(Words(counts, false), "uncertain") {
		t.Fatalf("unavailable counter claims a known loss: %+v; %s; %s", counts, Line(counts), Words(counts, false))
	}
}
