// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSkippedProgramsMakeRulesUncertain: a skip of a shared program the run's rules rely on (ADR 0148) is its own
// class, says the rules may not have held and that the skip may be another run's, counts no lost event, and never
// leaves "no action known to be missing" beside it.
func TestSkippedProgramsMakeRulesUncertain(t *testing.T) {
	for _, why := range []string{record.GapDecidingSkip, record.GapTrackingSkip, record.GapSkipCounterUnavailable} {
		if got := Classify(record.GapEnforce, why); got != RulesUncertain {
			t.Errorf("Classify(enforce, %s) = %d, want RulesUncertain", why, got)
		}
		if got := Classify(record.GapRecord, why); got != Missed {
			t.Errorf("Classify(record, %s) = %d: only what=enforce is this class", why, got)
		}
	}
	var tally Tally
	tally.Add(gap(t, record.GapPayload{What: record.GapEnforce, Why: record.GapDecidingSkip, Count: 3, DecisionPlane: "lsm"}))
	tally.Add(gap(t, record.GapPayload{What: record.GapEnforce, Why: record.GapTrackingSkip, Count: 2}))
	counts := tally.Counts()
	for _, c := range counts {
		if c.Lost != 0 || c.SharedSkipped == 0 {
			t.Errorf("%s: lost %d, skipped %d", c.Why, c.Lost, c.SharedSkipped)
		}
	}
	words := Words(counts, false)
	for _, want := range []string{"the rules may not have held", "3 executions of shared programs that decide",
		"2 executions of the shared program that adds", "other runs or ungoverned tasks"} {
		if !strings.Contains(words, want) {
			t.Errorf("words %q lack %q", words, want)
		}
	}
	if strings.Contains(words, "no action known to be missing") || strings.Contains(words, "events lost") {
		t.Errorf("words overclaim: %q", words)
	}
	if line := Line(counts); !strings.Contains(line, "enforce/bpf-decision-skip/shared-build x1") ||
		!strings.Contains(line, "may not have held") {
		t.Errorf("line %q", line)
	}
	// Rules first: the gravest thing a gap can say leads, ahead of a missed-actions count.
	mixed := append(counts, Count{What: record.GapRecord, Why: "channel-full", Events: 1})
	if w := Words(mixed, false); !strings.HasPrefix(w, "the rules may not have held") || !strings.Contains(w, "1 gap in the record") {
		t.Errorf("mixed words %q", w)
	}
	var unread Tally
	unread.Add(gap(t, record.GapPayload{What: record.GapEnforce, Why: record.GapSkipCounterUnavailable}))
	if w := Words(unread.Counts(), false); !strings.Contains(w, "could not be read") || !strings.Contains(w, "may not have held") {
		t.Errorf("unreadable words %q", w)
	}
}
