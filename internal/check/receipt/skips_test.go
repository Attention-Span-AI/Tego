// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSkippedProgramsMakeTheRulesUncertain: a run whose deciding or tracking program the kernel skipped (ADR 0148) has
// a receipt whose coverage is incomplete on its refusals, with code rules-uncertain, the count, and the shared scope;
// the same run without the line has no such entry.
func TestSkippedProgramsMakeTheRulesUncertain(t *testing.T) {
	for _, why := range []string{record.GapDecidingSkip, record.GapTrackingSkip, record.GapSkipCounterUnavailable} {
		t.Run(why, func(t *testing.T) {
			count := 5
			if why == record.GapSkipCounterUnavailable {
				count = 0
			}
			lines := pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second,
				payload: record.GapPayload{What: record.GapEnforce, Why: why, Count: count}})
			lines[0] = start("forwarder", true)
			rc := compute(t, lines, Options{})
			words := coverageFields(rc)["refusals"]
			if rc.Coverage.Complete || !strings.Contains(words, "the rules may not have held") {
				t.Fatalf("coverage %+v", rc.Coverage)
			}
			var code string
			for _, g := range rc.Coverage.Gaps {
				if g.Field == "refusals" {
					code = g.Code
				}
			}
			if code != CodeRulesUncertain {
				t.Errorf("refusals code %q", code)
			}
			if count > 0 && (!strings.Contains(words, "5 executions") || !strings.Contains(words, "other runs or ungoverned tasks")) {
				t.Errorf("words %q", words)
			}
			if _, missed := coverageFields(rc)["record"]; missed {
				t.Errorf("a skip was counted as a missed action: %+v", rc.Coverage)
			}
			var text bytes.Buffer
			if err := rc.Text(&text); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(text.String(), "may not have held") {
				t.Errorf("receipt text: %s", text.String())
			}
		})
	}
	lines := pausedAndBlockedRun()
	lines[0] = start("forwarder", true)
	if _, ok := coverageFields(compute(t, lines, Options{}))["refusals"]; ok {
		t.Error("a run with no skip line has a refusals coverage entry")
	}
}
