// SPDX-License-Identifier: Apache-2.0

package receipt

import (
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiveModeWhysAreNoLostActions: a time limit's end, a lift, a restore and a refused lift (ADR 0125, record minor
// 26) say what happened to the run's live rules; none lost an action, so a run that used them keeps a complete
// receipt.
func TestLiveModeWhysAreNoLostActions(t *testing.T) {
	for _, why := range []string{record.GapLiveBlockExpired, record.GapLiveUnblockExpired, record.GapLiveRuleLifted,
		record.GapLiveRuleRestored, record.GapLiveLiftExpired, record.GapLiveLiftRefused} {
		t.Run(why, func(t *testing.T) {
			lines := pausedAndBlockedRun(line{kind: record.KindGap, at: 8 * time.Second,
				payload: record.GapPayload{What: record.GapEnforce, Why: why}})
			lines[0] = start("forwarder", true)
			rc := compute(t, lines, Options{})
			if _, ok := coverageFields(rc)["record"]; ok || !rc.Coverage.Complete {
				t.Errorf("%s counts as a lost action: %+v", why, rc.Coverage)
			}
		})
	}
}
