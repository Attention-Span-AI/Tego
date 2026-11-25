// SPDX-License-Identifier: Apache-2.0

package record

import (
	"testing"
	"time"
)

// TestLiveBlockOfACommandNeedsNoNewRevision (ADR 0171): a live block on a command's words is an exec block whose value
// is the command's text, so its gap lines are valid at every revision a live exec block's are, the rule is
// live.block[exec:<words>], and a rule that is not the value's is refused as for any block. Nothing of the record
// changes for it.
func TestLiveBlockOfACommandNeedsNoNewRevision(t *testing.T) {
	at := time.Date(2026, 11, 25, 12, 0, 0, 0, time.UTC)
	line := func(why, op, value, rule string) GapPayload {
		return GapPayload{What: GapEnforce, Why: why, LiveBlock: &LiveBlockChange{Op: op, Kind: "exec", Value: value,
			Rule: rule, By: "uid:1 pid:2 cli", Serial: 1, At: at}}
	}
	const words = "npm install --global *"
	for _, why := range []string{GapLiveBlockAdded, GapLiveBlockRemoved} {
		op := map[string]string{GapLiveBlockAdded: "add", GapLiveBlockRemoved: "remove"}[why]
		for _, minor := range []int{MinorLiveBlock, MinorLiveModes, MinorEveryLaunch, Minor} {
			e := liveModesEvent(t, KindGap, "", line(why, op, words, "live.block[exec:"+words+"]"))
			if err := e.ValidateAt(minor); err != nil {
				t.Errorf("%s at %d: %v", why, minor, err)
			}
		}
		e := liveModesEvent(t, KindGap, "", line(why, op, words, "live.block[exec:npm install]"))
		if got := FieldCode(e.ValidateAt(Minor)); got != "live-block" {
			t.Errorf("%s with another rule: [%s], want [live-block]", why, got)
		}
	}
	if LiveRule("exec", "git push") != "live.block[exec:git push]" {
		t.Errorf("LiveRule = %q", LiveRule("exec", "git push"))
	}
}
