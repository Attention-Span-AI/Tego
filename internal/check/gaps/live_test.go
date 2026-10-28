// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"reflect"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSplitLiveChanges: a person's live changes (blocks, lifts, pauses, MCP tool switches, model routes, and what
// became of them) leave the gap line for their own; an unreadable or lost overlay, another what with a live why's
// name, and every other gap stay gaps. Each half keeps the tally's order.
func TestSplitLiveChanges(t *testing.T) {
	live := []string{
		record.GapLiveBlockAdded, record.GapLiveBlockRemoved, record.GapLiveBlockExpired, record.GapLiveUnblockExpired,
		record.GapLiveRuleLifted, record.GapLiveRuleRestored, record.GapLiveLiftExpired, record.GapLiveLiftRefused,
		record.GapRunPaused, record.GapRunResumed, record.GapPauseFailed, record.GapResumeFailed,
		record.GapMCPToolChanged, record.GapModelRouteChanged,
	}
	for _, why := range live {
		if !LiveChange(record.GapEnforce, why) {
			t.Errorf("enforce/%s is not a live change", why)
		}
	}
	for _, c := range [][2]string{
		{record.GapEnforce, record.GapLiveBlockUnreadable}, {record.GapEnforce, record.GapLiveBlockLost},
		{record.GapCapture, record.GapRunPaused}, {"record", "channel-full"}, {record.GapEnforce, "landlock-unavailable"},
		{Unknown, Unknown},
	} {
		if LiveChange(c[0], c[1]) {
			t.Errorf("%s/%s is taken for a live change", c[0], c[1])
		}
	}

	var tl Tally
	for _, p := range []record.GapPayload{
		{What: record.GapEnforce, Why: record.GapRunResumed},
		{What: record.GapEnforce, Why: record.GapLiveBlockAdded},
		{What: "capture", Why: "no-openssl", Binary: "/usr/bin/gh"},
		{What: record.GapEnforce, Why: record.GapRunPaused},
		{What: record.GapEnforce, Why: record.GapLiveBlockLost, Count: 2},
	} {
		tl.Add(gap(t, p))
	}
	missed, changes := Split(tl.Counts())
	if got, want := Line(missed), "capture/no-openssl x1 (in /usr/bin/gh); enforce/live-block-lost x1 (2 events lost)"; got != want {
		t.Errorf("gaps = %q\nwant %q", got, want)
	}
	if got, want := Line(changes), "enforce/live-block-added x1; enforce/run-paused x1; enforce/run-resumed x1"; got != want {
		t.Errorf("live changes = %q\nwant %q", got, want)
	}
	if g, l := Split(nil); g != nil || l != nil {
		t.Errorf("Split(nil) = %v, %v; want nil, nil", g, l)
	}
	only := []Count{{What: record.GapEnforce, Why: record.GapRunPaused, Events: 1}}
	if g, l := Split(only); g != nil || !reflect.DeepEqual(l, only) {
		t.Errorf("Split(a pause) = %v, %v; want no gap and the pause", g, l)
	}
}
