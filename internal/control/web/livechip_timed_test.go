// SPDX-License-Identifier: Apache-2.0

package web

import (
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLiveChipTimeLimits: a block that `tego unblock --for` made dormant, or whose `--for` limit passed, is never shown
// "In force" on the run page: the agent can do what it names (ADR 0125 decision 4). A confirmed block with a limit
// ahead is in force until that limit, not "until the run ends"; an untimed one keeps today's words.
func TestLiveChipTimeLimits(t *testing.T) {
	now := time.Now()
	facts := ledgerview.LiveFacts{Facts: livestatus.Facts{RecordMinor: record.MinorLiveModes, Timed: true, ReadsSeen: true}, Confirmed: 5, ConfirmedSeq: 9}
	v := liveView{Facts: facts, Serials: map[string]uint64{"exec:/bin/curl": 3}, Serial: 5, Now: now}
	block := liveblock.Entry{Kind: liveblock.KindExec, Value: "/bin/curl", By: "cli", At: now.Add(-2 * time.Hour)}

	untimed := liveChipOf(block, v)
	if untimed.State != ledgerview.LiveInForce || untimed.Note != "Refused from the next try until the run ends." {
		t.Errorf("untimed chip changed: %+v", untimed)
	}

	dormant := block
	dormant.From = now.Add(time.Hour)
	c := liveChipOf(dormant, v)
	if c.State != ledgerview.LiveDormant || c.Label != "Unblocked for a while" || strings.Contains(c.Label+c.Note, "In force") ||
		!strings.Contains(c.Note, "Refuses nothing until "+limitAt(dormant.From)) {
		t.Errorf("dormant chip: %+v", c)
	}

	expired := block
	expired.Until = now.Add(-time.Hour)
	c = liveChipOf(expired, v)
	if c.State != ledgerview.LiveExpired || c.Label != "Ended by its time limit" || strings.Contains(c.Label+c.Note, "In force") {
		t.Errorf("expired chip: %+v", c)
	}

	timed := block
	timed.Until = now.Add(time.Hour)
	c = liveChipOf(timed, v)
	if c.State != ledgerview.LiveInForce || c.Note != "Refused from the next try until "+limitAt(timed.Until)+"." ||
		c.Sentence != livestatus.SentenceInForceUntil {
		t.Errorf("timed chip: %+v", c)
	}

	// The Rules page's pending change, the Saved page's and the line page's outcomes judge the same limit.
	lb := runact.LiveBlocks{Blocks: []liveblock.Entry{dormant}, Serials: map[string]uint64{"exec:/bin/curl": 3}, Serial: 5}
	pl := pendingLiveOf(rules.PendingNow{Placed: []string{"exec:/bin/curl"}}, true, facts, lb, shortener{}, now)
	if pl.State == "live" || !strings.Contains(pl.Note, "unblocked for a while") {
		t.Errorf("pending, dormant: %+v", pl)
	}
	lb.Blocks = []liveblock.Entry{expired}
	pl = pendingLiveOf(rules.PendingNow{Placed: []string{"exec:/bin/curl"}}, true, facts, lb, shortener{}, now)
	if pl.State == "live" || !strings.Contains(pl.Note, "ended by its time limit") {
		t.Errorf("pending, expired: %+v", pl)
	}
	for _, e := range []liveblock.Entry{dormant, expired} {
		state, before, _, _ := liveOutWords(facts.StatusAt("exec", 3, now, e.From, e.Until))
		if strings.HasPrefix(before, "Live now") || (state != ledgerview.LiveDormant && state != ledgerview.LiveExpired) {
			t.Errorf("line page outcome for %+v: %s %q", e, state, before)
		}
	}
}
