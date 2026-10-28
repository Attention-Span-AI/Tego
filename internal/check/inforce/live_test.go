// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/check/livestatus"
)

// TestAddLiveStatus: a live block's line on the Rules page says its state now, and only a block that refuses
// something is said to be enforced at all.
func TestAddLiveStatus(t *testing.T) {
	cases := []struct {
		kind, value string
		state       livestatus.State
		sentence    string
		want        string
		claim       State
	}{
		{"exec", "curl", livestatus.InForce, livestatus.SentenceInForce, "Blocked now: cannot run curl", StateBestEffort},
		{"exec", "curl", livestatus.RecordedOnly, livestatus.SentenceRecordedOnly, "Marked now (recorded, not refused): cannot run curl", StateNotEnforced},
		{"net", "example.com:443", livestatus.Waiting, livestatus.SentenceWaiting, "Blocking: cannot connect to example.com on port 443", StateNotEnforced},
		{"path", "/p/data", livestatus.Partial, livestatus.SentencePartial, "Blocked now: cannot change /p/data (reads still go through)", StateBestEffort},
		{"path", "/p/data", livestatus.InForce, livestatus.SentenceInForce, "Blocked now: cannot open or change /p/data", StateBestEffort},
		{"exec", "curl", livestatus.Dormant, livestatus.SentenceDormant, "Unblocked for a while (refuses nothing until its time limit): cannot run curl", StateNotEnforced},
		{"exec", "curl", livestatus.Expired, livestatus.SentenceExpired, "Ended by its time limit: cannot run curl", StateNotEnforced},
	}
	for _, c := range cases {
		t.Run(string(c.state)+"/"+c.kind, func(t *testing.T) {
			v := newView()
			v.AddLiveStatus(c.kind, c.value, "uid:1000 pid:1 dashboard", c.state, c.sentence)
			rs := v.Group(GroupLive).Rules
			if len(rs) != 1 {
				t.Fatalf("live group holds %d rules", len(rs))
			}
			r := rs[0]
			if r.Sentence != c.want || r.EnforcedText != c.sentence || r.State != c.claim {
				t.Fatalf("rule = %q / %q / %s, want %q / %q / %s", r.Sentence, r.EnforcedText, r.State, c.want, c.sentence, c.claim)
			}
			if r.RuleKey != "live.block["+c.kind+":"+c.value+"]" {
				t.Fatalf("RuleKey = %q", r.RuleKey)
			}
		})
	}
}

// TestAddLiveKeepsItsClaim: the wrapper keeps AddLive's old claim, so a caller that knows no facts is unchanged.
func TestAddLiveKeepsItsClaim(t *testing.T) {
	v := newView()
	v.AddLive("exec", "curl", "uid:1000 pid:1 cli")
	r := v.Group(GroupLive).Rules[0]
	if r.EnforcedText != textLive || r.State != StateBestEffort || r.Sentence != "Blocked now: cannot run curl" {
		t.Fatalf("AddLive = %+v", r)
	}
}

// TestLiveGroupCopy: the live group's heading, lede and footer follow its rows, so a group that refuses nothing is
// never headed "Blocked" nor footed "refuses more than the rules file".
func TestLiveGroupCopy(t *testing.T) {
	cases := []struct {
		name   string
		states []livestatus.State
		title  string
		foot   string
	}{
		{"marks", []livestatus.State{livestatus.RecordedOnly, livestatus.RecordedOnly}, "Marked live now", "A mark refuses nothing"},
		{"waiting", []livestatus.State{livestatus.Waiting}, "Blocking live", "A block refuses nothing until the run puts it in force"},
		{"one refuses", []livestatus.State{livestatus.Waiting, livestatus.Partial}, "Blocked live now", "A live block refuses more than the rules file"},
		{"in force", []livestatus.State{livestatus.InForce}, "Blocked live now", "A live block refuses more than the rules file"},
		{"time limits", []livestatus.State{livestatus.Dormant, livestatus.Expired}, "Live blocks, none refusing now", "A block unblocked for a while refuses again"},
		{"dormant and waiting", []livestatus.State{livestatus.Dormant, livestatus.Waiting}, "Blocking live", "A block refuses nothing until the run puts it in force"},
		{"dormant and in force", []livestatus.State{livestatus.Dormant, livestatus.InForce}, "Blocked live now", "A live block refuses more than the rules file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := newView()
			for i, st := range c.states {
				v.AddLiveStatus("exec", "p"+string(rune('a'+i)), "uid:1000 pid:1 dashboard", st, "")
			}
			g := v.Group(GroupLive)
			if g.Title != c.title || !strings.HasPrefix(g.Default, c.foot) || g.Lede == "" {
				t.Fatalf("group = %q / %q / %q, want %q / %q…", g.Title, g.Lede, g.Default, c.title, c.foot)
			}
			if c.title != "Blocked live now" && (g.Lede == groupCopy[GroupLive][1] || strings.HasPrefix(g.Default, "A live block refuses")) {
				t.Fatalf("a group that refuses nothing claims a refusal: %q / %q", g.Lede, g.Default)
			}
		})
	}
}
