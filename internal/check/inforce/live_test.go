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
		{"write", "/p/out", livestatus.InForce, livestatus.SentenceInForce, "Blocked now: cannot change /p/out (reads still go through)", StateBestEffort},
		{"write", "/p/out", livestatus.RecordedOnly, livestatus.SentenceRecordedOnly, "Marked now (recorded, not refused): cannot change /p/out (reads still go through)", StateNotEnforced},
		{"read", "/p/data", livestatus.Waiting, livestatus.SentenceWaiting, "Blocking: cannot read /p/data", StateNotEnforced},
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

// TestEndedLiveRule: an ended run's block is said by what it did while the run ran, past tense, with "Was blocked" only
// for a block the run put in force; whatever it did, its state now is ended with no claim, its text says it ended
// with the run, and it is in no group. A block said in state ended with nothing known claims nothing either.
func TestEndedLiveRule(t *testing.T) {
	cases := []struct {
		kind, value string
		was         livestatus.State
		want        string
	}{
		{"exec", "curl", livestatus.InForce, "Was blocked: cannot run curl"},
		{"exec", "/opt/tools/", livestatus.InForce, "Was blocked: cannot run programs in /opt/tools/"},
		{"net", "example.com:443", livestatus.InForce, "Was blocked: cannot connect to example.com on port 443"},
		{"path", "/p/data", livestatus.InForce, "Was blocked: cannot open or change /p/data"},
		{"path", "/p/data", livestatus.Partial, "Was blocked: cannot change /p/data (reads went through)"},
		{"read", "/p/data", livestatus.InForce, "Was blocked: cannot read /p/data"},
		{"write", "/p/out", livestatus.InForce, "Was blocked: cannot change /p/out (reads went through)"},
		{"exec", "curl", livestatus.RecordedOnly, "Was marked (recorded, not refused): cannot run curl"},
		{"write", "/p/out", livestatus.RecordedOnly, "Was marked (recorded, not refused): cannot change /p/out"},
		{"net", "example.com:443", livestatus.Waiting, "Never put in force: cannot connect to example.com on port 443"},
		{"exec", "curl", livestatus.Ended, "Ended with the run: cannot run curl"},
		{"exec", "curl", livestatus.Dormant, "Ended with the run: cannot run curl"},
	}
	for _, c := range cases {
		t.Run(string(c.was)+"/"+c.kind, func(t *testing.T) {
			r := EndedLiveRule(c.kind, c.value, "uid:1000 pid:1 dashboard", c.was)
			if r.Sentence != c.want {
				t.Errorf("sentence %q, want %q", r.Sentence, c.want)
			}
			if r.Live != livestatus.Ended || r.State != StateNotEnforced || r.Enforced || !strings.HasPrefix(r.EnforcedText, "Ended with the run") {
				t.Errorf("rule %+v, want ended with no claim", r)
			}
			refused := strings.HasPrefix(c.want, "Was blocked")
			if strings.Contains(r.EnforcedText, "tego refused") != refused {
				t.Errorf("text %q for a block that %s", r.EnforcedText, map[bool]string{true: "refused", false: "refused nothing"}[refused])
			}
			if r.RuleKey != "live.block["+c.kind+":"+c.value+"]" || r.Group != GroupLive || r.Source.Origin != "live block by uid:1000 pid:1 dashboard" {
				t.Errorf("rule key %q, group %q, origin %q", r.RuleKey, r.Group, r.Source.Origin)
			}
		})
	}
	v := newView()
	v.AddLiveStatus("exec", "curl", "uid:1000 pid:1 cli", livestatus.Ended, livestatus.SentenceEnded)
	if r := v.Group(GroupLive).Rules[0]; r.Sentence != "Ended with the run: cannot run curl" {
		t.Errorf("a block said only as ended reads %q, want no claim of what it did", r.Sentence)
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
