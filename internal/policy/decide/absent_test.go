// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// absentRT is a table whose home holds ~/.netrc (a rule) and none of ~/.codex (an absent row whose ungranted name is
// ~/.codex) nor ~/.pgpass (an absent row in the home directory itself).
func absentRT(tier backend.Tier) *agent.RuleTable {
	return &agent.RuleTable{
		Tier:     tier,
		Contract: &agent.Contract{},
		FS: []agent.FSRule{
			{Kind: agent.FSWrite, Path: "/h/work", Resolved: "/h/work", Access: agent.AccessWriteSet},
			{Kind: agent.FSDenyRead, Path: "/h/.netrc", Resolved: "/h/.netrc", BuiltIn: true},
		},
		AbsentDenyRead: []agent.AbsentRow{
			{Path: "/h/.codex/auth.json", Resolved: "/h/.codex/auth.json", At: "/h/.codex"},
			{Path: "/h/.pgpass", Resolved: "/h/.pgpass", At: "/h/.pgpass"},
		},
	}
}

// TestAbsentRowReadIsRefusedByEveryModel: a read at or beneath an absent
// built-in row's ungranted name is refused by the Landlock ruleset every enforcing tier installs, so Evaluate (compile
// --test, the held open's chain model), the indexed Evaluator, the supervisor's advisory verdict and the exec open of
// an undeclared binary there all answer refused, read_denied, named by the row; before, each said allow, unmatched,
// and the ledger recorded a read that never happened. An --observe run installs no ruleset and refuses nothing.
func TestAbsentRowReadIsRefusedByEveryModel(t *testing.T) {
	codexRule := "fs.deny_read[/h/.codex/auth.json]"
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		rt := absentRT(tier)
		tabs := NewAdvisoryTablesFor(rt)
		for _, c := range []struct{ path, rule string }{
			{"/h/.codex/auth.json", codexRule},
			{"/h/.codex/config.toml", codexRule}, // ~/.codex itself is left out, so all of it is refused
			{"/h/.pgpass", "fs.deny_read[/h/.pgpass]"},
		} {
			a := agent.Action{Kind: agent.ActionFSRead, Path: c.path}
			for name, got := range map[string]agent.EvalResult{
				"Evaluate":  Evaluate(rt, a, tier),
				"Evaluator": NewEvaluator(rt).Evaluate(a, tier),
			} {
				if got.Verdict != agent.VerdictRefused || got.Rule != c.rule || got.Reason != record.ReasonReadDenied {
					t.Errorf("%s %s read %s = %+v, want refused %s read_denied", tier, name, c.path, got, c.rule)
				}
			}
			rule, v, reason := AdvisoryFS(rt, tabs.Both, c.path, record.FSOpen, unix.O_RDONLY, false)
			if v != record.VerdictRefused || rule != c.rule || reason != record.ReasonReadDenied {
				t.Errorf("%s advisory read %s = %s %s %s, want refused %s read_denied", tier, c.path, v, rule, reason, c.rule)
			}
		}
		// What the ruleset grants stays allowed, and an existing row keeps its own rule.
		for _, p := range []string{"/h/notes", "/h/work/x", "/h/.codexrc"} {
			if got := Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: p}, tier); got.Verdict != agent.VerdictAllow {
				t.Errorf("%s read %s = %+v, want allow", tier, p, got)
			}
			if _, v, _ := AdvisoryFS(rt, tabs.Both, p, record.FSOpen, unix.O_RDONLY, false); v != record.VerdictAllow {
				t.Errorf("%s advisory read %s = %s, want allow", tier, p, v)
			}
		}
		if got := Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: "/h/.netrc"}, tier); got.Rule != "fs.deny_read[/h/.netrc]" {
			t.Errorf("%s read ~/.netrc = %+v, want its own rule", tier, got)
		}
		// exec unrestricted (no exec:): the open of an undeclared binary made beneath ~/.codex is refused too.
		if got := Evaluate(rt, agent.Action{Kind: agent.ActionExec, Path: "/h/.codex/bin/tool"}, tier); got.Verdict != agent.VerdictRefused || got.Rule != codexRule {
			t.Errorf("%s exec ~/.codex/bin/tool = %+v, want refused %s", tier, got, codexRule)
		}
	}
	rt := absentRT(backend.TierObserve)
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: "/h/.codex/auth.json"}, backend.TierObserve); got.Verdict != agent.VerdictAllow {
		t.Errorf("observe read ~/.codex/auth.json = %+v; an --observe run installs no ruleset", got)
	}
	if name, ok := AbsentRead(rt, backend.TierObserve, "/h/.codex/auth.json"); ok {
		t.Errorf("AbsentRead at observe = %s", name)
	}
}
