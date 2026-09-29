// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAdvisoryLabelsAreCompileTestsLabels is R15's one spelling of `rule`: the line names an action as compile
// --test names it, so the two sources match by label as well as by verdict (ADR 0017's fs/read-watch,
// write-open-watch, unlink-watch and read-deny-read-nested-in-write cells, whose lines said unmatched and
// dropped the unenforced marker). A read no deny_read decides, and a refused modification, are named by the
// nearest entry of any kind, a watch entry included; a read tier 1 allows under a deny_read it cannot enforce
// carries the " (unenforced: parent writable)" marker.
//
// Spec: docs/p0/supervisor.md R15.
func TestAdvisoryLabelsAreCompileTestsLabels(t *testing.T) {
	fs := []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/w/out", Raw: "./out/", Access: agent.AccessWriteSet},
		{Kind: agent.FSDenyRead, Path: "/w/out/keys", Raw: "./out/keys/", Unenforced: true},
		{Kind: agent.FSDenyRead, Path: "/w/secrets", Raw: "./secrets/"},
		{Kind: agent.FSWatch, Path: "/w/config", Raw: "./config/"},
		{Kind: agent.FSWatch, Path: "/w/out/logs", Raw: "./out/logs/"},
	}
	type row struct {
		op   string
		kind agent.ActionKind
		path string
		flag int
	}
	rows := []row{
		{record.FSOpen, agent.ActionFSRead, "/w/config/app.toml", 0},
		{record.FSOpen, agent.ActionFSWrite, "/w/config/app.toml", 0x241},
		{record.FSUnlink, agent.ActionFSDelete, "/w/config/app.toml", 0},
		{record.FSMkdir, agent.ActionFSMkdir, "/w/config/d", 0},
		{record.FSOpen, agent.ActionFSRead, "/w/out/logs/l", 0},
		{record.FSOpen, agent.ActionFSWrite, "/w/out/logs/l", 0x241},
		{record.FSOpen, agent.ActionFSRead, "/w/out/keys/k", 0},
		{record.FSOpen, agent.ActionFSRead, "/w/secrets/k", 0},
		{record.FSOpen, agent.ActionFSRead, "/w/notes", 0},
		{record.FSOpen, agent.ActionFSWrite, "/w/notes", 0x241},
		{record.FSOpen, agent.ActionFSWrite, "/w/out/a", 0x241},
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		pol := testPolicy(nil, fs, nil)
		pol.Rules.Tier = tier
		c := compile(pol)
		for _, r := range rows {
			rule, v, _ := c.fsVerdict(r.path, r.op, r.flag, r.op == record.FSMkdir)
			ev := pol.Rules.Evaluate(agent.Action{Kind: r.kind, Path: r.path}, tier)
			if string(v) != string(ev.Verdict) || rule != ev.Rule {
				t.Errorf("tier %s %s %s: line %s %q, compile --test %s %q", tier, r.op, r.path, v, rule, ev.Verdict, ev.Rule)
			}
		}
	}
}
