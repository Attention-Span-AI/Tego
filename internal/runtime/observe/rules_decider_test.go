// SPDX-License-Identifier: Apache-2.0

package observe

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// A read beneath a deny_read, under a nearer implicit or watch entry, is refused by the tier: Landlock grants
// nothing on those (access 0) and fanotify's readable set holds write entries only. The recorder infers the
// refusal Evaluate answers, instead of letting the nearer entry decide.
func TestInferFSReadUnderDenyReadIgnoresNearerNonGrant(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Kind: agent.FSDenyRead, Path: "/h/.tego", BuiltIn: true},
		{Kind: agent.FSImplicit, Path: "/h/.tego/ledger"},
		{Kind: agent.FSDenyRead, Path: "/secret", Raw: "/secret"},
		{Kind: agent.FSWatch, Path: "/secret/logs", Raw: "/secret/logs"},
	}}
	ri := newRuleIndexAt(rt, "/nonexistent")
	for _, c := range []struct{ path, rule string }{
		{"/h/.tego/ledger/run1/events.jsonl", "fs.implicit[/h/.tego/ledger]"},
		{"/secret/logs/x", "fs.watch[/secret/logs]"},
	} {
		m := ri.matchFS(c.path)
		v, reason := ri.inferFS(record.FSOpen, false, m)
		ev := rt.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: c.path}, backend.TierCgroup)
		if v != record.VerdictRefused || reason != record.ReasonReadDenied {
			t.Errorf("%s: recorder infers %s/%s for a read the tier refuses (Evaluate %+v)", c.path, v, reason, ev)
		}
		if m.Rule != c.rule {
			t.Errorf("%s: named %s, want the nearest entry %s", c.path, m.Rule, c.rule)
		}
	}
}

// write: [/work], watch: [/work/logs]: Landlock (and Evaluate at every tier) allows a modification under
// /work/logs, since a watch entry withholds nothing (SEMANTICS §7); the recorder used to infer refused.
func TestInferFSWriteUnderNestedWatchIsAllowed(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, FS: []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessWriteFile | agent.AccessMakeReg | agent.AccessRemoveFile | agent.AccessRefer | agent.AccessMakeDir},
		{Kind: agent.FSWatch, Path: "/work/logs", Raw: "/work/logs"},
	}}
	ri := newRuleIndexAt(rt, "/nonexistent")
	m := ri.matchFS("/work/logs/a.log")
	if m.Rule != "fs.watch[/work/logs]" {
		t.Errorf("named %s, want the nearest entry fs.watch[/work/logs]", m.Rule)
	}
	ev := rt.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: "/work/logs/a.log"}, backend.TierCgroup)
	for _, op := range []string{record.FSOpen, record.FSUnlink, record.FSRename, record.FSMkdir} {
		if v, reason := ri.inferFS(op, true, m); v != record.VerdictAllow {
			t.Errorf("%s under a watch nested in a write entry: recorder infers %s/%s, Evaluate %+v", op, v, reason, ev)
		}
	}
}
