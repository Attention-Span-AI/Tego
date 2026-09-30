// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLandlockArmBoundsNoDepth: Landlock unions the rules on the whole path.
// The cgroup fallback's supervisor and the bpflsm plane apply the bounded root
// mutation decision before that inherited union (ADR 0028 S3).
func TestLandlockArmBoundsNoDepth(t *testing.T) {
	rt := &agent.RuleTable{FS: []agent.FSRule{
		{Kind: agent.FSDenyRead, Path: "/d", Raw: "/d", Resolved: "/d"},
		{Kind: agent.FSWrite, Path: "/w", Raw: "/w", Resolved: "/w", Access: agent.AccessWriteSet},
	}}
	deep := strings.Repeat("/x", agent.MaxWalk+6) + "/f"
	for _, c := range []struct {
		tier    backend.Tier
		kind    agent.ActionKind
		path    string
		verdict agent.Verdict
		rule    string
		reason  record.Reason
	}{
		{backend.TierLandlock, agent.ActionFSRead, "/d" + deep, agent.VerdictRefused, "fs.deny_read[/d]", record.ReasonReadDenied},
		{backend.TierLandlock, agent.ActionFSWrite, "/w" + deep, agent.VerdictAllow, "fs.write[/w]", ""},
		{backend.TierLandlock, agent.ActionFSMkdir, "/w" + deep, agent.VerdictAllow, "fs.write[/w]", ""},
		{backend.TierLandlock, agent.ActionFSDelete, "/w" + deep, agent.VerdictAllow, "fs.write[/w]", ""},
		{backend.TierCgroup, agent.ActionFSWrite, "/w" + deep, agent.VerdictRefused, agent.UnmatchedRule, record.ReasonPathUnresolved},
		{backend.TierCgroup, agent.ActionFSDelete, "/w" + deep, agent.VerdictRefused, agent.UnmatchedRule, record.ReasonPathUnresolved},
	} {
		got := Evaluate(rt, agent.Action{Kind: c.kind, Path: c.path}, c.tier)
		if got.Verdict != c.verdict || got.Rule != c.rule || got.Reason != c.reason {
			t.Errorf("tier %v %s %s…: %v %s %s, want %v %s %s", c.tier, c.kind, c.path[:4], got.Verdict, got.Rule, got.Reason, c.verdict, c.rule, c.reason)
		}
	}
	src, dst := "/w"+deep, "/w"+deep+"2"
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionFSRename, Path: src, DestPath: dst}, backend.TierLandlock); got.Verdict != agent.VerdictAllow || got.Rule != "fs.write[/w]" {
		t.Errorf("tier landlock deep rename: %v %s, want allow fs.write[/w]", got.Verdict, got.Rule)
	}
	if got := Evaluate(rt, agent.Action{Kind: agent.ActionFSRead, Path: "/d" + deep}, backend.TierBPFLSM); got.Verdict != agent.VerdictRefused || got.Rule == "fs.deny_read[/d]" {
		t.Errorf("tier bpflsm deep read: %v %s, want the bounded walk's refusal", got.Verdict, got.Rule)
	}
}
