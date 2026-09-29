// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// parityPolicy is the listener's policy over rt with no mounts beneath any entry and every path on one mount.
func parityPolicy(rt *agent.RuleTable) *policy {
	return newPolicyWith(rt, "/run.scope", func(string) ([]string, error) { return nil, nil },
		func(string) (mountKey, error) { return mountKey{unique: true, id: 1}, nil })
}

// A watch entry nested under an unenforced deny_read grants nothing (SEMANTICS §7), so the listener refuses a
// read beneath it as Evaluate's tier-2 column does; it used to reopen the path, a fail-open.
func TestDecideOpenWatchDoesNotReopenDenyRead(t *testing.T) {
	rt := policyTable([]agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessSet(0xffff)},
		{Kind: agent.FSDenyRead, Path: "/work/secret", Raw: "/work/secret", Unenforced: true},
		{Kind: agent.FSWatch, Path: "/work/secret/logs", Raw: "/work/secret/logs"},
	}, nil)
	p := parityPolicy(rt)
	v := p.decideOpen("/work/secret/logs/x")
	ev := rt.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: "/work/secret/logs/x"}, backend.TierCgroup)
	if v.allow || v.rule != "fs.deny_read[/work/secret]" {
		t.Errorf("decideOpen under a watch nested in a deny_read = %+v, want refused under fs.deny_read[/work/secret]", v)
	}
	if v.allow != (ev.Verdict == agent.VerdictAllow) {
		t.Errorf("tier 2 fanotify allow=%v, compile --test %+v", v.allow, ev)
	}
}

// A write-open under a deny_read nested in a write entry: fanotify cannot see the access mode and refuses the
// open, so Evaluate's tier-2 column refuses the write too, read-denied. A write
// entry nested deeper than the deny_read reopens the path for both.
func TestEvaluateTier2WriteOpenFollowsTheListener(t *testing.T) {
	rt := policyTable([]agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessSet(0xffff)},
		{Kind: agent.FSDenyRead, Path: "/work/secret", Raw: "/work/secret", Unenforced: true},
		{Kind: agent.FSWrite, Path: "/work/secret/out", Raw: "/work/secret/out", Access: agent.AccessSet(0xffff)},
	}, nil)
	p := parityPolicy(rt)
	for _, c := range []struct {
		path  string
		allow bool
	}{
		{"/work/secret/f", false},
		{"/work/secret/out/f", true},
		{"/work/f", true},
	} {
		v := p.decideOpen(c.path)
		ev := rt.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: c.path}, backend.TierCgroup)
		if v.allow != c.allow || (ev.Verdict == agent.VerdictAllow) != c.allow {
			t.Errorf("%s: fanotify decideOpen = %+v, Evaluate(write, cgroup) = %+v, want allow=%v for both", c.path, v, ev, c.allow)
		}
		if !c.allow && (ev.Reason != "read-denied" || ev.Rule != "fs.deny_read[/work/secret]") {
			t.Errorf("%s: Evaluate(write, cgroup) = %+v, want read-denied under fs.deny_read[/work/secret]", c.path, ev)
		}
	}
}
