// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// At tier 1 an exec.allow directory inside an enforced deny_read keeps its own fd with
// READ_FILE (enforce-landlock R5, I11 (1)), so a read beneath it happens. The advisory verdict recorded it
// refused. Tier 2's listener does refuse it, and a read beside the exec directory stays refused at tier 1.
func TestAdvisoryReadUnderExecDirInsideDenyRead(t *testing.T) {
	fs := []agent.FSRule{{Kind: agent.FSDenyRead, Path: "/s", Raw: "/s"}}
	cases := []struct {
		tier backend.Tier
		path string
		want record.Verdict
	}{
		{backend.TierLandlock, "/s/bin/data.txt", record.VerdictAllow},
		{backend.TierLandlock, "/s/other.txt", record.VerdictRefused},
		{backend.TierCgroup, "/s/bin/data.txt", record.VerdictRefused},
	}
	for _, tc := range cases {
		pol := testPolicy(nil, fs, nil)
		pol.Rules.Tier = tc.tier
		pol.Rules.Contract = &agent.Contract{Exec: &agent.ExecSection{}}
		pol.Rules.Exec = []agent.ExecRule{{Raw: "/s/bin/", Path: "/s/bin", IsDir: true, Verdict: agent.VerdictAllow}}
		c := compile(pol)
		rule, v, _ := c.fsVerdict(tc.path, record.FSOpen, 0, false)
		if v != tc.want {
			t.Errorf("tier %s read %s: advisory %s %s, want %s", tc.tier, tc.path, v, rule, tc.want)
		}
		ev := pol.Rules.Evaluate(agent.Action{Kind: agent.ActionFSRead, Path: tc.path}, tc.tier)
		if string(ev.Verdict) != string(v) {
			t.Errorf("tier %s read %s: advisory %s, compile --test %+v", tc.tier, tc.path, v, ev)
		}
	}
}

// Landlock asks REMOVE_FILE/REFER on the parent directory, so unlinking or renaming a
// file that is itself a write entry (write: [/work/out.txt]) is refused, and Evaluate says so.
// The supervisor's advisory verdict matches the path itself and records allow.
func TestAdvisoryUnlinkOfWriteEntryItself(t *testing.T) {
	fs := []agent.FSRule{{Kind: agent.FSWrite, Path: "/work/out.txt", Raw: "/work/out.txt", Access: agent.AccessWriteSet}}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		pol := testPolicy(nil, fs, nil)
		pol.Rules.Tier = tier
		c := compile(pol)
		for op, kind := range map[string]agent.ActionKind{record.FSUnlink: agent.ActionFSDelete, record.FSRename: agent.ActionFSRename} {
			rule, v, _ := c.fsVerdict("/work/out.txt", op, 0, op == record.FSMkdir)
			a := agent.Action{Kind: kind, Path: "/work/out.txt", DestPath: "/work/out.txt"}
			ev := pol.Rules.Evaluate(a, tier)
			if string(v) != string(ev.Verdict) {
				t.Errorf("tier %s %s /work/out.txt: advisory %s %s, compile --test %+v", tier, op, v, rule, ev)
			}
		}
	}
}
