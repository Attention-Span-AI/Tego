// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// At tier 2 the fanotify listener refuses a write-open under a deny_read nested in a write entry, since it cannot see
// the open's access mode, unless a longer write entry reopens the path; the advisory verdict says so, as compile
// --test does (R15). At tier 1 Landlock's union allows it.
func TestAdvisoryWriteOpenFollowsTheTier2Listener(t *testing.T) {
	fs := []agent.FSRule{
		{Kind: agent.FSWrite, Path: "/work", Raw: "/work", Access: agent.AccessSet(0xffff)},
		{Kind: agent.FSDenyRead, Path: "/work/secret", Raw: "/work/secret", Unenforced: true},
		{Kind: agent.FSWrite, Path: "/work/secret/out", Raw: "/work/secret/out", Access: agent.AccessSet(0xffff)},
	}
	const wflags = unix.O_WRONLY | unix.O_CREAT
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup} {
		pol := testPolicy(nil, fs, nil)
		pol.Rules.Tier = tier
		c := compile(pol)
		for _, path := range []string{"/work/secret/f", "/work/secret/out/f", "/work/f"} {
			rule, v, reason := c.fsVerdict(path, record.FSOpen, wflags, false)
			ev := pol.Rules.Evaluate(agent.Action{Kind: agent.ActionFSWrite, Path: path}, tier)
			if string(v) != string(ev.Verdict) || rule != ev.Rule || string(reason) != string(ev.Reason) {
				t.Errorf("tier %s, write-open %s: advisory %s %s %s, compile --test %+v", tier, path, v, rule, reason, ev)
			}
		}
	}
}
