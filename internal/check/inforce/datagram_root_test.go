// SPDX-License-Identifier: Apache-2.0

package inforce

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestRootTierDatagramResidualIsListed (C156): under a net: section, the root tier without a decision plane (tier
// cgroup on its fanotify listener) leaves addressed unix datagrams to the kernel's own program only on Linux 6.7 and
// later (cgroup/sendmsg_unix), so below it the datagram's address is checked on tego's copy. The view must list that
// residual as best effort, as it lists the landlock tier's. A plane that decides the run (lsm, fmod_ret) closes it, tier
// bpflsm has a plane, and an observe run refuses nothing.
func TestRootTierDatagramResidualIsListed(t *testing.T) {
	f := newFixture(t)
	rt := f.compile(t, commandRules, nil)
	for _, c := range []struct {
		tier  backend.Tier
		plane string
		want  bool
	}{
		{backend.TierLandlock, "", true},
		{backend.TierCgroup, "", true},
		{backend.TierCgroup, record.DecisionPlaneLSM, false},
		{backend.TierCgroup, record.DecisionPlaneFmodRet, false},
		{backend.TierBPFLSM, record.DecisionPlaneLSM, false},
	} {
		v := Of(rt, c.tier, c.plane)
		var got *Rule
		for _, r := range v.Group(GroupNetwork).Rules {
			if r.Key == "built-in.datagrams" {
				got = &r
			}
		}
		if (got != nil) != c.want {
			t.Errorf("%s plane %q: datagram residual listed %v, want %v:\n%s", c.tier, c.plane, got != nil, c.want, v.Text())
			continue
		}
		if got != nil && (got.State != StateBestEffort || got.Enforced || !strings.Contains(got.EnforcedText, "Best effort")) {
			t.Errorf("%s plane %q: the residual is %+v, want a best-effort claim", c.tier, c.plane, *got)
		}
	}
	// Tier cgroup's words name the kernel boundary, not the landlock tier's race.
	v := Of(rt, backend.TierCgroup, "")
	for _, r := range v.Group(GroupNetwork).Rules {
		if r.Key == "built-in.datagrams" && !strings.Contains(r.EnforcedText, "6.7") {
			t.Errorf("tier cgroup's datagram residual says %q, want it to name Linux 6.7", r.EnforcedText)
		}
	}
}
