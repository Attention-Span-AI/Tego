// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// A write entry and an enforced deny_read at one path tie in the nearest-wins walk. FSDecider, which the
// tier-2 recorder infers a verdict by (internal/runtime/observe), lets the write entry's read set through by
// Landlock's union (nestedReadGrant), so Evaluate's root-tier walk must answer the same, whichever of the two
// the table lists first.
func TestEvaluateSamePathTieFollowsFSDecider(t *testing.T) {
	deny := FSRule{Kind: FSDenyRead, Path: "/work/s", Raw: "/work/s", Resolved: "/data/s"}
	write := FSRule{Kind: FSWrite, Path: "/work/s", Raw: "/work/s", Access: AccessSet(0xffff)}
	for _, order := range [][]FSRule{{deny, write}, {write, deny}} {
		rt := &RuleTable{FS: order, Tier: backend.TierBPFLSM}
		const path = "/work/s/f"
		dec, ok := rt.FSDecider(path, true)
		if !ok {
			t.Fatalf("FSDecider(%s) found no entry", path)
		}
		want := VerdictAllow
		if dec.Kind == FSDenyRead {
			want = VerdictRefused
		}
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			got := rt.Evaluate(Action{Kind: ActionFSRead, Path: path}, tier)
			if got.Verdict != want {
				t.Errorf("order %s first, tier %s: Evaluate(read) = %+v, FSDecider chose %s (want %s)",
					order[0].Kind, tier, got, dec.RuleName(), want)
			}
		}
	}
}
