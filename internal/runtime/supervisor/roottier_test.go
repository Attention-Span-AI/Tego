// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestListenerExecAtTierBPFLSM: an exec of an image under a deny_read that an exec.allow directory inside it grants
// is refused by the kernel's open of the image at tier cgroup (the listener or the plane) and at tier bpflsm (the
// plane over the same backend), so the exec's one line says refused under the deny_read at both. At tier bpflsm it
// said allow while the kernel refused (TIER3-PLAN T11, conformance exec/exec-entry-directory-inside-deny-read). At
// tier landlock nothing refuses that open and the grant stands.
func TestListenerExecAtTierBPFLSM(t *testing.T) {
	const secrets, bin = "/p/secrets", "/p/secrets/bin/tool"
	for _, tc := range []struct {
		tier backend.Tier
		want record.Verdict
	}{
		{backend.TierLandlock, record.VerdictAllow},
		{backend.TierCgroup, record.VerdictRefused},
		{backend.TierBPFLSM, record.VerdictRefused},
	} {
		pol := testPolicy(nil, []agent.FSRule{{Path: secrets, Resolved: secrets, Kind: agent.FSDenyRead}}, nil)
		pol.Rules.Tier = tc.tier
		c := &compiled{pol: pol}
		d := execDecision{rule: "exec[/p/secrets/bin/]", verdict: record.VerdictAllow}
		got, _ := c.listenerExec(d, execImage{linked: true, link: bin, here: true})
		if got.verdict != tc.want {
			t.Errorf("tier %s: %s via %q, want %s", tc.tier, got.verdict, got.rule, tc.want)
		}
		if tc.want == record.VerdictRefused && got.reason != record.ReasonReadDenied {
			t.Errorf("tier %s: reason %s, want read-denied", tc.tier, got.reason)
		}
	}
}
