// SPDX-License-Identifier: Apache-2.0

//go:build integration && linux

package conformance

import "testing"

func TestMountStartupRefusalAxes(t *testing.T) {
	for _, detached := range []bool{false, true} {
		for _, ax := range []axis{
			{tier: TierLandlock},
			{tier: TierCgroup},
			planeAxis(ModeFmodRet),
			planeAxis(ModeLSM),
			{tier: TierBPFLSM, decisionPlane: "lsm"},
		} {
			fx := &Fixture{Model: Model{ListenerRefuses: true, PlaneCannotHold: detached}}
			if detached {
				ax = ax.onListener()
			}
			got := mountStartupRefusal(fx, ax)
			want := ax.tier == TierCgroup && ax.decisionPlane == "" || detached && ax.tier == TierBPFLSM
			if (len(got) != 0) != want {
				t.Errorf("detached=%v tier=%s plane=%q: refusal %v, want %v", detached, ax.tier, ax.decisionPlane, got, want)
			}
		}
	}
}
