// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestAutoTiersAreThisUsersOnThisKernel is the demo's bug: a tegobpf build compiled and ran an auto contract
// as a normal user, on a kernel without bpf in the LSM list, at tier bpflsm, and refused its fs.ask_read for a
// tier the run could never get. The tiers tier: auto resolves among are those this build constructs and this
// process could be given here: tier cgroup and above only as root, tier bpflsm only with bpf in the LSM list.
// An untagged build answers landlock alone whoever runs it; under -tags tegobpf this reads the real process.
func TestAutoTiersAreThisUsersOnThisKernel(t *testing.T) {
	got := builtTiers()
	if !slices.Contains(got, backend.TierLandlock) {
		t.Fatalf("builtTiers() = %v, want tier landlock among them", got)
	}
	if !config.InitNSRoot() {
		for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			if slices.Contains(got, tier) {
				t.Errorf("builtTiers() = %v as a user who is not root: tier %s needs root, so no run of this user gets it", got, tier)
			}
		}
	}
	if st, err := doctor.ReadLSMState(); (err != nil || !st.BPFActive) && slices.Contains(got, backend.TierBPFLSM) {
		t.Errorf("builtTiers() = %v on a kernel whose LSM list %v has no bpf: tier bpflsm cannot run here", got, st.Modules)
	}
}
