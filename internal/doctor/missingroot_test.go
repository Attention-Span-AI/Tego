// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestMissingRootNamesTheTier: without root, each root tier's "missing for" line names that tier. Tier bpflsm
// inherits tier cgroup's list, and its section read "root: tier cgroup needs ...".
func TestMissingRootNamesTheTier(t *testing.T) {
	st := state(func(st *probeState) { st.root = false })
	for _, tier := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
		got := strings.Join(st.missingFor(tier), "; ")
		if !strings.Contains(got, "root: tier "+string(tier)+" needs") {
			t.Errorf("missing for %s: %q, want its own root line", tier, got)
		}
		for _, other := range []backend.Tier{backend.TierCgroup, backend.TierBPFLSM} {
			if other != tier && strings.Contains(got, "tier "+string(other)+" needs") {
				t.Errorf("missing for %s names tier %s: %q", tier, other, got)
			}
		}
	}
}
