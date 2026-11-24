// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Record metadata is unverified input. Check lengths before validation so a
// malformed ledger cannot amplify a catalog through its display identifiers.
func recordedName(name string) string {
	if len(name) <= 40 {
		if _, err := identity.ParseAgentID(name); err == nil {
			return name
		}
	}
	return "unknown"
}

func lastRun(id string, at time.Time, tier, hash string) *LastRun {
	if len(id) != 31 || !identity.RunID(id).Valid() {
		id = "unknown"
	}
	switch backend.Tier(tier) {
	case backend.TierObserve, backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM:
	case backend.TierAuto:
		// Auto selects a backend; it cannot identify a recorded backend.
		tier = "unknown"
	default:
		tier = "unknown"
	}
	if !validHash(hash) {
		hash = ""
	}
	same := "unknown"
	if backend.Tier(tier) == backend.TierObserve {
		same = "not-enforced"
	}
	return &LastRun{ID: id, At: at, Tier: tier, ContractHash: hash, SameContract: same}
}
