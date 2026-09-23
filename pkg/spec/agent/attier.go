// SPDX-License-Identifier: Apache-2.0

package agent

import "github.com/attention-span-ai/tego/pkg/spec/backend"

// AtTier returns the table a run at tier t enforces (R14). Compile resolves tier: auto to the machine's
// ceiling without probing the machine, and enforce.Select may then give the run a lower tier; every
// reader of the run's table has to see the tier that really runs. The tier-2 backend refuses a table
// that names any other tier (docs/p0/enforce-cgroup-observe.md §4, Prepare's precondition), and
// Evaluate answers in rt.Tier's semantics when no tier is passed, so a table left at its compiled
// tier would make an auto contract fail at Prepare or be judged in another tier's semantics.
//
// The result differs from rt in Tier alone, plus Capture where the new tier cannot carry the compiled
// mode: uprobe capture needs BPF, so a landlock run tops out at the forwarder, the same clamp Compile
// applies to a table it resolves to landlock. rt itself is returned when it already names t, and when
// t is not an enforcement tier (observe, auto, "" or unknown), which leaves an observe run's table
// exactly as compiled. rt is never modified (I4); like a TTL refresh, this builds a new table.
func (rt *RuleTable) AtTier(t backend.Tier) *RuleTable {
	if rt == nil || rt.Tier == t || !t.AtOrBelow(backend.TierBPFLSM) {
		return rt
	}
	out := *rt
	out.Tier = t
	if t == backend.TierLandlock && out.Capture == CaptureUprobe {
		out.Capture = CaptureForwarder
	}
	return &out
}
