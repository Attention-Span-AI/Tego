// SPDX-License-Identifier: Apache-2.0

package decide

import (
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// AbsentRead is the rule a read of p is refused under because p is at or beneath the name the Landlock ruleset leaves
// ungranted for a built-in deny_read row that did not exist at compile (agent.RuleTable.AbsentDenyRead, ADR 0067 D3),
// and whether it is. Every enforcing tier installs that ruleset (tier landlock, and tiers cgroup and bpflsm compose
// it), so the kernel refuses the read there, and the tier models answer it refused, read_denied, named by the row: the
// ledger line, compile --test and the chain's attribution then say what the ruleset did (ADR 0016). An --observe run
// installs no ruleset, so it refuses nothing here. The callers ask
// it only where their own answer would be allow: compile leaves out a row any write or exec.allow directory entry
// covers, which is the only grant that could reach beneath the name, and the Landlock builder refuses to leave out
// any other name than the one asked about here (enforce-landlock E9). p is the path as the kernel names it.
func AbsentRead(rt *agent.RuleTable, tier backend.Tier, p string) (string, bool) {
	if rt == nil || len(rt.AbsentDenyRead) == 0 {
		return "", false
	}
	if tier != backend.TierLandlock && tier != backend.TierCgroup && tier != backend.TierBPFLSM {
		return "", false
	}
	a, ok := rt.AbsentRowOf(p)
	if !ok {
		return "", false
	}
	return a.RuleName(), true
}
