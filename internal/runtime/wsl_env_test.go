// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The socket refusal is authority; omitting the launch hint is additional
// protection. Neither env.pass nor env.set may put it back in an enforcing run.
func TestAgentOmitsWSLInteropInEveryEnforcingTier(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, backend.TierObserve} {
		for _, set := range []bool{false, true} {
			rt := &agent.RuleTable{Contract: &agent.Contract{}, Env: []string{"HOME", "PATH", "WSL_INTEROP"}}
			if set {
				rt.Set = map[string]string{"WSL_INTEROP": "/run/WSL/contract_interop"}
			}
			r := &runner{rt: rt, deps: Deps{Enforce: tierBackend{tier: tier},
				Environ: []string{"HOME=/nonexistent", "PATH=/bin", "WSL_INTEROP=/run/WSL/parent_interop"}}}
			found := false
			for _, kv := range r.agentEnv() {
				if strings.HasPrefix(kv, "WSL_INTEROP=") {
					found = true
				}
			}
			if found != (tier == backend.TierObserve) {
				t.Errorf("tier %s, env.set %t: WSL_INTEROP present %t", tier, set, found)
			}
		}
	}
}
