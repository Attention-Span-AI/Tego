// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"strings"
	"testing"

	watchadopt "github.com/attention-span-ai/tego/internal/watch/adopt"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestBusinessRulesRefuseRunBeforeAnySideEffect(t *testing.T) {
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM, backend.TierObserve} {
		t.Run(string(tier), func(t *testing.T) {
			rt := &agent.RuleTable{Tier: tier, Contract: &agent.Contract{Name: "business-test", MCP: []agent.MCPServer{{Name: "square", BusinessRules: &agent.BusinessRules{}}}}}
			// A valid dependency set must still refuse constructing a runner.
			// The fake backend does no probing; no Run/prepare happens if this
			// assertion fails under a guard-removal overlay.
			deps := Deps{Config: config.Builtin(), Enforce: tierBackend{tier: tier}}
			ordinary := *rt
			ordinaryContract := *rt.Contract
			ordinaryContract.MCP = nil
			ordinary.Contract = &ordinaryContract
			if control, err := newRunner(&ordinary, []string{"must-never-start"}, deps); control == nil || err != nil {
				t.Fatalf("test dependencies cannot construct an ordinary runner: %v", err)
			}
			prepared, err := newRunner(rt, []string{"must-never-start"}, deps)
			if prepared != nil || err == nil || !strings.Contains(err.Error(), agent.BusinessRulesUnavailable) {
				t.Fatalf("tier %s constructed runner: %v %v", tier, prepared, err)
			}
			result, err := Run(context.Background(), rt, []string{"must-never-start"}, deps)
			if err == nil || !strings.Contains(err.Error(), agent.BusinessRulesUnavailable) || result.ExitCode != identity.ExitLauncher || result.RunID != "" {
				t.Fatalf("tier %s: %+v %v", tier, result, err)
			}
		})
	}
}

func TestBusinessRulesRefuseAdoptionBeforePreparingScope(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierBPFLSM, Contract: &agent.Contract{Name: "business-test", MCP: []agent.MCPServer{{Name: "square", BusinessRules: &agent.BusinessRules{}}}}}
	deps := AdoptDeps{Config: config.Builtin(), Enforce: tierBackend{tier: backend.TierCgroup}}
	spec := AdoptSpec{Root: watchadopt.Process{Identity: watchadopt.Identity{PID: 2, Start: 1}, Cgroup: "/not-a-real-cgroup"}, Recheck: func(watchadopt.Process) error { return nil }}
	ordinary := *rt
	ordinaryContract := *rt.Contract
	ordinaryContract.MCP = nil
	ordinary.Contract = &ordinaryContract
	if control, err := newAdoption(&ordinary, spec, deps); control == nil || err != nil {
		t.Fatalf("test dependencies cannot construct an ordinary adoption: %v", err)
	}
	// Only construction is attempted under the negative overlay. No fake PID is
	// inspected or moved: a missing guard fails this assertion before Adopt.
	if prepared, err := newAdoption(rt, spec, deps); prepared != nil || err == nil || !strings.Contains(err.Error(), agent.BusinessRulesUnavailable) {
		t.Fatalf("business adoption constructed: admitted=%t err=%v", prepared != nil, err)
	}
	result, err := Adopt(context.Background(), rt, spec, deps)
	if err == nil || !strings.Contains(err.Error(), agent.BusinessRulesUnavailable) || result.ExitCode != identity.ExitLauncher || result.RunID != "" {
		t.Fatalf("adoption: %+v %v", result, err)
	}
}
