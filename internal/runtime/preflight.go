// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/harness"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Preflight checks launch prerequisites that need no backend or kernel probe.
// The caller must still call Run, which repeats these checks and checks the
// selected backend before acquiring resources. Refusal order is structural
// inputs, the root-only approval floor, caller identity, recorded extras, compiled policy, network, asks, then
// agent identity and explicit socket requests. Machine capability refusals
// follow this entire group.
func Preflight(rt *agent.RuleTable, cmd []string, deps Deps) error {
	switch {
	case rt == nil:
		return fmt.Errorf("%w: no rule table", ErrDeps)
	case rt.BusinessRulesConfigured():
		return errors.New(agent.BusinessRulesUnavailable)
	case len(cmd) == 0 || cmd[0] == "":
		return fmt.Errorf("%w: no command", ErrDeps)
	case deps.Config == nil:
		return fmt.Errorf("%w: no machine config", ErrDeps)
	case rt.Contract == nil:
		return fmt.Errorf("%w: the rule table carries no contract", ErrDeps)
	}
	// The root-only approval floor's launcher, recording and setuid conditions decide from the configuration alone:
	// refused here, they cost no kernel probe (ADR 0154).
	if err := preflightLocalRoles(rt, deps); err != nil {
		return err
	}
	// The baseline facts that do not depend on the selected backend. The runner keeps the rest in the line's
	// order: applied-against-recording-only (it needs the tier), the launch command, then the record boundary
	// (which the CLI also checks before probing, CheckBaselineLaunchRecord).
	if err := validateBaselineTable(rt, deps.Config); err != nil {
		return err
	}
	if err := validIdentity(deps); err != nil {
		return err
	}
	if err := deps.RunStartExtras.check(); err != nil {
		return err
	}
	if rt.Contract.Net != nil && len(rt.Contract.Net.HTTP) != 0 && (rt.HTTP == nil || !canForward(rt)) {
		return fmt.Errorf("%w: net.http requires compiled forwarder policy and an enforcing tier", ErrDeps)
	}
	if rt.Contract.Net != nil && rt.Contract.Net.Proxy != nil && (rt.Proxy == nil || !canForward(rt)) {
		return fmt.Errorf("%w: net.proxy requires compiled forwarder policy and an enforcing tier", ErrDeps)
	}
	if err := rt.Proxy.ValidateLimits(rt.Limits); err != nil {
		return fmt.Errorf("%w: %w", ErrDeps, err)
	}
	if err := validateNetworkPolicy(rt, deps); err != nil {
		return err
	}
	if err := validateAskPolicy(rt); err != nil {
		return err
	}
	if _, err := identity.ParseAgentID(rt.Contract.Name); err != nil {
		return fmt.Errorf("%w: %w", ErrDeps, err)
	}
	// An explicit harness is invariant under provisioning. Auto can follow an
	// adapter's replacement argv, so its request stays at the runtime backstop.
	if name := declaredHarness(rt); name != harness.Auto {
		if dir, set := rt.Set["XDG_RUNTIME_DIR"]; set {
			if err := checkClaudeSocketRequest(dir, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// AtTier converts uprobe capture to the forwarder when landlock is selected.
// Before selection, rejecting that possibility would refuse a valid fallback.
func canForward(rt *agent.RuleTable) bool {
	return rt.Capture == agent.CaptureForwarder || rt.Capture == agent.CaptureUprobe
}
