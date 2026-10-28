// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// codeLiveUnavailable is an adoption of a live.mode: adjustable contract, refused (refuseAdjustableRun).
const codeLiveUnavailable = "live-unavailable"

// refuseAdjustableRun refuses an adoption compiled from live.mode: adjustable: Compile takes the fence out of the
// kernel layers, and an adopted process was started before Tego, so no live refusal can be in place from its first
// instruction (ADR 0125 decision 6). runtime.Adopt refuses it too (ErrLiveUnavailable); this says so before anything
// is set up. A run goes on: its launcher seeds every fence refusal before the agent's first instruction, and refuses
// to start where it cannot (runtime.ErrLiveStart). It returns 0 to go on.
func refuseAdjustableRun(rt *agent.RuleTable, label string, adopted bool, stderr io.Writer) int {
	if !rt.Adjustable() || !adopted {
		return 0
	}
	message(stderr, label, 0, 0, "tego adopt: live.mode: adjustable cannot adopt a running agent: no live refusal can "+
		"be in place from its first instruction (ADR 0125 decision 6). Adopt it under live.mode: locked", codeLiveUnavailable)
	return identity.ExitLauncher
}
