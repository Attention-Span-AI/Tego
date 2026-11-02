// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// ErrLiveUnavailable is the launcher's refusal to adopt a process under a table compiled from live.mode: adjustable
// (ADR 0125 decision 6). Compile takes every fence entry out of the kernel layers (the contract plus the fence is what
// Landlock, fanotify and the BPF rows hold), so the fence is refused only by Tego's live layer, which must refuse every
// entry before the agent's first instruction. An adopted process was started before Tego, so no adoption can.
var ErrLiveUnavailable = errors.New("live.mode: adjustable cannot run with this tego")

// ErrLiveStart is the launcher's refusal to start an Adjustable run where its live layer cannot refuse every fence
// entry from the run's first instruction (checkAdjustable, ADR 0125 decisions 6 and 7), or cannot make the run's key
// or fence (seedFence).
var ErrLiveStart = errors.New("live.mode: adjustable cannot start this run")

// refuseAdjustable refuses an Adjustable table for an adoption (adopted true); nil for every other table and for a
// run, whose launcher seeds the fence's refusals before the supervisor lets the agent run (startNotifyLoop,
// checkAdjustable), so a Locked run starts exactly as before.
func refuseAdjustable(rt *agent.RuleTable, adopted bool) error {
	if !rt.Adjustable() || !adopted {
		return nil
	}
	return fmt.Errorf("%w: an adopted run was started before Tego, so no live refusal can be in place from its "+
		"first instruction (ADR 0125 decision 6); adopt it under live.mode: locked", ErrLiveUnavailable)
}
