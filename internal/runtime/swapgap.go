// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"fmt"
	"strings"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// GapMemorySwapUncapped is the why of the what=limits gap a run with a memory cap records when its cgroup has
// no memory.swap.max while swap is on: the kernel accounts no swap to cgroups (swapaccount=0 or
// cgroup.memory=noswap), so the agent can exceed its memory cap into swap (runtime-launch.md R10, ADR 0038).
const GapMemorySwapUncapped = "memory-swap-uncapped"

// Diagnostic codes of the warnings a run prints through Deps.Warn, which the CLI prints in brackets after the text: a
// consumer keyed on the code tells them apart (every runtime warning was printed as swap-uncapped).
const (
	// WarnSwapUncapped: a memory cap the swap can exceed (runtime-launch.md R10).
	WarnSwapUncapped = "swap-uncapped"
	// WarnHeldUnavailable: gate.completion: held whose open deputy did not start, so the open cells are best effort for
	// the run (ADR 0041, the launch probe's degrade).
	WarnHeldUnavailable = "held-unavailable"
	// WarnHeldLabel: the disclosure that a held open is decided by the contract's rules, not by a tighter LSM profile
	// on the agent (ADR 0041 D2's label check, not built; heldLabelWarning).
	WarnHeldLabel = "held-label"
)

// swapCapper is a cgroup manager that can tell whether a memory cap on a cgroup also holds the swap
// (cgroup.FS.UncappedSwap); a manager that cannot is taken to cap it.
type swapCapper interface {
	UncappedSwap(c cgroup.Cgroup) []string
}

// checkSwapCap is createCgroup's check once the limits are written: a memory cap that the kernel cannot extend
// to swap is printed once as a warning, and emitLimitsGap records it after run_start.
func (r *runner) checkSwapCap(cg cgroup.Cgroup, l cgroup.Limits) {
	r.swapUncapped = nil
	if l.MemoryMax == 0 && !l.MemoryMaxSet {
		return
	}
	sc, ok := r.cgm.(swapCapper)
	if !ok {
		return
	}
	areas := sc.UncappedSwap(cg)
	if len(areas) == 0 {
		return
	}
	r.swapUncapped = areas
	r.log.Warn("runtime: memory cap does not hold swap", "swap", strings.Join(areas, ","))
	if r.deps.Warn != nil {
		r.deps.Warn(WarnSwapUncapped, fmt.Sprintf("the memory cap can be exceeded into swap (%s): this kernel accounts no swap to "+
			"cgroups, so the run's cgroup has no memory.swap.max; enable swap accounting (remove swapaccount=0 and "+
			"cgroup.memory=noswap from the kernel command line) or turn swap off", strings.Join(areas, ", ")))
	}
}

// emitLimitsGap records, right after run_start, the memory cap checkSwapCap found the swap can bypass:
// what=limits, why=memory-swap-uncapped.
func (r *runner) emitLimitsGap() {
	if len(r.swapUncapped) > 0 {
		r.emitGap(source.Gap{What: record.GapLimits, Why: GapMemorySwapUncapped})
	}
}
