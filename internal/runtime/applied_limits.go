// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// readAppliedLimits reads back the limits cg holds after SetLimits wrote l, for run_start.applied_limits (GAPS C221):
// the requested limits are in the contract's copy, and what holds is the kernel's number (memory is rounded to a page).
// A file that cannot be read is left out and said in the log; nil when the run wrote no limit or none could be read.
// Each limit the run wrote is the lowest ceiling along the chain of cgroups above its scope (cgroup.ReadEffective, GAPS
// N85), since the kernel holds the run to that one. A chain with an ancestor that cannot be read, or one cut short by a
// private cgroup namespace's root, leaves the member out rather than state the scope's own number as the one that
// holds. The read is once, at the run's start: a ceiling an operator changes later is not followed.
func (r *runner) readAppliedLimits(cg cgroup.Cgroup, l cgroup.Limits) *record.AppliedLimits {
	root := ""
	if r.cgm != nil {
		root = r.cgm.Root()
	}
	a, err := cgroup.ReadEffective(cg, l, cgroup.EffectiveTop(cg.Path, root))
	if err != nil {
		r.log.Warn("runtime: the limits the run's scope holds could not all be read back, or an ancestor cgroup's ceiling could not be read; run_start leaves those out rather than state a limit that may not be the one that holds", "err", err)
	}
	out := appliedRecord(a)
	// A value the record cannot hold (a kernel that spells a file another way) is left out, never a run that fails to start.
	if out != nil {
		if err := (&record.RunStartPayload{RecordMinor: record.MinorEveryLaunch, AppliedLimits: out}).ValidateFields(); err != nil {
			r.log.Warn("runtime: the limits the run's scope holds are not recordable; run_start leaves them out", "err", err)
			return nil
		}
	}
	return out
}

// appliedRecord is a for run_start: each limit the scope holds, and none the kernel reads as "max" (no limit) or the
// record cannot state (a pids.max of 0).
func appliedRecord(a cgroup.Applied) *record.AppliedLimits {
	var out record.AppliedLimits
	out.CPUMax = a.CPUMax
	if a.CPUWeight >= 1 && a.CPUWeight <= 10000 {
		w := a.CPUWeight
		out.CPUWeight = &w
	}
	if a.WrotePidsMax && a.PidsMax >= 1 {
		n := int(a.PidsMax)
		out.PidsMax = &n
	}
	if a.WroteMemoryMax && a.MemoryMax >= 0 {
		n := a.MemoryMax
		out.MemoryMax = &n
	}
	if a.WroteMemoryHigh && a.MemoryHigh >= 0 {
		n := a.MemoryHigh
		out.MemoryHigh = &n
	}
	if out == (record.AppliedLimits{}) {
		return nil
	}
	return &out
}
