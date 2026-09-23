// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// readResources is how runResources reads a cgroup; cgroup.ReadResources outside this package's tests.
var readResources = cgroup.ReadResources

// runResources is run_end's resource line: the run cgroup's peaks and counters, read in step 13 before the
// cgroup is removed (runtime-launch.md §4.1). Step 12 normally leaves the tree empty by then, so every task
// the run had is counted and none still adds to them. It is not guaranteed: awaitEmpty returns with the tree
// still populated when its wait fails while ctx has not ended (cgroup.events or its inotify watch could not
// be read), which kills the tree and notes it in run_end.detail, and when the wait after the kill ends without seeing it empty (a task in
// uninterruptible sleep past killTimeout). The files are then read as they stand, and the tasks left can keep
// adding to them after the read; every value is a peak or a cumulative counter, so it is a lower bound then.
// It is nil for a run that never had a cgroup and for one whose files gave nothing, and a file the kernel
// lacks is an absent key rather than a zero (record.Resources). A file that could not be read is logged and
// leaves its keys absent; it never changes how the run ends.
func (r *runner) runResources() *record.Resources {
	if r.cg.Path == "" {
		return nil
	}
	got, err := readResources(r.cg)
	if err != nil {
		r.log.Warn("run: read the cgroup's resource files for run_end", "path", r.cg.Path, "err", err)
	}
	if got.Empty() {
		return nil
	}
	out := &record.Resources{
		MemoryPeak:       got.MemoryPeak,
		PidsPeak:         got.PidsPeak,
		CPUUsageUsec:     got.CPUUsageUsec,
		CPUUserUsec:      got.CPUUserUsec,
		CPUSystemUsec:    got.CPUSystemUsec,
		CPUNrThrottled:   got.CPUNrThrottled,
		CPUThrottledUsec: got.CPUThrottledUsec,
	}
	if got.MemoryHigh != nil || got.MemoryMax != nil || got.MemoryOOM != nil || got.MemoryOOMKill != nil {
		out.MemoryEvents = &record.MemoryEvents{High: got.MemoryHigh, Max: got.MemoryMax, OOM: got.MemoryOOM,
			OOMKill: got.MemoryOOMKill}
	}
	return out
}
