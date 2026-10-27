// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// inputActivity is the stall check's source for a person typing at the terminal the agent shares (G7). The
// kernel stamps a terminal's access time each time a read of it returns bytes, so a new atime on the terminal
// device means the agent consumed input since the last tick. The run reads nothing from the terminal and sees
// no key: it fstats a file descriptor it already holds.
//
// The stamp has the kernel's own granularity: it is written only when the 8-second window of its last write is
// over (tty_update_time), so input is seen up to 8 s after it was typed and several keys inside one window show
// as one; a stall_after under about 16 s can still end a session that is being typed in. The first reading is
// the baseline: the stamp left by whoever read the terminal before this run is not activity.
//
// The returned func gives the monotonic time (from now) at which a changed stamp was last observed, or 0 for
// none. It is called from the watcher's one goroutine.
func (t *sharedTerminal) inputActivity(now func() uint64) func() uint64 {
	var last unix.Timespec
	var based bool
	var latest uint64
	return func() uint64 {
		var st unix.Stat_t
		if err := sys.FileDo(t.in, func(fd int) error { return unix.Fstat(fd, &st) }); err != nil {
			return latest
		}
		switch {
		case !based:
			last, based = st.Atim, true
		case st.Atim != last:
			last, latest = st.Atim, now()
		}
		return latest
	}
}

// wireInputActivity has the watcher count the person's input on the terminal the agent shares as activity, for a run
// that bounds stall_after (G7). A run whose stdin is not a terminal has no such input, and wall stays a hard cap.
func (r *runner) wireInputActivity(t *sharedTerminal) {
	if t == nil || t.in == nil || r.budget == nil || r.rt == nil || !r.rt.Limits.Bounded(agent.BudgetStallAfter) {
		return
	}
	r.budget.AddActivity(t.inputActivity(r.deps.Clock.MonoNS))
}
