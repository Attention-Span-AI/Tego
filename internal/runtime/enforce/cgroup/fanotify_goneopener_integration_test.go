// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"testing"

	"golang.org/x/sys/unix"
)

// TestResponseForAnOpenerThatIsGoneIsSwallowed is docs/p0/enforce-cgroup-observe.md §6 E10 against a real
// fanotify group: when a pids cap kills the cgroup while a decision is in flight, the kernel's teardown of the
// opener drops the pending permission event, and the listener's answer then names a descriptor the group no longer
// holds. The kernel refuses that write (ENOENT, or ESRCH from the process side), which is the opener already
// being gone, so writeResponse must report success rather than fail the listener. A real group is the only
// place the kernel's own answer can be had, hence CAP_SYS_ADMIN; requireFanotify skips without it.
func TestResponseForAnOpenerThatIsGoneIsSwallowed(t *testing.T) {
	l := requireFanotify(t)
	// No event was ever delivered to this group, so no descriptor number is one it is waiting on.
	for _, fd := range []int32{3, 1 << 20} {
		if err := l.writeResponse(fd, unix.FAN_ALLOW); err != nil {
			t.Errorf("writeResponse(%d) = %v; a response for an opener that is gone must be swallowed, not fatal", fd, err)
		}
		if err := l.writeResponse(fd, unix.FAN_DENY); err != nil {
			t.Errorf("writeResponse(%d, deny) = %v", fd, err)
		}
	}
}
