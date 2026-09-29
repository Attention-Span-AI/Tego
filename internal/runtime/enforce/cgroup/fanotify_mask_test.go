// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestFanotifyGroupHasOnlyPermissionEventsAndAnUnlimitedQueue is the part of docs/p0/enforce-cgroup-observe.md
// §6 E37 that holds without a kernel under memory pressure (the doc says the rest is unreachable and untested).
// The FAN_Q_OVERFLOW branch in handle is dead code only while two things hold: the group asks for no
// notification-class event, whose queue could overflow, and the group's queue is unlimited, so the kernel
// allocates permission events with __GFP_NOFAIL. Either changing makes the branch live and the documented
// analysis wrong, so both are pinned here.
func TestFanotifyGroupHasOnlyPermissionEventsAndAnUnlimitedQueue(t *testing.T) {
	t.Parallel()
	const permission = unix.FAN_OPEN_PERM | unix.FAN_OPEN_EXEC_PERM | unix.FAN_ACCESS_PERM
	if fanPermMask&^permission != 0 || fanPermMask == 0 {
		t.Errorf("fanPermMask = %#x holds a bit that is not a permission event; the FAN_Q_OVERFLOW branch in handle is then live (E37, I11)", uint64(fanPermMask))
	}
	src, err := os.ReadFile("fanotify.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), "unix.FAN_CLASS_CONTENT|unix.FAN_UNLIMITED_QUEUE") {
		t.Errorf("the group is not created with FAN_UNLIMITED_QUEUE; the kernel would drop permission events on overflow with no gap (E37)")
	}
}
