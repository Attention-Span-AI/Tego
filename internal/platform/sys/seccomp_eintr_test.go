// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TestNotifSendAndIDValidRetryEINTR: seccomp_notify_send and seccomp_notify_id_valid return -EINTR when a
// signal is pending while they wait for notify_lock, and the kernel does not restart them. Returned as it
// was, the supervisor read it as a dead target and left the notification unanswered, its task trapped until
// the listener closed. Both wrappers make the call again, as SeccompNotifRecv does; any other errno is
// returned after one call.
func TestNotifSendAndIDValidRetryEINTR(t *testing.T) {
	real := notifIoctlFake
	t.Cleanup(func() { notifIoctlFake = real })
	script := func(answers ...unix.Errno) *[]uint {
		var calls []uint
		notifIoctlFake = func(req uint, _ unsafe.Pointer) unix.Errno {
			e := answers[len(calls)]
			calls = append(calls, req)
			return e
		}
		return &calls
	}

	calls := script(unix.EINTR, unix.EINTR, 0)
	if err := SeccompNotifSend(3, &SeccompNotifResp{ID: 7}); err != nil || len(*calls) != 3 {
		t.Errorf("Send after EINTR twice: err %v, calls %d; want nil after 3", err, len(*calls))
	}
	calls = script(unix.EINTR, 0)
	if ok, err := SeccompNotifIDValid(3, 7); !ok || err != nil || len(*calls) != 2 {
		t.Errorf("IDValid after EINTR: %v, %v, calls %d; want true, nil after 2", ok, err, len(*calls))
	}
	calls = script(unix.EINTR, unix.ENOENT)
	if ok, err := SeccompNotifIDValid(3, 7); ok || err != nil || len(*calls) != 2 {
		t.Errorf("IDValid EINTR then ENOENT: %v, %v, calls %d; want false, nil", ok, err, len(*calls))
	}
	calls = script(unix.ENOENT)
	if err := SeccompNotifSend(3, &SeccompNotifResp{ID: 7}); !errors.Is(err, unix.ENOENT) || len(*calls) != 1 {
		t.Errorf("Send ENOENT: err %v, calls %d; want ENOENT after 1", err, len(*calls))
	}
}
