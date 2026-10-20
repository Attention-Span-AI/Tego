// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TestListenerPollErrIsNoHangup: what Wait makes of the listener's poll bits, on real descriptors standing in for
// it. POLLERR alone is seccomp_notify_poll's mutex_lock_interruptible on notify_lock failing for a signal pending on
// the polling thread (kernel/seccomp.c, since 5.0): nothing about the listener, so it is a wait that took nothing and
// the worker polls again. Read as the listener's hangup, every worker it reached returned as if the run were over,
// the loop closed the listener under a live agent, and every notified syscall of the agent failed ENOSYS with no line
// and no error (TestIntegrationApprovedOpensSurviveASignalStorm, 6 of 60 runs with the KVM guest throttled, 2 of 12
// at moderate host load, 2026-10-16). POLLHUP is the hangup: no task carries the filter any more. A pipe's write end
// whose reader is gone polls POLLERR alone, and a pipe's empty read end whose writer is gone POLLHUP alone.
func TestListenerPollErrIsNoHangup(t *testing.T) {
	// pipe's ends are closed once each: the one a case closes is not closed again at cleanup, where its number
	// may name another test's descriptor by then.
	pipe := func() (r, w *int) {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() {
			for _, fd := range p {
				if fd >= 0 {
					_ = unix.Close(fd)
				}
			}
		})
		return &p[0], &p[1]
	}
	closeEnd := func(fd *int) { _ = unix.Close(*fd); *fd = -1 }
	wake, _ := pipe()
	wakeR := *wake

	errR, errW := pipe()
	closeEnd(errR)
	if got, err := (sysKernel{ln: sys.InertForTest(*errW)}).Wait(wakeR, 0); err != nil || got != waitTimeout {
		t.Errorf("POLLERR alone: %v (%v), want waitTimeout: a signal interrupted the poll's lock, the listener is fine", got, err)
	}

	hupR, hupW := pipe()
	closeEnd(hupW)
	if got, err := (sysKernel{ln: sys.InertForTest(*hupR)}).Wait(wakeR, 0); err != nil || got != waitHup {
		t.Errorf("POLLHUP: %v (%v), want waitHup", got, err)
	}
}
