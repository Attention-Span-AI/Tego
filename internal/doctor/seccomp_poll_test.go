// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestSelfTestPollErrIsNoNotification: seccomp_notify_poll answers EPOLLERR alone when its interruptible lock loses
// to a signal pending on the polling thread (kernel/seccomp.c, since 5.0; the supervisor's rule in
// internal/runtime/supervisor/kernel.go). Read as "readable", the self-test went on to a blocking NOTIF_RECV and its
// timeout, which exists for a kernel that never delivers, no longer bounded `tego doctor`. A pipe's write end
// whose reader is closed polls POLLERR alone, the same shape.
func TestSelfTestPollErrIsNoNotification(t *testing.T) {
	pipe := func() [2]int {
		var p [2]int
		if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		return p
	}

	errEnd := pipe()
	_ = unix.Close(errEnd[0])
	t.Cleanup(func() { _ = unix.Close(errEnd[1]) })
	start := time.Now()
	err := waitReadable(errEnd[1], 50*time.Millisecond)
	if !errors.Is(err, ErrSeccompSelfTest) {
		t.Fatalf("POLLERR alone: %v, want the self-test's timeout: nothing was there to receive", err)
	}
	if took := time.Since(start); took < 50*time.Millisecond {
		t.Errorf("POLLERR alone ended the wait after %s, before its 50ms deadline", took)
	}

	hup := pipe()
	_ = unix.Close(hup[1])
	t.Cleanup(func() { _ = unix.Close(hup[0]) })
	if err := waitReadable(hup[0], time.Second); !errors.Is(err, ErrSeccompSelfTest) {
		t.Errorf("POLLHUP: %v, want the self-test's error: the filtered thread left without a notification", err)
	}

	ready := pipe()
	t.Cleanup(func() { _ = unix.Close(ready[0]); _ = unix.Close(ready[1]) })
	if _, err := unix.Write(ready[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if err := waitReadable(ready[0], time.Second); err != nil {
		t.Errorf("POLLIN: %v, want nil", err)
	}
}
