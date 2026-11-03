// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"time"

	"golang.org/x/sys/unix"
)

// PollReadable is poll(2) for POLLIN on fd until timeout has passed: how many descriptors are ready (0 or 1) and
// poll's error. A signal that ends the poll resumes it for what is left of the bound, so the wait still ends there.
// poll is never restarted after a signal handler, SA_RESTART or not (signal(7)), and a Go test process takes signals
// while a test waits, the runtime's own preemption signal (SIGURG) among them: the runtime can send it to a thread
// just as that thread's goroutine enters the poll, which then ends with EINTR at once.
func PollReadable(fd int, timeout time.Duration) (int, error) {
	pfd := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
	deadline := time.Now().Add(timeout)
	for {
		ms := 0
		if left := time.Until(deadline); left > 0 {
			ms = int((left + time.Millisecond - 1) / time.Millisecond)
		}
		n, err := unix.Poll(pfd, ms)
		if !errors.Is(err, unix.EINTR) {
			return n, err
		}
	}
}
