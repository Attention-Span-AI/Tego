// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"runtime"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pollBound is the wait the tests below hold PollReadable to.
const pollBound = 300 * time.Millisecond

// TestPollReadableOutlastsSignals: a signal on the waiting thread ends its poll with EINTR, and the wait goes on for
// what is left of its bound, so a descriptor with nothing to read answers 0 once the bound has passed, not an error.
// The waiting thread is sent the runtime's own preemption signal every millisecond meanwhile. A single poll fails
// here with "interrupted system call", as TestFanotifyProbeMarksTheObjectItOpens did in the race job.
func TestPollReadableOutlastsSignals(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	pid, tid := unix.Getpid(), unix.Gettid()
	stop, stopped := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(stopped)
		tick := time.NewTicker(time.Millisecond)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				_ = unix.Tgkill(pid, tid, unix.SIGURG)
			}
		}
	}()
	defer func() { close(stop); <-stopped }()
	start := time.Now()
	n, err := PollReadable(p[0], pollBound)
	if err != nil || n != 0 {
		t.Fatalf("an empty pipe polled n=%d err=%v, want 0 and no error", n, err)
	}
	if took := time.Since(start); took < pollBound {
		t.Fatalf("the wait ended after %v, before its bound of %v", took, pollBound)
	}
}

// TestPollReadableAnswersAReadyDescriptor: a descriptor with something to read answers 1.
func TestPollReadableAnswersAReadyDescriptor(t *testing.T) {
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = unix.Close(p[0]); _ = unix.Close(p[1]) }()
	if _, err := unix.Write(p[1], []byte{1}); err != nil {
		t.Fatal(err)
	}
	if n, err := PollReadable(p[0], pollBound); err != nil || n != 1 {
		t.Fatalf("a pipe holding a byte polled n=%d err=%v, want 1 and no error", n, err)
	}
}
