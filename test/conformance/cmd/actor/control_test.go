// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// TestTracemeThreadBlocksSignals: the thread that asks for a TRACEME blocks every signal it can before it asks.
// Once traced, a signal delivered to that thread (the Go runtime's own preemption SIGURG among them) is a
// signal-delivery-stop its tracer, outside the run, never resumes, so the stage hung before it reported; the
// control/traceme-outside cell timed out so at tier landlock on AL2023's 6.1 (2026-10-19).
func TestTracemeThreadBlocksSignals(t *testing.T) {
	type result struct {
		blocked uint64
		err     error
	}
	seen := make(chan result, 1)
	ask := ptraceTraceme
	t.Cleanup(func() { ptraceTraceme = ask })
	// traceme's own path, up to the TRACEME: the seam reads the mask of the thread that would ask, and asks nothing.
	ptraceTraceme = func() syscall.Errno {
		b, err := os.ReadFile("/proc/thread-self/status")
		if err != nil {
			seen <- result{err: err}
			return 0
		}
		for _, line := range strings.Split(string(b), "\n") {
			if v, ok := strings.CutPrefix(line, "SigBlk:"); ok {
				n, err := strconv.ParseUint(strings.TrimSpace(v), 16, 64)
				seen <- result{blocked: n, err: err}
				return 0
			}
		}
		seen <- result{err: os.ErrNotExist}
		return 0
	}
	code := make(chan int, 1)
	// traceme locks its goroutine to the thread and never unlocks it, so the runtime ends the thread with the
	// goroutine and no other goroutine runs with its mask.
	go func() { code <- traceme() }()
	if c := <-code; c != 0 {
		t.Fatalf("traceme returned %d before it asked", c)
	}
	var r result
	select {
	case r = <-seen:
	default:
		t.Fatal("traceme never asked for the TRACEME")
	}
	if r.err != nil {
		t.Fatal(r.err)
	}
	// Every signal but SIGKILL (9) and SIGSTOP (19), which the kernel never lets a thread block.
	const want = ^uint64(0) &^ (1<<(9-1) | 1<<(19-1))
	if r.blocked != want {
		t.Errorf("the TRACEME thread blocks %#x, want %#x (every signal but SIGKILL and SIGSTOP)", r.blocked, want)
	}
}
