// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"io"
	"testing"
	"time"
)

// TestPtraceTracemeHelperIsAlwaysReaped: the ptrace_traceme cell's helper (`__doctor-plane-probe ptrace-traceme`)
// answers and is reaped, every time. PTRACE_TRACEME traces the calling thread only. Called from a thread other than
// the thread-group leader, that thread's exit leaves a zombie only its tracer can reap, and only by its thread id with
// __WALL; until then the leader is never reported, so os/exec's Wait (waitid on the leader's pidfd) and the SIGKILL
// planeChild.wait sends after planeProbeTimeout both wait forever. The helper locked its goroutine to whatever thread
// it was on, which is the leader only while the Go scheduler has not moved the main goroutine since the process's
// inits: in the KVM root suites (default-lsm boot, 2026-10-16, host load ~20) doctor.Run waited in that Wait for 11
// minutes and `tego doctor --json` for 24. And a traced thread stops at the delivery of any signal, the Go runtime's
// SIGURG among them, which Wait then reports as "stop signal: urgent I/O condition" (17 of 120 tries, 12 copies of
// this test at once at GOMAXPROCS=1 beside busy loops), failing the cell and the plane mode. The helper's main now
// stays on the startup thread (an init locks it there for this argv only), it never traces from another thread, and it
// blocks every signal before PTRACE_TRACEME.
func TestPtraceTracemeHelperIsAlwaysReaped(t *testing.T) {
	const tries = 40
	for i := range tries {
		child, err := startPlaneChildAs(nil, planeTracemeRole, "", -1)
		if err != nil {
			t.Fatalf("try %d: %v", i, err)
		}
		if _, err := io.WriteString(child.stdin, "go\n"); err != nil {
			child.stop()
			t.Fatalf("try %d: %v", i, err)
		}
		line, err := child.readLine()
		if err != nil {
			child.stop()
			t.Fatalf("try %d: the helper did not answer: %v", i, err)
		}
		if line != planePassed && line != planeRefused {
			child.stop()
			t.Fatalf("try %d: the helper answered %q, want %q or %q", i, line, planePassed, planeRefused)
		}
		// planeChild.wait itself never returns for an unreapable helper, so the test keeps its own deadline.
		waited := make(chan error, 1)
		go func() { waited <- child.wait() }()
		select {
		case err := <-waited:
			if err != nil {
				t.Fatalf("try %d: %v", i, err)
			}
		case <-time.After(planeProbeTimeout + 10*time.Second):
			t.Fatalf("try %d: the helper (pid %d) answered %q and was never reaped, SIGKILL included", i,
				child.cmd.Process.Pid, line)
		}
	}
}
