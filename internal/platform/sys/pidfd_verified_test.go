// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestPidfdSignalVerified: the signal reaches the process only when verify, run after the pidfd is open, accepts it;
// verify's refusal is the answer and nothing is sent (ADR 0048 (8)'s pidfd backstop for a kill the plane could not
// send).
func TestPidfdSignalVerified(t *testing.T) {
	cmd := exec.Command("sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep to signal: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	refused := errors.New("another process")
	if err := PidfdSignalVerified(cmd.Process.Pid, syscall.SIGKILL, func() error { return refused }); !errors.Is(err, refused) {
		t.Fatalf("a refused verify answered %v", err)
	}
	select {
	case err := <-done:
		t.Fatalf("a refused verify still signalled: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	if err := PidfdSignalVerified(cmd.Process.Pid, syscall.SIGKILL, func() error { return nil }); err != nil {
		t.Fatalf("a verified kill: %v", err)
	}
	select {
	case <-done:
		if ws, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); !ok || ws.Signal() != syscall.SIGKILL {
			t.Fatalf("the process ended %v, not by SIGKILL", cmd.ProcessState)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the verified kill did not land")
	}
}
