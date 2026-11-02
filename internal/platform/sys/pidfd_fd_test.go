// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
)

// TestPidfdSendSignalFD: a signal through an owner reaches the process it names, and a closed or nil owner signals
// nothing and is ErrClosed.
func TestPidfdSendSignalFD(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "30")
	if err := cmd.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	fd, err := PidfdOpenProcessFD(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	if err := PidfdSendSignalFD(fd, 0); err != nil {
		t.Fatalf("signal 0 through the owner: %v", err)
	}
	if err := fd.Close(); err != nil {
		t.Fatal(err)
	}
	if err := PidfdSendSignalFD(fd, syscall.SIGKILL); !errors.Is(err, ErrClosed) {
		t.Fatalf("a closed owner: %v, want ErrClosed", err)
	}
	if err := PidfdSendSignalFD(nil, syscall.SIGKILL); !errors.Is(err, ErrClosed) {
		t.Fatalf("a nil owner: %v, want ErrClosed", err)
	}
	if err := syscall.Kill(cmd.Process.Pid, 0); err != nil {
		t.Fatalf("the process is gone after signals through a closed owner: %v", err)
	}
}
