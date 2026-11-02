// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"os/exec"
	"syscall"
	"testing"
)

// TestStartWithPidfd: the pidfd clone3 stores through SysProcAttr.PidFD comes back owned and names the child, attr
// keeps no pointer once the start returns, a start that makes no pidfd is ErrNoPidfd, and a failed start is its own
// error with nothing owned.
func TestStartWithPidfd(t *testing.T) {
	if _, err := StartWithPidfd(nil, func() error { t.Fatal("start ran without an attr"); return nil }); err == nil {
		t.Fatal("a nil SysProcAttr was accepted")
	}

	cmd := exec.Command("/bin/true")
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	pidfd, err := StartWithPidfd(cmd.SysProcAttr, cmd.Start)
	if err != nil {
		t.Fatal(err)
	}
	if cmd.SysProcAttr.PidFD != nil {
		t.Error("SysProcAttr.PidFD still points at the start's number")
	}
	var ws syscall.WaitStatus
	if err := pidfd.Borrow(func(n int) error {
		var err error
		ws, _, err = WaitPidfd(n, false)
		return err
	}); err != nil {
		t.Fatalf("the owned pidfd does not reap the child: %v", err)
	}
	if !ws.Exited() || ws.ExitStatus() != 0 {
		t.Errorf("child wait status %v", ws)
	}
	_ = cmd.Process.Release()
	if err := pidfd.Close(); err != nil {
		t.Fatal(err)
	}

	attr := &syscall.SysProcAttr{}
	if f, err := StartWithPidfd(attr, func() error { return nil }); !errors.Is(err, ErrNoPidfd) || f != nil {
		t.Errorf("a start that stored no pidfd = %v, %v; want nil, ErrNoPidfd", f, err)
	}
	failed := errors.New("start failed")
	if f, err := StartWithPidfd(attr, func() error { return failed }); err != failed || f != nil {
		t.Errorf("a failed start = %v, %v; want nil and its own error", f, err)
	}
}
