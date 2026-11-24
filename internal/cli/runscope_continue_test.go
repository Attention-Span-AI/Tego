// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"golang.org/x/sys/unix"
)

// Hold a real Wait4 stop result until after fg, making the delayed delivery deterministic.
// The child remains unreaped throughout Follow, as it does in executeUserScope.
func scopeContinuedStopParent() int {
	job := tegoruntime.NewJobControl(tegoruntime.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
	defer job.Close()
	dir := os.Getenv("SCOPE_EXPECT_CWD")
	cmd := exec.Command("/bin/sh", "-c", `kill -TSTP $$
printf resumed > "$1/resumed"
exec sleep 30`, "sh", dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return 81
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	var ws unix.WaitStatus
	for {
		_, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WUNTRACED, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil || !ws.Stopped() {
			return 82
		}
		break
	}
	if err := scopeWriteMarker(filepath.Join(dir, "waited"), []byte(fmt.Sprintf("%d %d", os.Getpid(), cmd.Process.Pid))); err != nil {
		return 83
	}
	var goAhead [1]byte
	if _, err := os.Stdin.Read(goAhead[:]); err != nil {
		return 84
	}
	job.Follow(context.Background(), cmd.Process.Pid, syscall.Signal(ws.StopSignal()))
	return 0
}

func TestScopeProcessDiscardsAContinuedGroupStop(t *testing.T) {
	master, slave := scopePTY(t)
	dir := t.TempDir()
	cmd := exec.Command("/bin/bash", "--norc", "--noprofile", "-c", `set -m
"$1"
while [ ! -e "$2/continue" ]; do sleep 0.01; done
fg
exit "$?"`, "bash", os.Args[0], dir)
	cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=continued-stop-parent", "SCOPE_EXPECT_CWD="+dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(done) }()
	var pidfds []int
	t.Cleanup(func() {
		for _, fd := range pidfds {
			_ = unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
			_ = unix.Close(fd)
		}
		_ = cmd.Process.Kill()
		<-done
	})
	var parent, child int
	if _, err := fmt.Sscanf(string(scopeWaitFile(t, filepath.Join(dir, "waited"))), "%d %d", &parent, &child); err != nil {
		t.Fatal(err)
	}
	for _, pid := range []int{parent, child} {
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		pidfds = append(pidfds, fd)
	}
	// The child stop is already saved. Stop the entire job as a cooked Ctrl-Z would, then let bash fg it.
	if err := unix.Kill(-parent, syscall.SIGTSTP); err != nil {
		t.Fatal(err)
	}
	scopeWaitStopped(t, parent)
	scopeWaitStopped(t, child)
	if err := os.WriteFile(filepath.Join(dir, "continue"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	scopeWaitFile(t, filepath.Join(dir, "resumed"))
	// A second CONT reaches an already-running child before the saved stop is delivered to Follow.
	if err := unix.Kill(-parent, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if _, err := master.Write([]byte("follow\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if waitErr != nil {
			t.Fatalf("parent stopped again after fg: %v (parent %d)", waitErr, parent)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("parent did not discard the continued child's saved stop")
	}
}
