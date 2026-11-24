// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"golang.org/x/sys/unix"
)

const scopeNestedAgentEnv = "TEGO_SCOPE_NESTED_AGENT"

// The grandchild owns a foreground process group, as an interactive agent may. Its launcher and the outer
// waiting parent keep the shell's original group; both must stop before the shell can offer its prompt.
func scopeNestedAgent() {
	continued := make(chan os.Signal, 1)
	signal.Notify(continued, syscall.SIGCONT)
	defer signal.Stop(continued)
	signal.Ignore(syscall.SIGTTOU)
	if err := unix.IoctlSetPointerInt(0, unix.TIOCSPGRP, unix.Getpgrp()); err != nil {
		os.Exit(86)
	}
	modes, err := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil {
		os.Exit(85)
	}
	modes.Lflag &^= unix.ICANON | unix.ECHO
	if err := unix.IoctlSetTermios(0, unix.TCSETS, modes); err != nil {
		os.Exit(84)
	}
	if err := scopeWriteMarker(filepath.Join(os.Getenv("SCOPE_EXPECT_CWD"), "child"), []byte(strconv.Itoa(os.Getpid()))); err != nil {
		os.Exit(83)
	}
	_ = unix.Kill(os.Getpid(), syscall.SIGSTOP)
	// kill returns before every runtime thread has stopped. Wait for the
	// follower's continuation before checking the restored terminal or exiting.
	<-continued
	front, err := unix.IoctlGetInt(0, unix.TIOCGPGRP)
	now, modeErr := unix.IoctlGetTermios(0, unix.TCGETS)
	if err != nil || modeErr != nil || front != unix.Getpgrp() || now.Lflag&(unix.ICANON|unix.ECHO) != 0 {
		os.Exit(82)
	}
	os.Exit(37)
}

func scopeNestedLauncher() int {
	job := tegoruntime.NewJobControl(tegoruntime.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
	defer job.Close()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), scopeNestedAgentEnv+"=1")
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return 81
	}
	defer func() { _ = cmd.Process.Release() }()
	if err := scopeWriteMarker(filepath.Join(os.Getenv("SCOPE_EXPECT_CWD"), "launcher"), []byte(strconv.Itoa(os.Getpid()))); err != nil {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		return 80
	}
	for {
		var ws unix.WaitStatus
		_, err := unix.Wait4(cmd.Process.Pid, &ws, unix.WUNTRACED, nil)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return 79
		}
		if ws.Stopped() {
			job.Follow(context.Background(), cmd.Process.Pid, syscall.Signal(ws.StopSignal()))
			continue
		}
		if ws.Exited() {
			return ws.ExitStatus()
		}
		if ws.Signaled() {
			return 128 + int(ws.Signal())
		}
	}
}

func TestScopeProcessFollowsAnAgentInItsOwnForegroundGroup(t *testing.T) {
	_, slave := scopePTY(t)
	saved, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cmd := exec.Command("/bin/bash", "--norc", "--noprofile", "-c", `set -m
"$1"
while [ ! -e "$2/continue" ]; do sleep 0.01; done
fg
exit "$?"`, "bash", os.Args[0], dir)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=proxy-stop-nested", "SCOPE_EXPECT_CWD="+dir)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	var waitErr error
	go func() {
		waitErr = cmd.Wait()
		close(done)
	}()
	var pidfds []int
	t.Cleanup(func() {
		for _, fd := range pidfds {
			_ = unix.PidfdSendSignal(fd, syscall.SIGKILL, nil, 0)
			_ = unix.Close(fd)
		}
		_ = cmd.Process.Kill()
		<-done
	})
	pids := make(map[string]int)
	for _, name := range []string{"child", "launcher", "proxy"} {
		pid, err := strconv.Atoi(string(scopeWaitFile(t, filepath.Join(dir, name))))
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatal(err)
		}
		pidfds = append(pidfds, fd)
		pids[name] = pid
	}
	for _, name := range []string{"child", "launcher", "proxy"} {
		scopeWaitStopped(t, pids[name])
	}
	now, err := unix.IoctlGetTermios(int(slave.Fd()), unix.TCGETS)
	if err != nil || *now != *saved {
		t.Fatalf("nested stop left raw terminal: %v %v", now, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "continue"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
		if ee, ok := waitErr.(*exec.ExitError); !ok || ee.ExitCode() != 37 {
			t.Fatalf("nested foreground resume: %v", waitErr)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("nested agent did not resume with its modes and foreground group")
	}
}
