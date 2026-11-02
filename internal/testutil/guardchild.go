// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"
)

// forwardedSignals are the signals the guard parent passes on to the child: an interrupt or a termination aimed at
// the binary go test started, and go test's SIGQUIT to a test binary that outlived its -timeout.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// isGuardParent reports whether v, guardParentEnv's value, is the pid of this process's parent and that parent runs
// this process's executable: only the GuardedMain that started this child set it so.
func isGuardParent(v string) bool {
	pid, err := strconv.Atoi(v)
	if err != nil || pid <= 1 || pid != os.Getppid() {
		return false
	}
	self, err := os.Stat("/proc/self/exe")
	if err != nil {
		return false
	}
	parent, err := os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	return err == nil && os.SameFile(self, parent)
}

// runGuardedChild runs the tests in a child, as the binary was started (startArgs, startEnv, the standard streams
// and every descriptor it inherited without close-on-exec) with guardParentEnv naming this process, forwards
// forwardedSignals to it while it runs, and returns its exit code: 128 plus the signal's number, said on stderr,
// for a child a signal ended. An error is a child that could not be started: no test has run.
func runGuardedChild(stderr io.Writer) (int, error) {
	// PR_SET_PDEATHSIG fires when the thread that started the child ends, so that thread must be this one, which
	// lives until the binary exits.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := &exec.Cmd{
		Path:        "/proc/self/exe",
		Args:        startArgs,
		Env:         append(startEnv[:len(startEnv):len(startEnv)], guardParentEnv+"="+strconv.Itoa(os.Getpid())),
		Stdin:       os.Stdin,
		Stdout:      os.Stdout,
		Stderr:      os.Stderr,
		SysProcAttr: &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL},
	}
	sigs := make(chan os.Signal, len(forwardedSignals))
	signal.Notify(sigs, forwardedSignals...)
	defer signal.Stop(sigs)
	if err := cmd.Start(); err != nil {
		return 0, err
	}
	done, forwarded := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case s := <-sigs:
				_ = cmd.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	err := cmd.Wait()
	close(done)
	<-forwarded
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0, nil
	case errors.As(err, &exit):
		if ws, ok := exit.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
			_, _ = fmt.Fprintf(stderr, "testutil: the tests' process %d ended by signal %v\n", cmd.Process.Pid, ws.Signal())
			return 128 + int(ws.Signal()), nil
		}
		return exit.ExitCode(), nil
	}
	_, _ = fmt.Fprintf(stderr, "testutil: waiting for the tests' process %d: %v\n", cmd.Process.Pid, err)
	return 1, nil
}
