// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func scopeWaitForParentDeath() int {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM)
	defer signal.Stop(signals)
	dir := os.Getenv("SCOPE_EXPECT_CWD")
	if err := scopeWriteMarker(filepath.Join(dir, "child"), []byte(strconv.Itoa(os.Getpid()))); err != nil {
		return 88
	}
	sig := <-signals
	if err := scopeWriteMarker(filepath.Join(dir, "parent-death-signal"), []byte(fmt.Sprint(int(sig.(syscall.Signal))))); err != nil {
		return 87
	}
	return 37
}

// The handler is armed before the child acknowledges readiness. Killing only the proxy must deliver TERM to
// the child, allowing its ordinary shutdown path to run. A parent-death KILL leaves no acknowledgement.
func TestScopeParentDeathAllowsTheLauncherToStopCleanly(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command(os.Args[0])
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "TEGO_SCOPE_TEST_HELPER=proxy-parentdeath", "SCOPE_EXPECT_CWD="+dir)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	child, err := strconv.Atoi(string(scopeWaitFile(t, filepath.Join(dir, "child"))))
	if err != nil {
		t.Fatal(err)
	}
	pidfd, err := unix.PidfdOpen(child, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = unix.PidfdSendSignal(pidfd, syscall.SIGKILL, nil, 0)
		_ = unix.Close(pidfd)
	})
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if got := string(scopeWaitFile(t, filepath.Join(dir, "parent-death-signal"))); got != strconv.Itoa(int(syscall.SIGTERM)) {
		t.Fatalf("parent death delivered %q, want SIGTERM", got)
	}
}
