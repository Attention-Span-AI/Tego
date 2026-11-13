// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// TestLauncherGone: a run's launcher is gone when its lock is free, or when the lock line's process is not the one
// that wrote it (gone, or its pid now another process's by start time); it is not gone while the line's process
// holds the lock, and not gone when the holder cannot be judged (no line yet, a line naming a process that does not
// hold the lock). The pid alone never decides.
func TestLauncherGone(t *testing.T) {
	dir := t.TempDir()
	if gone, err := LauncherGone(dir); err != nil || !gone {
		t.Fatalf("no lock file: gone %v err %v, want gone", gone, err)
	}
	lock := filepath.Join(dir, ledger.LockFile)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if gone, err := LauncherGone(dir); err != nil || !gone {
		t.Fatalf("a free lock: gone %v err %v, want gone", gone, err)
	}
	holder := holdLock(t, lock)
	holderStart, err := StartBootNS(holder)
	if err != nil {
		t.Fatal(err)
	}
	reaped := exec.Command("/bin/true")
	if err := reaped.Run(); err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	other := exec.Command("/bin/sleep", "30")
	if err := other.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() { _ = other.Process.Kill(); _ = other.Wait() })
	otherStart, err := StartBootNS(other.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		info LockInfo
		want bool
	}{
		{"the holder's own line", LockInfo{PID: holder, StartBootNS: holderStart}, false},
		{"no line yet", LockInfo{}, false},
		{"a pid that is gone", LockInfo{PID: reaped.Process.Pid, StartBootNS: holderStart}, true},
		{"the holder's pid with another start time (reused)", LockInfo{PID: holder, StartBootNS: holderStart + 1}, true},
		{"a live process that does not hold the lock", LockInfo{PID: other.Process.Pid, StartBootNS: otherStart}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			line := ""
			if tc.info.PID != 0 {
				line = tc.info.String()
			}
			if err := os.WriteFile(lock, []byte(line), 0o600); err != nil {
				t.Fatal(err)
			}
			if gone, err := LauncherGone(dir); err != nil || gone != tc.want {
				t.Errorf("gone %v err %v, want %v", gone, err, tc.want)
			}
		})
	}
}

// holdLock starts a process that holds path's flock until the test ends (TestHoldLockHelper) and returns its pid.
func holdLock(t *testing.T, path string) int {
	t.Helper()
	ready := filepath.Join(t.TempDir(), "ready")
	cmd := exec.Command(os.Args[0], "-test.run=^TestHoldLockHelper$")
	cmd.Env = append(os.Environ(), "TEGO_TEST_HOLD_LOCK="+path, "TEGO_TEST_HOLD_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			return cmd.Process.Pid
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in launcher never took the lock")
		}
	}
}

// TestHoldLockHelper is holdLock's stand-in launcher: it holds a lock until it is killed. It does nothing in a normal
// run.
func TestHoldLockHelper(t *testing.T) {
	path := os.Getenv("TEGO_TEST_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(os.Getenv("TEGO_TEST_HOLD_READY"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for {
		time.Sleep(time.Hour)
	}
}

// TestLauncherOfUnknownAndExited: a launcher whose identity cannot be read (its stat line unreadable, as under a
// restricted procfs, or malformed) is unknown, never gone, so nothing calls its run lost or kills it; a launcher that
// has exited but is not reaped yet (a zombie, which keeps its pid and start time and holds no lock) is gone while
// another process holds the lock, where it read as alive forever.
func TestLauncherOfUnknownAndExited(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, ledger.LockFile)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	holder := holdLock(t, lock)
	holderStart, err := StartBootNS(holder)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lock, []byte(LockInfo{PID: holder, StartBootNS: holderStart}.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	for name, readErr := range map[string]error{
		"an unreadable stat line": fmt.Errorf("read /proc/%d/stat: %w", holder, syscall.EACCES),
		"a malformed stat line":   fmt.Errorf("parse /proc stat: %w", proc.ErrStat),
	} {
		t.Run(name, func(t *testing.T) {
			old := startBootNS
			startBootNS = func(int) (uint64, error) { return 0, readErr }
			t.Cleanup(func() { startBootNS = old })
			if l, err := LauncherOf(dir); err != nil || l != Unknown {
				t.Errorf("launcher %v err %v, want unknown", l, err)
			}
			if _, err := OpenStopTargetFor(dir, LockInfo{PID: holder, StartBootNS: holderStart}); !errors.Is(err, ErrUnverified) || errors.Is(err, ErrStale) {
				t.Errorf("OpenStopTargetFor: %v, want ErrUnverified and not ErrStale", err)
			}
		})
	}

	// A dead, unreaped launcher: started and never waited for, so it stays a zombie.
	zombie := exec.Command("/bin/true")
	if err := zombie.Start(); err != nil {
		t.Skipf("no /bin/true: %v", err)
	}
	t.Cleanup(func() { _ = zombie.Wait() })
	start, err := StartBootNS(zombie.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		b, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stat", zombie.Process.Pid))
		if st, err := proc.ParseStat(b); err == nil && st.State == 'Z' {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the stand-in launcher never became a zombie")
		}
	}
	if err := os.WriteFile(lock, []byte(LockInfo{PID: zombie.Process.Pid, StartBootNS: start}.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := LauncherOf(dir); err != nil || l != Gone {
		t.Errorf("a zombie launcher with its lock held by another process: launcher %v err %v, want gone", l, err)
	}
}
