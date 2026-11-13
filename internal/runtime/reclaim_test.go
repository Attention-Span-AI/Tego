// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
)

// holdLock starts a process that flocks the lock file at path, as a process of a run can, and returns it.
func holdLock(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	ready := path + ".held"
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockHolderHelper$")
	cmd.Env = append(os.Environ(), "TEGO_TEST_HOLD_LOCK="+path, "TEGO_TEST_HOLD_READY="+ready)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	deadline := time.Now().Add(20 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			return cmd
		}
		if time.Now().After(deadline) {
			t.Fatal("the lock holder never took the lock")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestLockHolderHelper holds a lock until it is killed. It does nothing in a normal run.
func TestLockHolderHelper(t *testing.T) {
	path := os.Getenv("TEGO_TEST_HOLD_LOCK")
	if path == "" {
		t.Skip("helper process only")
	}
	// A raw descriptor, not an *os.File: once flocked, the file is never used again, and a collection that
	// found it unreachable ran its finalizer, closed it and dropped the lock mid-test, which failed the
	// live-launcher case in one of CI's two root variants.
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

// goneLauncher is a pid and start time of a process that has exited.
func goneLauncher(t *testing.T) LockInfo {
	t.Helper()
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	start, err := StartBootNS(cmd.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	return LockInfo{PID: cmd.Process.Pid, StartBootNS: start}
}

// TestASweepReclaimsALockItsLauncherNoLongerHolds: a process of a run can open the
// run's lock file and flock it, and once the launcher died the run read as running forever, so no sweep
// ended it and `tego stop` called it not running. A lock whose recorded launcher is gone is now reclaimed:
// the run's tree is killed, which ends the holder, and the run is swept as an orphan. A lock whose launcher
// is alive is left alone.
func TestASweepReclaimsALockItsLauncherNoLongerHolds(t *testing.T) {
	const id = "r-00000000-000000000000a-orphan"
	for _, tc := range []struct {
		name      string
		launcher  func(t *testing.T) LockInfo
		wantEnded bool
	}{
		{"the launcher is gone", goneLauncher, true},
		{"the launcher is alive", func(t *testing.T) LockInfo {
			start, err := StartBootNS(os.Getpid())
			if err != nil {
				t.Fatal(err)
			}
			return LockInfo{PID: os.Getpid(), StartBootNS: start}
		}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, scopes := t.TempDir(), t.TempDir()
			lostRunIn(t, root, id, 0)
			lock := filepath.Join(root, id, ledger.LockFile)
			if err := os.WriteFile(lock, []byte(tc.launcher(t).String()), 0o600); err != nil {
				t.Fatal(err)
			}
			holder := holdLock(t, lock)
			scope := scopeUnder(t, scopes, id)
			m := &scopeCgroups{fakeCgroups: fakeCgroups{root: scopes}}
			m.onKill = func() { _ = holder.Process.Kill(); _ = holder.Wait() }
			prev := orphanRoots
			orphanRoots = func(cgroup.Manager, markDir, runDir) ([]string, error) { return []string{scopes}, nil }
			t.Cleanup(func() { orphanRoots = prev })

			if _, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); err != nil {
				t.Fatalf("Sweep: %v", err)
			}
			st, err := ledger.NewRunRepository(root).State(context.Background(), id)
			if err != nil {
				t.Fatal(err)
			}
			if ended := st == ledger.StateEnded; ended != tc.wantEnded {
				t.Fatalf("state %s, want ended=%v (killed %v)", st, tc.wantEnded, m.killed)
			}
			if killed := len(m.killed) > 0; killed != tc.wantEnded || (killed && m.killed[0] != scope) {
				t.Errorf("killed %v", m.killed)
			}
		})
	}
}
