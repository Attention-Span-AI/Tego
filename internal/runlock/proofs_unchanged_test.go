// SPDX-License-Identifier: Apache-2.0

package runlock_test

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// TestRunlockProofsUnchanged holds the R22 cases against the moved package's exported API, by path and under a
// lent directory, as tego stop, tego ask and the sweep reach them: a lock line planted by a user who owns the ledger
// root names a process that does not hold the run's flock (ErrNotLockHolder, nothing signalled); a line whose start
// time is not the holder's is stale (ErrStale); a line recording another pid namespace is ErrNotLockHolder before
// any lookup, never ErrStale; and the process that does hold the flock is accepted.
func TestRunlockProofsUnchanged(t *testing.T) {
	victim := exec.Command("/bin/sleep", "30")
	if err := victim.Start(); err != nil {
		t.Skipf("no /bin/sleep: %v", err)
	}
	t.Cleanup(func() { _ = victim.Process.Kill(); _ = victim.Wait() })
	vstart, err := runlock.StartBootNS(victim.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	self, err := runlock.StartBootNS(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	f, err := os.OpenFile(filepath.Join(dir, ledger.LockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	at, err := sys.Own(unix.Open(dir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = at.Close() })

	own := runlock.OwnPIDNS()
	for _, d := range []runlock.Dir{{Path: dir}, {Path: dir, At: at}} {
		open := func(info runlock.LockInfo) error {
			target, err := runlock.OpenStopTargetIn(d, info)
			if err == nil {
				_ = target.Close()
			}
			return err
		}
		if err := open(runlock.LockInfo{PID: victim.Process.Pid, StartBootNS: vstart}); !errors.Is(err, runlock.ErrNotLockHolder) {
			t.Errorf("lent=%v: a planted line naming a process that holds no lock: %v, want ErrNotLockHolder", d.At != nil, err)
		}
		if err := open(runlock.LockInfo{PID: os.Getpid(), StartBootNS: self + 1}); !errors.Is(err, runlock.ErrStale) {
			t.Errorf("lent=%v: the holder's pid with another start time: %v, want ErrStale", d.At != nil, err)
		}
		if err := open(runlock.LockInfo{PID: os.Getpid(), StartBootNS: 0}); !errors.Is(err, runlock.ErrStale) {
			t.Errorf("lent=%v: a line with no start time: %v, want ErrStale", d.At != nil, err)
		}
		if own != 0 {
			if err := open(runlock.LockInfo{PID: os.Getpid(), StartBootNS: self, PIDNS: own + 1}); !errors.Is(err, runlock.ErrNotLockHolder) {
				t.Errorf("lent=%v: a line from another pid namespace: %v, want ErrNotLockHolder", d.At != nil, err)
			}
		}
		if err := open(runlock.LockInfo{PID: os.Getpid(), StartBootNS: self, PIDNS: own}); err != nil {
			t.Errorf("lent=%v: the process holding the lock: %v", d.At != nil, err)
		}
		held, _, err := runlock.ProbeLockIn(d)
		if err != nil || !held {
			t.Errorf("lent=%v: probe of a held lock: held=%v, %v", d.At != nil, held, err)
		}
	}
	if syscall.Kill(victim.Process.Pid, 0) != nil {
		t.Fatal("the victim named by the planted line was signalled away")
	}
}
