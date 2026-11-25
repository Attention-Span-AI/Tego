// SPDX-License-Identifier: Apache-2.0

package askclient

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runlock"
)

// The ledger's close releases the run's flock before the launcher process exits. A command that probed the lock held, and
// whose proof that the named process holds it then failed, is looking at a run that ended: ErrNoBroker, and the
// refusal stands while the lock is still held by something else.
func TestALockReleasedWhileTheLauncherWasProvedIsNoLiveBroker(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, ledger.LockFile)
	child := exec.Command("sleep", "300")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	start, err := runlock.StartBootNS(child.Process.Pid)
	if err != nil {
		t.Fatal(err)
	}
	line := runlock.LockInfo{PID: child.Process.Pid, StartBootNS: start}
	if err = os.WriteFile(lock, []byte(line.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(lock, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	// held by this test, named process is a bystander: the proof fails, the lock is still held: the refusal stands
	if _, err = Launcher(dir); !errors.Is(err, runlock.ErrNotLockHolder) || errors.Is(err, ErrNoBroker) {
		t.Fatalf("a lock held by another process: %v, want ErrNotLockHolder", err)
	}
	old := lockFree
	t.Cleanup(func() { lockFree = old })
	lockFree = func(d string) bool { // the holder unlocks between the proof's failure and this look
		_ = f.Close()
		return old(d)
	}
	if _, err = Launcher(dir); !errors.Is(err, ErrNoBroker) {
		t.Fatalf("a lock released while the launcher was proved: %v, want ErrNoBroker", err)
	}
}
