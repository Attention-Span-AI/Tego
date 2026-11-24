// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// root without CAP_SYS_PTRACE (Docker's default root) reads an undumpable launcher's /proc/<pid>/fd directory, which root's
// DAC override lets it list, and is refused every descriptor's fdinfo. Such a reader used to be told "no descriptor
// proves the run's flock", a sentence that says nothing of why, and on a filesystem that prints its superblock's device
// (btrfs, overlayfs, bcachefs) never that /proc/locks lists the flock and why the reader does not take that row (N81).

// fakeLauncher is a /proc of one process, pid, whose descriptor directory lists one entry that is the lock file, under a
// temporary root, and the file's stat. Its fdinfo is whatever readProofFile is made to say.
func fakeLauncher(t *testing.T, pid int) (dir string, st syscall.Stat_t) {
	t.Helper()
	dir = t.TempDir()
	lock := lockPath(dir)
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Stat(lock, &st); err != nil {
		t.Fatal(err)
	}
	proc := t.TempDir()
	fd := filepath.Join(proc, fmt.Sprint(pid), "fd")
	if err := os.MkdirAll(fd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(lock, filepath.Join(fd, "3")); err != nil {
		t.Fatal(err)
	}
	old, oldRead := procRoot, readProofFile
	t.Cleanup(func() { procRoot, readProofFile = old, oldRead })
	procRoot = proc
	return dir, st
}

func TestARefusedFdinfoIsAHiddenLauncherNotAnAbsentLock(t *testing.T) {
	const pid = 4242
	_, st := fakeLauncher(t, pid)
	readProofFile = func(path string, _ int) ([]byte, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: syscall.EACCES}
	}
	err := requireFDLockHolder(pid, st)
	if !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("every fdinfo refused: %v, want a permission error (the launcher hides its descriptors)", err)
	}
	// A readable fdinfo that shows no lock is the other thing: no descriptor proves it, and that is no permission refusal.
	readProofFile = func(string, int) ([]byte, error) { return []byte("pos:\t0\nflags:\t02\n"), nil }
	if err = requireFDLockHolder(pid, st); err == nil || errors.Is(err, fs.ErrPermission) {
		t.Fatalf("readable fdinfo with no flock: %v, want the plain refusal", err)
	}
}

func TestARootCallerWithoutPtraceIsToldWhatItDidNotTake(t *testing.T) {
	const pid = 4243
	dir, st := fakeLauncher(t, pid)
	readProofFile = func(path string, _ int) ([]byte, error) {
		return nil, &fs.PathError{Op: "open", Path: path, Err: syscall.EACCES}
	}
	oldTable, oldSelf, oldGate, oldBackoff, oldMount := readLocksTable, readSelfProc, callerSignalsOnlyItself, lockProofBackoff, mountIDOf
	t.Cleanup(func() {
		readLocksTable, readSelfProc, callerSignalsOnlyItself, lockProofBackoff, mountIDOf = oldTable, oldSelf, oldGate, oldBackoff, oldMount
	})
	lockProofBackoff = 0
	mountIDOf = func(*os.File) int { return 77 }
	readSelfProc = func(name string) ([]byte, error) {
		if name == "mountinfo" {
			return []byte("26 1 0:25 / / rw - btrfs /dev/vda5 rw\n77 26 0:43 /home /home rw - btrfs /dev/vda5 rw,subvol=/home\n"), nil
		}
		return nil, syscall.ENOENT
	}
	row := func(major, minor uint32) []byte {
		return []byte(fmt.Sprintf("1: FLOCK  ADVISORY  WRITE %d %02x:%02x:%d 0 EOF\n", pid, major, minor, st.Ino))
	}
	prove := func(gate bool, table []byte) error {
		readLocksTable = func() []byte { return table }
		callerSignalsOnlyItself = func(int) bool { return gate }
		return requireLockHolder(Dir{Path: dir}, pid)
	}

	t.Run("the table lists the flock under the filesystem's device and the caller may signal others", func(t *testing.T) {
		err := prove(false, row(0, 43))
		if !errors.Is(err, ErrNotLockHolder) || errors.Is(err, ErrStale) {
			t.Fatalf("%v, want ErrNotLockHolder", err)
		}
		for _, want := range []string{"lists its flock only under 0:43", "this caller does not take", "cannot signal another user's process", "CAP_SYS_PTRACE"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, err)
			}
		}
		if strings.Contains(err.Error(), "showed no row") {
			t.Errorf("the table did list a row, and the refusal says it showed none: %v", err)
		}
	})
	t.Run("a caller that signals only itself takes that row", func(t *testing.T) {
		if err := prove(true, row(0, 43)); err != nil {
			t.Fatalf("%v", err)
		}
	})
	t.Run("no row anywhere keeps the old words", func(t *testing.T) {
		err := prove(false, nil)
		if !errors.Is(err, ErrNotLockHolder) || !strings.Contains(err.Error(), "showed no row of its flock") || strings.Contains(err.Error(), "lists its flock only under") {
			t.Fatalf("%v", err)
		}
	})
	t.Run("a row on another device is not the filesystem's", func(t *testing.T) {
		err := prove(false, row(0, 44))
		if !errors.Is(err, ErrNotLockHolder) || strings.Contains(err.Error(), "lists its flock only under") {
			t.Fatalf("%v", err)
		}
	})
}

// A launcher in exit has released its address space and its descriptor table, and the task work that drops its flock and
// the exit that turns its pidfd readable come after: for that moment the run's lock is held by a process with no
// descriptor. A reader that looks then used to be told "no descriptor proves the run's flock" (an [io] failure, exit
// 125), when the run was ending (N109, the third window of the lost approve race).

// childProcess is a live process of this test, its identity as a lock line names it, and a pidfd of the test's own to wait
// for its exit without sleeping.
func childProcess(t *testing.T) (info LockInfo, kill func()) {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	start, err := StartBootNS(pid)
	if err != nil {
		t.Fatal(err)
	}
	own, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = own.Close(); _ = cmd.Process.Kill(); _ = cmd.Wait() })
	kill = func() {
		t.Helper()
		if err := cmd.Process.Kill(); err != nil {
			t.Fatal(err)
		}
		if exited, err := pidfdExitedWithin(own, 30*time.Second); err != nil || !exited {
			t.Fatalf("the child did not exit: %v %v", exited, err)
		}
	}
	return LockInfo{PID: pid, StartBootNS: start}, kill
}

// holdOwnLock takes the run's flock on a descriptor of this test, as a launcher that is not the process under proof does, and
// returns the release.
func holdOwnLock(t *testing.T, dir string) (release func()) {
	t.Helper()
	f, err := os.OpenFile(lockPath(dir), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	var once sync.Once
	release = func() { once.Do(func() { _ = f.Close() }) }
	t.Cleanup(release)
	return release
}

// fakeProcOf describes pid's /proc directory under procRoot: nfds descriptor entries and a status with or without Vm lines.
func fakeProcOf(t *testing.T, pid, nfds int, hasMemory bool) {
	t.Helper()
	dir := filepath.Join(procRoot, fmt.Sprint(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < nfds; i++ {
		if err := os.Symlink("/dev/null", filepath.Join(dir, "fd", fmt.Sprint(i))); err != nil {
			t.Fatal(err)
		}
	}
	status := "Name:\tsleep\nState:\tS (sleeping)\nThreads:\t1\n"
	if hasMemory {
		status = "Name:\tsleep\nState:\tS (sleeping)\nVmPeak:\t 1 kB\nVmSize:\t 1 kB\nThreads:\t1\n"
	}
	if err := os.WriteFile(filepath.Join(dir, "status"), []byte(status), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestALauncherInExitIsGoneNotAnotherHolder(t *testing.T) {
	info, kill := childProcess(t)
	dir, _ := fakeLauncher(t, 1) // the lock file and a fake /proc root; the launcher's own directory is described below
	holdOwnLock(t, dir)          // held, by someone else: only the launcher's leaving ends the run here
	fakeProcOf(t, info.PID, 0, false)
	readProofFile = func(path string, limit int) ([]byte, error) {
		if strings.HasSuffix(path, "/status") {
			kill() // the launcher finishes exiting as its state is read: the wait ends when its pidfd turns readable
		}
		return readLockProofFile(path, limit)
	}
	_, err := OpenStopTargetFor(dir, info)
	if !errors.Is(err, ErrStale) || errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("a launcher with no descriptors and no memory that then exits: %v, want ErrStale (gone), not a refusal of the holder", err)
	}
}

func TestAProcessThatHoldsNoDescriptorButIsAliveIsStillNotTheHolder(t *testing.T) {
	info, _ := childProcess(t)
	dir, _ := fakeLauncher(t, 1)
	holdOwnLock(t, dir)
	old := launcherExitWait
	t.Cleanup(func() { launcherExitWait = old })
	launcherExitWait = 20 * time.Millisecond // a live process is waited for only this long, and then refused
	for _, tc := range []struct {
		name      string
		hasMemory bool
	}{{"it still has its memory (a live process with no descriptor)", true}, {"it has none but does not exit", false}} {
		t.Run(tc.name, func(t *testing.T) {
			fakeProcOf(t, info.PID, 0, tc.hasMemory)
			_, err := OpenStopTargetFor(dir, info)
			if !errors.Is(err, ErrNotLockHolder) || errors.Is(err, ErrStale) {
				t.Fatalf("%v, want ErrNotLockHolder: the process is alive and does not hold the lock", err)
			}
		})
	}
}

func TestALauncherThatExitedWhileItsProofWasReadIsGone(t *testing.T) {
	info, kill := childProcess(t)
	dir, _ := fakeLauncher(t, 1)
	holdOwnLock(t, dir)
	fakeProcOf(t, info.PID, 3, true)
	readProofFile = func(path string, limit int) ([]byte, error) {
		kill() // gone by the time its descriptors have been read, whatever they said
		return []byte("pos:\t0\nflags:\t02\n"), nil
	}
	_, err := OpenStopTargetFor(dir, info)
	if !errors.Is(err, ErrStale) {
		t.Fatalf("a launcher that exited during its proof: %v, want ErrStale", err)
	}
}

// The ledger's close releases the run's flock before the launcher process exits (it prints its summary, closes its other
// files): for that time the lock is not held and the launcher is alive with its full descriptor table, and a proof that it
// holds the lock fails. The run has ended, and a reader told "the pid does not hold the lock" calls it unknown (N109). The
// judging readers say gone; OpenStopTargetFor stays a refusal and never ErrStale, which the sweep reads as a launcher gone
// with the lock held and answers by killing the run's tree.
func TestALockReleasedWhileItsHolderWasBeingProvedIsTheRunEnding(t *testing.T) {
	info, _ := childProcess(t)
	dir, _ := fakeLauncher(t, 1)
	fakeProcOf(t, info.PID, 3, true)
	if err := os.WriteFile(lockPath(dir), []byte(info.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	release := holdOwnLock(t, dir)
	readProofFile = func(path string, limit int) ([]byte, error) {
		release() // the launcher unlocks as its descriptors are being read
		return []byte("pos:\t0\nflags:\t02\n"), nil
	}
	if l, cause, err := LauncherCheck(dir); err != nil || l != Gone || cause != nil {
		t.Fatalf("a lock released during the proof: %v %v %v, want Gone", l, cause, err)
	}
	release = holdOwnLock(t, dir)
	if _, err := OpenStopTargetFor(dir, info); !errors.Is(err, ErrNotLockHolder) || errors.Is(err, ErrStale) {
		t.Fatalf("the proof of a lock that was released: %v, want the refusal, never ErrStale (the sweep kills a run's tree on it)", err)
	}
	// and with the lock still held by another process the refusal stands for the judging readers too
	holdOwnLock(t, dir)
	readProofFile = func(string, int) ([]byte, error) { return []byte("pos:\t0\nflags:\t02\n"), nil }
	if l, cause, err := LauncherCheck(dir); err != nil || l != Unknown || !errors.Is(cause, ErrNotLockHolder) {
		t.Fatalf("a lock still held by another process: %v %v %v, want Unknown", l, cause, err)
	}
}
