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
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// undumpableHolder starts the stand-in launcher TestLockHolderProofNonDumpableHelper makes of the test binary: a
// process that made itself undumpable (as the secret-holding launcher does) and holds the flock of the run lock in dir.
// It returns the lock file, its stat, the holder's pid, and whether the kernel's /proc/locks prints the device that stat
// shows (it does not on a btrfs subvolume).
func undumpableHolder(t *testing.T, dir string) (lock string, st syscall.Stat_t, pid int, deviceMatches bool) {
	t.Helper()
	lock = lockPath(dir)
	f, err := os.OpenFile(lock, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
	ready := filepath.Join(dir, "ready")
	child := exec.Command(os.Args[0], "-test.run=^TestLockHolderProofNonDumpableHelper$", "-test.timeout=30s")
	child.Env = append(os.Environ(), "TEGO_LOCK_NONDUMPABLE_HELPER=1", "TEGO_LOCK_HELPER_READY="+ready)
	child.ExtraFiles = []*os.File{f}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = child.Process.Kill(); _ = child.Wait() })
	for deadline := time.Now().Add(10 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the undumpable stand-in launcher did not take the lock")
		}
	}
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		t.Fatal(err)
	}
	parentInfo, err := os.ReadFile(fmt.Sprintf("/proc/%d/fdinfo/%d", os.Getpid(), f.Fd()))
	row := fdInfoFlockRow(parentInfo, child.Process.Pid, uint64(st.Ino))
	if err != nil || row == "" {
		t.Fatalf("the shared open file description must show the child's flock: %q, %v", parentInfo, err)
	}
	want := fmt.Sprintf("%02x:%02x:%d", unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)), st.Ino)
	return lock, st, child.Process.Pid, strings.Fields(row)[5] == want
}

// TestUndumpableLauncherProofReadsTheTableAgain: the stand-in launcher is undumpable, so a caller that is not root
// cannot read its descriptors and /proc/locks is the only proof. A read of that table that leaves its row out (the
// table is paginated, and a lock taken or dropped between two fills moves a row) is read again, up to
// lockProofTableReads times; a launcher whose row no read shows is refused, in words that say why and how it is
// proved, never as a launcher that is gone; and a launcher whose descriptors are readable is proved by them and the
// table is read once.
func TestUndumpableLauncherProofReadsTheTableAgain(t *testing.T) {
	dir := t.TempDir()
	_, st, pid, deviceMatches := undumpableHolder(t, dir)
	table := listedTable(t, pid, uint64(st.Ino))
	old := readLocksTable
	t.Cleanup(func() { readLocksTable = old })

	if lockProofTableReads < 3 {
		t.Fatalf("lockProofTableReads = %d: a table read that omits the row twice must still be recovered", lockProofTableReads)
	}
	reads := 0
	readLocksTable = func() []byte {
		reads++
		if reads < 3 { // the first two reads leave the row out
			return nil
		}
		return table
	}
	err := requireLockHolder(Dir{Path: dir}, pid)
	// Where the printed device is not stat's (a btrfs subvolume), a caller that signals only itself takes the row on
	// the mount's superblock device; any other caller has no proof.
	if deviceMatches || callerSignalsOnlyItself(pid) {
		if err != nil || reads != 3 {
			superblockDiagnostics(t, dir, pid, table)
			t.Fatalf("a row shown by the third read: err %v after %d reads, want nil after 3", err, reads)
		}
	} else if !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("a printed device that is not stat's, and no readable descriptor: %v, want ErrNotLockHolder", err)
	}

	reads = 0
	readLocksTable = func() []byte { reads++; return nil }
	oldBackoff := lockProofBackoff
	lockProofBackoff = 0
	t.Cleanup(func() { lockProofBackoff = oldBackoff })
	err = requireLockHolder(Dir{Path: dir}, pid)
	if !errors.Is(err, ErrNotLockHolder) || errors.Is(err, ErrStale) {
		t.Fatalf("no read shows the row: %v, want ErrNotLockHolder and not ErrStale (the launcher is not gone)", err)
	}
	if reads != lockProofTableReads {
		t.Errorf("the table was read %d times, want %d", reads, lockProofTableReads)
	}
	for _, want := range []string{"not dumpable", "CAP_SYS_PTRACE"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q does not say %q", err, want)
		}
	}

	// A launcher whose descriptors are readable (this process holds the lock itself) is proved by them, table or not.
	f, st2 := heldProofFile(t, lockPath(t.TempDir()))
	_ = f
	reads = 0
	readLocksTable = func() []byte { reads++; return nil }
	if err := requireLockHolderFromSnapshot(nil, os.Getpid(), st2); err != nil {
		t.Fatalf("a dumpable holder with no global row: %v", err)
	}
	if reads != 0 {
		t.Errorf("a snapshot proof read the table %d times", reads)
	}
}

// TestUndumpableLauncherIsAliveToStatus: what `tego status`, the dashboard's run chip, `tego stop` and the sweep ask
// of a run (LauncherCheck) is Alive for a launcher that made itself undumpable, as long as /proc/locks prints the
// device stat shows; and it is Unknown, with the cause, to a caller that may signal others where it does not. It is never Gone, which would end or
// reclaim a live run.
func TestUndumpableLauncherIsAliveToStatus(t *testing.T) {
	dir := t.TempDir()
	lock, st, pid, deviceMatches := undumpableHolder(t, dir)
	start, err := StartBootNS(pid)
	if err != nil {
		t.Fatalf("/proc/%d/stat of an undumpable process: %v", pid, err)
	}
	if err := os.WriteFile(lock, []byte(LockInfo{PID: pid, StartBootNS: start}.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	table := listedTable(t, pid, uint64(st.Ino))
	old := readLocksTable
	t.Cleanup(func() { readLocksTable = old })
	readLocksTable = func() []byte { return table }

	l, cause, err := LauncherCheck(dir)
	if err != nil {
		t.Fatal(err)
	}
	if l != Alive {
		superblockDiagnostics(t, dir, pid, table)
	}
	switch {
	case (deviceMatches || callerSignalsOnlyItself(pid)) && (l != Alive || cause != nil):
		t.Fatalf("an undumpable launcher whose lock /proc/locks shows (on stat's device, or on the superblock's for a caller that signals only itself): %v, %v; want Alive", l, cause)
	case !deviceMatches && !callerSignalsOnlyItself(pid) && (l != Unknown || cause == nil):
		t.Fatalf("an undumpable launcher whose printed device is not stat's, to a caller that may signal others: %v, %v; want Unknown with a cause", l, cause)
	}
	if l == Gone {
		t.Fatal("a live launcher read as gone")
	}
	// The identity every reader of a launcher takes (the adoption's adopterAlive, the reaper's and the relay's start
	// time, the peer's StartBootNS) is its stat line, which stays readable; what the process says it runs (exe, cwd) is
	// refused and the read says so in Process.Err, never as an empty answer.
	st1, err := proc.New().Stat(pid)
	if err != nil || st1.StartBootNS() != start {
		t.Fatalf("stat of an undumpable process: %v, start %d want %d", err, st1.StartBootNS(), start)
	}
	p, err := proc.New().Process(pid)
	if err != nil || p.StartBootNS != start || p.Exe != "" || p.Cwd != "" || !errors.Is(p.Err, fs.ErrPermission) {
		t.Fatalf("Process of an undumpable process: %+v, %v; want its identity and a permission error for exe and cwd", p, err)
	}
	if len(p.Argv) == 0 || p.Cgroup == "" {
		t.Errorf("cmdline and cgroup of an undumpable process are readable: argv %v cgroup %q", p.Argv, p.Cgroup)
	}
	// Its start time, its pidfd and the signal a stop sends do not need a readable /proc entry.
	target, err := openPidfdTarget(pid, start)
	if err != nil {
		t.Fatalf("pidfd of an undumpable launcher: %v", err)
	}
	defer func() { _ = target.Close() }()
	if err := target.Signal(0); err != nil {
		t.Fatalf("signal of an undumpable launcher: %v", err)
	}
}

// TestTableReadsAreMadeApart: the four reads of /proc/locks for a launcher whose descriptors are hidden are separated by
// a pause (3, 6 and 9 ms), so that lock churn which hides the held row from one read is over before the next: back to
// back they can be cut by the same churn.
func TestTableReadsAreMadeApart(t *testing.T) {
	dir := t.TempDir()
	_, _, pid, _ := undumpableHolder(t, dir)
	old := readLocksTable
	t.Cleanup(func() { readLocksTable = old })
	var at []time.Time
	readLocksTable = func() []byte { at = append(at, time.Now()); return nil }
	if err := requireLockHolder(Dir{Path: dir}, pid); !errors.Is(err, ErrNotLockHolder) {
		t.Fatalf("no row in any read: %v", err)
	}
	if len(at) != lockProofTableReads {
		t.Fatalf("%d reads, want %d", len(at), lockProofTableReads)
	}
	for i := 1; i < len(at); i++ {
		if gap, want := at[i].Sub(at[i-1]), time.Duration(i)*lockProofBackoff; gap < want {
			t.Errorf("read %d came %v after the one before, want at least %v", i+1, gap, want)
		}
	}
}
