// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// Lock and stop-marker errors, one per failure class.
var (
	// ErrStale is returned by OpenStopTargetFor when the pid recorded in a run's lock file is now a
	// different process: its start time no longer matches (R22, case 15).
	ErrStale = errors.New("runtime: lock holder is gone; the pid was reused")
	// ErrLockInfo is a lock file whose content is not "<pid> <start_boot_ns>" (torn or truncated).
	ErrLockInfo = errors.New("runtime: malformed lock file")
	// ErrNotLockHolder is returned by OpenStopTargetFor when the lock file's line names a process that does not hold
	// the run's flock (or whose hold cannot be read): a line a user planted in a ledger root they own, or a launcher
	// in another pid namespace. Nothing is signalled, and it is not ErrStale, so no caller reads it as "the
	// launcher is gone" (R22).
	ErrNotLockHolder = errors.New("runtime: the pid the lock file names does not hold the run's lock")
	// ErrUnverified is a lock line whose process exists but whose identity cannot be read: its /proc stat line is
	// unreadable (a restricted procfs, EACCES) or does not parse. It is neither the launcher proved nor ErrStale, so
	// no caller reads it as "the launcher is gone": nothing is signalled, killed or reclaimed on it.
	ErrUnverified = errors.New("runtime: the lock holder's identity cannot be read")
)

// LockInfo is the advisory content of <ledger_root>/<run>/lock: who holds it and when that process
// started, in CLOCK_BOOTTIME nanoseconds. Liveness is the flock alone and never this content (§3);
// the pair exists only so `tego stop` can target the holder through a pidfd it has verified (R22).
type LockInfo struct {
	PID         int
	StartBootNS uint64
	// PIDNS is the inode of the launcher's pid namespace (/proc/self/ns/pid), the optional third field of
	// the line. PID means nothing outside that namespace, so a reader in another one must not read a pid
	// that is missing or different there as "the launcher is gone" (OpenStopTargetFor). 0: not recorded.
	PIDNS uint64
}

// String renders the lock file's single line, terminator included.
func (i LockInfo) String() string {
	out := strconv.Itoa(i.PID) + " " + strconv.FormatUint(i.StartBootNS, 10)
	if i.PIDNS != 0 {
		out += " " + strconv.FormatUint(i.PIDNS, 10)
	}
	return out + "\n"
}

// OwnPIDNS is the inode of this process's pid namespace, 0 when /proc does not say: the lock line's third field.
func OwnPIDNS() uint64 {
	fi, err := os.Stat("/proc/self/ns/pid")
	if err != nil {
		return 0
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return st.Ino
	}
	return 0
}

// ParseLockInfo decodes a lock file's bytes. It never panics on a torn, empty or oversized read: a
// line that is not "<pid> <start_boot_ns>" is ErrLockInfo (§9 FuzzParseLockInfo).
func ParseLockInfo(b []byte) (LockInfo, error) {
	fields := strings.Fields(string(b))
	if len(fields) != 2 && len(fields) != 3 {
		return LockInfo{}, fmt.Errorf("%w: want two or three fields, got %d", ErrLockInfo, len(fields))
	}
	pid, err := strconv.Atoi(fields[0])
	if err != nil || pid <= 0 {
		return LockInfo{}, fmt.Errorf("%w: pid %q", ErrLockInfo, fields[0])
	}
	start, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return LockInfo{}, fmt.Errorf("%w: start_boot_ns %q", ErrLockInfo, fields[1])
	}
	info := LockInfo{PID: pid, StartBootNS: start}
	if len(fields) == 3 {
		ns, err := strconv.ParseUint(fields[2], 10, 64)
		if err != nil {
			return LockInfo{}, fmt.Errorf("%w: pid_ns %q", ErrLockInfo, fields[2])
		}
		info.PIDNS = ns
	}
	return info, nil
}

// lockPath is the run's lock file, the one ledger.Open flocks (R1).
func lockPath(runDir string) string { return filepath.Join(runDir, ledger.LockFile) }

// ProbeLock reports whether a live process holds the run's lock and what the lock file says about
// it. The probe is one flock(LOCK_EX|LOCK_NB) on a fresh descriptor: it fails with EWOULDBLOCK for
// the holder's own process too, because flock(2) is per open file description (R1, R12) — the
// sweeper needs no self-exclusion. held is false and info is the zero value when the run directory
// has no lock file at all (E27: a missing lock counts as free).
//
// The lock file is opened as the ledger's readers open theirs: O_NOFOLLOW, O_NONBLOCK, and refused unless it
// is a regular file. A plain O_RDONLY open blocked for good on a FIFO planted under the name, which hung `tego
// stop` and every sweep that probed the run (R22), and followed a link out of the run directory.
func ProbeLock(runDir string) (held bool, info LockInfo, err error) {
	return ProbeLockIn(Dir{Path: runDir})
}

// ProbeLockIn is ProbeLock for d, under the directory a sweep hook was lent when d holds one.
func ProbeLockIn(d Dir) (held bool, info LockInfo, err error) {
	f, err := d.openFile(ledger.LockFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, LockInfo{}, nil
		}
		return false, LockInfo{}, fmt.Errorf("runtime: open lock file: %w", err)
	}
	defer func() { _ = f.Close() }()
	b := make([]byte, 128)
	n, rerr := f.Read(b)
	if rerr == nil || n > 0 {
		if parsed, perr := ParseLockInfo(b[:n]); perr == nil {
			info = parsed
		}
	}
	if err := sys.Flock(f, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return true, info, nil
		}
		return false, info, fmt.Errorf("runtime: flock %s: %w", lockPath(d.Path), err)
	}
	// The probe took the lock; releasing it by closing the descriptor leaves the run free.
	_ = sys.Flock(f, syscall.LOCK_UN)
	return false, info, nil
}

// StopTarget is a launcher process held open by a pidfd whose identity was verified once, so every
// later signal reaches that exact task even if the pid is reused in between (R22, cases 15/29/32).
type StopTarget struct {
	fd  *sys.FD // the verified pidfd; closed by Close, borrowed by Signal (ADR 0023)
	pid int
}

// OpenStopTargetFor opens the launcher the run's parsed lock line names (info.PID, info.StartBootNS) through
// pidfd_open(2) after proving that pid holds THIS run's flock (R22): the lock line is advisory text any user who
// owns the ledger root can write, and both values are world-readable in /proc, so a privileged stop or sweep
// steered by a planted line would otherwise signal a victim. A process that does not hold the lock returns
// ErrNotLockHolder; a process that started at another time than info.StartBootNS returns ErrStale without
// signalling anything, and so does a pid that no longer exists. A StartBootNS of 0 is refused as ErrStale too:
// mintRun never writes it, so a line carrying it was not written by a launcher. A line that records the launcher's pid namespace
// and names another one than the caller's is ErrNotLockHolder before anything is looked up: its pid is a number
// in a namespace this process cannot see, so it is absent or some other process here, and ErrStale would read a
// live launcher as gone (stop's "not running", the sweep's orphan kill). Nothing is signalled.
func OpenStopTargetFor(runDir string, info LockInfo) (*StopTarget, error) {
	return OpenStopTargetIn(Dir{Path: runDir}, info)
}

// OpenStopTargetIn is OpenStopTargetFor for d, whose lock is proved under the directory a sweep hook was lent when d
// holds one.
func OpenStopTargetIn(d Dir, info LockInfo) (*StopTarget, error) {
	pid, wantStartBootNS := info.PID, info.StartBootNS
	if info.PIDNS != 0 {
		if own := OwnPIDNS(); own != 0 && own != info.PIDNS {
			return nil, fmt.Errorf("%w: pid %d is in another pid namespace", ErrNotLockHolder, pid)
		}
	}
	if wantStartBootNS == 0 {
		return nil, fmt.Errorf("%w: pid %d: the lock line records no start time", ErrStale, pid)
	}
	t, err := openPidfdTarget(pid, wantStartBootNS)
	if err != nil {
		return nil, err
	}
	if err := requireLockHolder(d, pid); err != nil {
		left := launcherLeft(t, err)
		_ = t.Close()
		if left {
			// The launcher was alive when its pidfd was opened and has left since, so there is no holder to prove: the
			// run ended while it was being looked at. Not ErrNotLockHolder: nothing here holds the lock, and a reader that
			// calls it unknown would never learn the run is over. (A launcher that released the lock and is still alive,
			// finishing, is not stale: the sweep reads ErrStale as a launcher gone with the lock held, and kills the run's
			// tree. Readers that only judge ask LockFree.)
			return nil, fmt.Errorf("%w: pid %d left while the run's lock was being proved (%v)", ErrStale, pid, err)
		}
		return nil, err
	}
	return t, nil
}

// LockFree says no process holds the run's lock at this moment (the probe takes it for an instant). A reader whose proof that
// a process holds the lock failed asks it again: the ledger's close releases the flock before the launcher process exits (it
// prints its summary and closes its other files first), so a proof that began on a held lock can fail on a run that ended
// meanwhile, and that run is over, not a launcher that cannot be judged.
func LockFree(runDir string) bool {
	held, _, err := ProbeLock(runDir)
	return err == nil && !held
}

// errDescriptorsReleased is requireFDLockHolder finding the launcher's descriptor directory empty and its address space
// gone: a live launcher has its lock descriptor and its standard three at least, so a process with neither descriptors
// nor memory has been through exit's release of both (the kernel does that before the task work that drops its flock and
// before its pidfd turns readable) and is exiting.
var errDescriptorsReleased = errors.New("the launcher has released its descriptors")

// releasedItsMemory says the process under proc (a /proc/<pid> directory) has no address space left: its status has no Vm
// lines, which the kernel prints only for a process with an mm, and exit gives up the mm before the descriptor table. With
// an empty descriptor directory it tells a launcher in exit from a live process that merely holds no descriptor.
func releasedItsMemory(proc string) bool {
	b, err := readProofFile(proc+"/status", lockProofTableLimit)
	if err != nil || len(b) == 0 {
		return false
	}
	return !strings.Contains(string(b), "\nVmSize:")
}

// launcherExitWait bounds how long a launcher that has released its descriptors is waited for to finish exiting: the end
// of exit is a few task works after the release, and the wait ends the moment the pidfd turns readable.
var launcherExitWait = 2 * time.Second

// launcherLeft says the process behind t, which was alive when t was opened, has left by the time a proof of its lock
// failed with err: its pidfd is readable, or err says it has released its descriptors and it finishes exiting within
// launcherExitWait. A launcher that is still running (a refusal that is the proof's own: another process holds the lock, or
// the descriptors are hidden) is not left, and its refusal stands.
func launcherLeft(t *StopTarget, err error) bool {
	timeout := time.Duration(0)
	if errors.Is(err, errDescriptorsReleased) {
		timeout = launcherExitWait
	}
	exited, perr := pidfdExitedWithin(t.fd, timeout)
	return perr == nil && exited
}

// requireLockHolder proves that pid holds the flock on the exact run lock. A positive global kernel
// row must match owner, device and inode; an absent row or a differing printed superblock device (as
// on some btrfs subvolumes) requires descriptor-specific proof. A paginated /proc/locks read can omit
// a held lock when unrelated locks change between fills, so absence is not evidence of unlock.
func requireLockHolder(d Dir, pid int) error {
	f, err := d.openFile(ledger.LockFile)
	if err != nil {
		return fmt.Errorf("%w: pid %d: %w", ErrNotLockHolder, pid, err)
	}
	defer func() { _ = f.Close() }()
	var st syscall.Stat_t
	if err := sys.FileDo(f, func(fd int) error { return syscall.Fstat(fd, &st) }); err != nil {
		return fmt.Errorf("%w: pid %d: %w", ErrNotLockHolder, pid, err)
	}
	table := readLocksTable()
	err = requireLockHolderFromSnapshot(table, pid, st)
	if err == nil || !errors.Is(err, fs.ErrPermission) {
		return err
	}
	// A launcher that is not dumpable (it holds secrets, ADR 0126, "Amendment 2026-11-21: the secret-holding launcher
	// is not dumpable") hides its descriptors from a caller without CAP_SYS_PTRACE, so the global table is the only
	// proof it leaves. Two things follow.
	//
	// The table is paginated: another process taking or dropping a lock between two of its fills can leave the held
	// row out of one read, so a read that does not show it is made again, a few times with a pause between, before the
	// launcher is called no holder. A launcher whose descriptors are readable is proved by them at once and the table
	// is read once.
	//
	// The table prints the superblock's device and stat the subvolume's, on a btrfs subvolume (and bcachefs, and
	// overlayfs), so the exact device never matches there. A caller that cannot signal beyond its own uid (superblockProof)
	// may then take the row on the device of the mount that holds the file: a proof forged by a user can at most make
	// that caller signal a process it could already signal.
	alt, mnt, relaxed := superblockProof(f, pid)
	sbDev, sbOK := alt, relaxed
	if !relaxed {
		// A caller the gate refuses (root, CAP_KILL, CAP_SYS_PTRACE, another user's launcher) takes no row on the
		// superblock's device, but its refusal says when the table lists one: that is the cause of the refusal, and
		// "no row" would be false.
		sbDev, _, sbOK = superblockDevice(f)
	}
	withheld := false
	for i := 0; ; i++ {
		if relaxed && rowOnDevice(table, pid, st, alt) && mountIDOf(f) == mnt {
			return nil
		}
		withheld = withheld || !relaxed && sbOK && rowOnDevice(table, pid, st, sbDev)
		if i+1 >= lockProofTableReads {
			break
		}
		time.Sleep(time.Duration(i+1) * lockProofBackoff)
		table = readLocksTable()
		if e := requireLockHolderFromSnapshot(table, pid, st); e == nil {
			return nil
		} else {
			err = e
		}
	}
	if withheld {
		return fmt.Errorf("%w; %s", err, hiddenLauncherWithheldWhy(sbDev))
	}
	return fmt.Errorf("%w; %s", err, hiddenLauncherWhy)
}

// hiddenLauncherWithheldWhy is hiddenLauncherWhy for a refusal where /proc/locks does list the launcher's flock, but
// under the device of the file's filesystem (btrfs, overlayfs and bcachefs print that, not the file's own), and the
// caller is one superblockProof does not let take that row.
func hiddenLauncherWithheldWhy(dev uint64) string {
	return fmt.Sprintf("the launcher's descriptors are hidden from this user (it is not dumpable, as a launcher that holds "+
		"secrets is, or it is another user's), and /proc/locks lists its flock only under %d:%d, the device of this file's whole "+
		"filesystem (the filesystem prints that, not the file's own device), a row this caller does not take: only a caller that "+
		"cannot signal another user's process takes it (not root, no CAP_KILL or CAP_SYS_PTRACE, and the launcher its own "+
		"user's), because a lock line written by another user could otherwise point a caller that can signal anything at a process "+
		"that holds a different file's lock with the same inode number; a caller with CAP_SYS_PTRACE (root, unless a container or a "+
		"service unit drops it) reads the descriptors and proves it", unix.Major(dev), unix.Minor(dev))
}

// hiddenLauncherWhy is what a refusal says when the launcher's descriptors could not be read: why, and what proves it
// anyway. Never a guess that the launcher holds the lock.
const hiddenLauncherWhy = "the launcher's descriptors are hidden from this user (it is not dumpable, as a launcher that holds " +
	"secrets is, or it is another user's), and /proc/locks showed no row of its flock for the device of this file's mount; " +
	"a caller with CAP_SYS_PTRACE (root, unless a container or a service unit drops it) reads them"

// lockProofTableReads is how many times the global lock table is read for a launcher whose descriptors are hidden, and
// lockProofBackoff the pause after the first read, doubled and tripled after the next: a few milliseconds, since the
// omission comes from lock churn that is over in that time.
const lockProofTableReads = 4

var lockProofBackoff = 3 * time.Millisecond

// readLocksTable is the global lock table, nil when it cannot be read (no global evidence: the descriptors then
// decide). A variable so a test can stand in a sequence of reads.
var readLocksTable = func() []byte {
	b, _ := readLockProofFile("/proc/locks", lockProofTableLimit)
	return b
}

// readSelfProc reads /proc/self/<name> (mountinfo); a variable so a test can describe a mount the host does not have.
var readSelfProc = func(name string) ([]byte, error) { return readLockProofFile("/proc/self/"+name, lockProofTableLimit) }

// callerSignalsOnlyItself is the gate of the superblock proof: this caller is not root (real or effective), holds
// neither CAP_KILL nor CAP_SYS_PTRACE in its effective or permitted set, and the process it is about to prove has
// its real, effective, saved and filesystem uids all equal to the caller's effective uid. Such a caller can signal
// that process whatever the proof says, so a proof a user forged gives it no power it lacks. A variable so a test can
// describe a caller.
var callerSignalsOnlyItself = func(pid int) bool {
	eff, perm, _, err := sys.Capabilities()
	if err != nil {
		return false
	}
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/status")
	if err != nil {
		return false
	}
	return signalsOnlyItself(os.Getuid(), os.Geteuid(), eff, perm, b)
}

// signalsOnlyItself is callerSignalsOnlyItself over its facts: the caller's real and effective uid and capability sets,
// and the target's /proc status.
func signalsOnlyItself(ruid, euid int, eff, perm uint64, status []byte) bool {
	const powers = 1<<unix.CAP_KILL | 1<<unix.CAP_SYS_PTRACE
	if ruid == 0 || euid == 0 || (eff|perm)&powers != 0 {
		return false
	}
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		f := strings.Fields(rest)
		if len(f) != 4 {
			return false
		}
		for _, v := range f {
			if n, err := strconv.Atoi(v); err != nil || n != euid {
				return false
			}
		}
		return true
	}
	return false
}

// mountIDOf is the mount id of the mount that holds f, from statx(2)'s STATX_MNT_ID (Linux 5.8 and later; the same number
// as fdinfo's "mnt_id:" and mountinfo's first field); -1 when it cannot be read, and then no superblock proof is made. A
// variable so a test can describe a mount the host does not have, or one that moved.
var mountIDOf = func(f *os.File) int {
	id := -1
	_ = sys.FileDo(f, func(fd int) error {
		var stx unix.Statx_t
		if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_MNT_ID, &stx); err != nil || stx.Mask&unix.STATX_MNT_ID == 0 {
			return err
		}
		id = int(stx.Mnt_id)
		return nil
	})
	return id
}

// superblockProof is the device /proc/locks prints for f's file (the superblock's, from /proc/self/mountinfo's row of
// the mount that holds f) and that mount's id, when the caller may rely on it: the gate holds and both are read.
// ok is false otherwise, and then only the exact device and the descriptors prove a launcher.
func superblockProof(f *os.File, pid int) (dev uint64, mnt int, ok bool) {
	if !callerSignalsOnlyItself(pid) {
		return 0, 0, false
	}
	return superblockDevice(f)
}

// superblockDevice is the device /proc/locks prints for f's file and the mount id it was read for: the device of the
// mount that holds f, from /proc/self/mountinfo. It makes no judgement of the caller.
func superblockDevice(f *os.File) (dev uint64, mnt int, ok bool) {
	mnt = mountIDOf(f)
	if mnt < 0 {
		return 0, 0, false
	}
	b, err := readSelfProc("mountinfo")
	if err != nil {
		return 0, 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 5 || fields[0] != strconv.Itoa(mnt) {
			continue
		}
		maj, min, found := strings.Cut(fields[2], ":")
		major, e1 := strconv.ParseUint(maj, 10, 32)
		minor, e2 := strconv.ParseUint(min, 10, 32)
		if !found || e1 != nil || e2 != nil {
			return 0, 0, false
		}
		return unix.Mkdev(uint32(major), uint32(minor)), mnt, true
	}
	return 0, 0, false
}

// rowOnDevice reports whether the table lists a granted FLOCK of pid on st's inode printed with device dev. The file
// must be regular. It is requireLockHolderFromSnapshot's row test with the device the caller chose.
func rowOnDevice(table []byte, pid int, st syscall.Stat_t, dev uint64) bool {
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG {
		return false
	}
	for _, line := range strings.Split(string(table), "\n") {
		row := fdInfoFlockRow([]byte("lock: "+line), pid, uint64(st.Ino))
		if row == "" {
			continue
		}
		id := strings.Split(strings.Fields(row)[5], ":")
		if len(id) != 3 {
			continue
		}
		major, majorErr := strconv.ParseUint(id[0], 16, 32)
		minor, minorErr := strconv.ParseUint(id[1], 16, 32)
		if majorErr == nil && minorErr == nil && unix.Mkdev(uint32(major), uint32(minor)) == dev {
			return true
		}
	}
	return false
}

// requireLockHolderFromSnapshot receives the observed table explicitly. It never accepts inode alone:
// different filesystems can assign the same inode to different files. A complete exact-device row also
// permits proof for a non-dumpable launcher whose fdinfo is inaccessible to an otherwise valid stopper.
func requireLockHolderFromSnapshot(table []byte, pid int, st syscall.Stat_t) error {
	for _, line := range strings.Split(string(table), "\n") {
		row := fdInfoFlockRow([]byte("lock: "+line), pid, uint64(st.Ino))
		if row == "" {
			continue
		}
		id := strings.Split(strings.Fields(row)[5], ":")
		if len(id) != 3 {
			continue
		}
		major, majorErr := strconv.ParseUint(id[0], 16, 32)
		minor, minorErr := strconv.ParseUint(id[1], 16, 32)
		if majorErr == nil && minorErr == nil && major == uint64(unix.Major(uint64(st.Dev))) &&
			minor == uint64(unix.Minor(uint64(st.Dev))) && st.Mode&syscall.S_IFMT == syscall.S_IFREG {
			return nil
		}
	}
	if err := requireFDLockHolder(pid, st); err != nil {
		return fmt.Errorf("%w: pid %d: %w", ErrNotLockHolder, pid, err)
	}
	return nil
}

const (
	lockProofTableLimit = 16 << 20
	lockProofFDLimit    = 8192
	lockProofInfoLimit  = 4096
	lockProofTimeLimit  = 5 * time.Second
)

// requireFDLockHolder streams the descriptor directory rather than allocating an untrusted process's
// entire descriptor list. Launchers acquire the ledger lock early, before composing even a 4095-row
// Landlock table. Proof beyond these generous limits is unavailable and fails closed.
func requireFDLockHolder(pid int, want syscall.Stat_t) error {
	base := procRoot + "/" + strconv.Itoa(pid)
	dir, err := os.Open(base + "/fd")
	if err != nil {
		return fmt.Errorf("read launcher descriptors: %w", err)
	}
	defer func() { _ = dir.Close() }()
	deadline := time.Now().Add(lockProofTimeLimit)
	scanned := 0
	var denied error // the first descriptor whose fdinfo this caller was refused: the launcher hides them
	for {
		entries, readErr := dir.ReadDir(128)
		for _, entry := range entries {
			if scanned >= lockProofFDLimit || time.Now().After(deadline) {
				return fmt.Errorf("descriptor lock proof exceeded %d entries or %s", lockProofFDLimit, lockProofTimeLimit)
			}
			scanned++
			if _, err := strconv.ParseUint(entry.Name(), 10, 32); err != nil {
				continue
			}
			infoPath := base + "/fdinfo/" + entry.Name()
			before, err := readFDLockRow(infoPath, pid, uint64(want.Ino))
			if err != nil || before == "" {
				if denied == nil && errors.Is(err, fs.ErrPermission) {
					denied = err
				}
				continue // a closing descriptor, or another file, is not evidence
			}
			fdPath := base + "/fd/" + entry.Name()
			var got syscall.Stat_t
			if err := syscall.Stat(fdPath, &got); err != nil || !sameLockFile(got, want) {
				continue
			}
			after, err := readFDLockRow(infoPath, pid, uint64(want.Ino))
			if err != nil || after != before {
				continue
			}
			// A close/reuse between the reads must not substitute another inode or filesystem.
			if err := syscall.Stat(fdPath, &got); err == nil && sameLockFile(got, want) {
				return nil
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				if scanned == 0 && releasedItsMemory(base) {
					return errDescriptorsReleased
				}
				if denied != nil {
					// The directory lists (root reads it, whoever owns it) and every descriptor's fdinfo is refused: the
					// launcher is not dumpable and this caller lacks CAP_SYS_PTRACE. That is a hidden launcher, as an
					// unreadable directory is, and not a launcher that holds no such lock.
					return fmt.Errorf("read launcher descriptors: %w", denied)
				}
				return errors.New("no descriptor proves the run's flock")
			}
			return fmt.Errorf("read launcher descriptors: %w", readErr)
		}
	}
}

func sameLockFile(got, want syscall.Stat_t) bool {
	return got.Dev == want.Dev && got.Ino == want.Ino && got.Mode&syscall.S_IFMT == syscall.S_IFREG
}

func readFDLockRow(path string, pid int, ino uint64) (string, error) {
	b, err := readProofFile(path, lockProofInfoLimit)
	if err != nil {
		return "", err
	}
	return fdInfoFlockRow(b, pid, ino), nil
}

// procRoot and readProofFile are what requireFDLockHolder reads a launcher's descriptors through: variables only so a test
// can describe a launcher whose descriptor directory lists and whose fdinfo is refused (root without CAP_SYS_PTRACE).
var (
	procRoot      = "/proc"
	readProofFile = readLockProofFile
)

// readLockProofFile discards partial or oversized evidence, so a complete-looking prefix is never
// accepted from a read that exceeded its bound. The caller can still seek independent descriptor proof.
func readLockProofFile(path string, limit int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, int64(limit)+1))
	if err != nil {
		return nil, err
	}
	if len(b) > limit {
		return nil, fmt.Errorf("lock proof record exceeds %d-byte read bound", limit)
	}
	return b, nil
}

// fdInfoFlockRow requires a granted full-file FLOCK with the exact kernel owner, not a POSIX/OFD lock,
// waiter, inherited lock owned by another process, or inode-only descriptor entry.
func fdInfoFlockRow(info []byte, pid int, ino uint64) string {
	for _, line := range strings.Split(string(info), "\n") {
		rest, ok := strings.CutPrefix(line, "lock:")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) != 8 || fields[1] != "FLOCK" || fields[2] != "ADVISORY" ||
			(fields[3] != "READ" && fields[3] != "WRITE") || fields[6] != "0" || fields[7] != "EOF" {
			continue
		}
		if !strings.HasSuffix(fields[0], ":") {
			continue
		}
		if _, err := strconv.ParseUint(strings.TrimSuffix(fields[0], ":"), 10, 64); err != nil {
			continue
		}
		row := strings.Join(fields, " ")
		if flockHeldBy([]byte(row), pid, ino) {
			return row
		}
	}
	return ""
}

// flockHeldBy reports whether a /proc/locks table lists a FLOCK held (not waited for) by pid on inode ino.
// A line reads "1: FLOCK  ADVISORY  WRITE 1234 fd:01:5678 0 EOF"; a waiter's line carries "->" after the index.
func flockHeldBy(table []byte, pid int, ino uint64) bool {
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 6 || fields[1] != "FLOCK" {
			continue
		}
		owner, err := strconv.Atoi(fields[4])
		if err != nil || owner != pid {
			continue
		}
		id := fields[5]
		k := strings.LastIndexByte(id, ':')
		if k < 0 {
			continue
		}
		if n, err := strconv.ParseUint(id[k+1:], 10, 64); err == nil && n == ino {
			return true
		}
	}
	return false
}

// openPidfdTarget opens pid through pidfd_open(2) and verifies that the process behind the fd started at
// wantStartBootNS.
func openPidfdTarget(pid int, wantStartBootNS uint64) (*StopTarget, error) {
	// Process scope: this descriptor signals the launcher and is polled for its exit, and a thread's
	// exit is not the process's (sys.ErrThreadScopedPidfd guards the other direction).
	fd, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("%w: pid %d is gone", ErrStale, pid)
		}
		return nil, fmt.Errorf("runtime: pidfd_open(%d): %w", pid, err)
	}
	got, err := startBootNS(pid)
	if err != nil {
		_ = fd.Close()
		// Only a stat line that is not there says the process is gone (it exited and was reaped after pidfd_open).
		// An unreadable or malformed one, or one of a task released while it was read, says nothing of who the pid
		// is: the identity is unknown, never stale.
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH) {
			return nil, fmt.Errorf("%w: pid %d: %w", ErrStale, pid, err)
		}
		return nil, fmt.Errorf("%w: pid %d: %w", ErrUnverified, pid, err)
	}
	if got != wantStartBootNS {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: pid %d started at %d, lock says %d", ErrStale, pid, got, wantStartBootNS)
	}
	// The process the lock line names, but it may have exited and not been reaped yet: a zombie keeps its pid and its
	// stat line, holds no descriptor and so no lock. Its pidfd is readable once it has exited (pidfd_open(2)).
	if exited, perr := pidfdExited(fd); perr != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: pid %d: poll its pidfd: %w", ErrUnverified, pid, perr)
	} else if exited {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: pid %d has exited (not yet reaped)", ErrStale, pid)
	}
	return &StopTarget{fd: fd, pid: pid}, nil
}

// startBootNS is StartBootNS, as openPidfdTarget reads it; a test makes it fail as a restricted procfs does.
var startBootNS = StartBootNS

// pidfdExited reports whether the process behind a process pidfd has exited: the pidfd polls readable then, reaped or
// not. It does not wait.
func pidfdExited(fd *sys.FD) (bool, error) { return pidfdExitedWithin(fd, 0) }

// pidfdExitedWithin is pidfdExited that waits up to timeout for the exit: the poll returns the moment the process has
// exited, so it never waits longer than the exit takes.
func pidfdExitedWithin(fd *sys.FD, timeout time.Duration) (bool, error) {
	var exited bool
	err := fd.Borrow(func(n int) error {
		pfd := []unix.PollFd{{Fd: int32(n), Events: unix.POLLIN}}
		deadline := time.Now().Add(timeout)
		for {
			wait := max(int(time.Until(deadline).Milliseconds()), 0)
			_, err := unix.Poll(pfd, wait)
			if errors.Is(err, unix.EINTR) {
				continue
			}
			if err != nil {
				return err
			}
			exited = pfd[0].Revents&(unix.POLLIN|unix.POLLHUP) != 0
			return nil
		}
	})
	return exited, err
}

// PID is the process the target refers to.
func (t *StopTarget) PID() int { return t.pid }

// Signal delivers sig through the held pidfd (pidfd_send_signal(2)), never by raw pid, so the
// verified identity still holds at delivery time (R22).
func (t *StopTarget) Signal(sig syscall.Signal) error {
	if t == nil {
		return fmt.Errorf("runtime: signal: %w", os.ErrClosed)
	}
	err := sys.PidfdSendSignalFD(t.fd, sig)
	switch {
	case errors.Is(err, sys.ErrClosed):
		return fmt.Errorf("runtime: signal: %w", os.ErrClosed)
	case err != nil:
		return fmt.Errorf("runtime: pidfd_send_signal(%d, %v): %w", t.pid, sig, err)
	}
	return nil
}

// Close releases the pidfd. Idempotent; a Signal in flight keeps the number until it returns.
func (t *StopTarget) Close() error {
	if t == nil {
		return nil
	}
	if err := t.fd.Close(); err != nil {
		return fmt.Errorf("runtime: close pidfd: %w", err)
	}
	return nil
}

// StartBootNS reads field 22 of /proc/<pid>/stat (starttime, in USER_HZ ticks since boot) and
// returns it in nanoseconds since boot — the CLOCK_BOOTTIME-relative value an exec id and a lock
// file carry (spec/identity/RUN-IDENTITY.md). It is immune to wall-clock steps (case 19).
func StartBootNS(pid int) (uint64, error) {
	b, err := proc.ReadStat(func() ([]byte, error) { return os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat") })
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/stat: %w", pid, err)
	}
	return parseStartBootNS(b)
}

// parseStartBootNS is StartBootNS's pure half. It goes through proc.ParseStat, the one fuzzed parser
// of the stat line every package shares, so the lock file, the launcher's child record and an exec id
// all convert the same field with the same tick; a malformed line wraps proc.ErrStat. So does the line of a task
// released while it was read (proc.ErrReleased) when StartBootNS's reads of it (proc.ReadStat) ran out.
func parseStartBootNS(stat []byte) (uint64, error) {
	st, err := proc.ParseStat(stat)
	if err != nil {
		return 0, fmt.Errorf("parse /proc stat: %w", err)
	}
	return st.StartBootNS(), nil
}
