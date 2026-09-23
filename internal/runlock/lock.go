// SPDX-License-Identifier: Apache-2.0

package runlock

import (
	"errors"
	"fmt"
	"io"
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

// Lock and stop-marker errors, one per failure class (docs/p0/runtime-launch.md §9 "Naming").
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
		_ = t.Close()
		return nil, err
	}
	return t, nil
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
	b, _ := readLockProofFile("/proc/locks", lockProofTableLimit) // unavailable global evidence still permits descriptor proof
	return requireLockHolderFromSnapshot(b, pid, st)
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
	base := "/proc/" + strconv.Itoa(pid)
	dir, err := os.Open(base + "/fd")
	if err != nil {
		return fmt.Errorf("read launcher descriptors: %w", err)
	}
	defer func() { _ = dir.Close() }()
	deadline := time.Now().Add(lockProofTimeLimit)
	scanned := 0
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
	b, err := readLockProofFile(path, lockProofInfoLimit)
	if err != nil {
		return "", err
	}
	return fdInfoFlockRow(b, pid, ino), nil
}

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
	got, err := StartBootNS(pid)
	if err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: pid %d: %w", ErrStale, pid, err)
	}
	if got != wantStartBootNS {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: pid %d started at %d, lock says %d", ErrStale, pid, got, wantStartBootNS)
	}
	return &StopTarget{fd: fd, pid: pid}, nil
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
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		return 0, fmt.Errorf("read /proc/%d/stat: %w", pid, err)
	}
	return parseStartBootNS(b)
}

// parseStartBootNS is StartBootNS's pure half. It goes through proc.ParseStat, the one fuzzed parser
// of the stat line every package shares, so the lock file, the launcher's child record and an exec id
// all convert the same field with the same tick; a malformed line wraps proc.ErrStat.
func parseStartBootNS(stat []byte) (uint64, error) {
	st, err := proc.ParseStat(stat)
	if err != nil {
		return 0, fmt.Errorf("parse /proc stat: %w", err)
	}
	return st.StartBootNS(), nil
}
