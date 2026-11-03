// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// Whether a build's timer lives, and whether a launcher holds the build, is read without taking either lock (ADR
// 0022, notes 2026-10-06 and 2026-10-16): a probe that takes a lock for a moment makes a process that asks for it in
// that moment read it held, which made a last launcher out start no timer and would make a timer
// starting under a probe exit. Prepare reads the pid the timer wrote into its timer file (timerRunning); `tego stop`
// reads that and, for a build it does not show a timer for, the kernel's lock table, /proc/locks, which costs an RCU
// grace period a read. The table's format is stable since 2.6 and the same on every kernel Tego runs on (5.14 to
// 7.x, arm64):
//
//	1: FLOCK  ADVISORY  WRITE 1234 00:1a:5678 0 EOF
//	1: -> FLOCK  ADVISORY  WRITE 4321 00:1a:5678 0 EOF
//
// The second line is a waiter blocked on the first (fs/locks.c lock_get_status: the " ->" prefix, indented by its
// depth since 5.15), which holds nothing. The device is the inode's superblock's, major and minor in hex; the inode
// number is decimal; the pid is the holder's in the pid namespace of the /proc that is read. A /proc of a child pid
// namespace does not list a lock whose holder it cannot see (fs/locks.c locks_show), which its readers take as no
// holder: a re-arm pass there starts a timer beside a live one, which exits on its timer lock, and a build a launcher
// holds gets a timer that waits for it. Nothing is removed on that reading: a removal takes the build lock itself.
//
// The table is read in pieces, and a piece can leave out a lock held all along (note 2026-11-02). /proc/locks is a
// seq_file over the host's list of locks, which every flock(2) changes: each read(2) prints lines from one consistent
// view of the list, at most a page of them (the seq_file buffer, 4 KiB on amd64), then lets the list go
// (fs/locks.c locks_start and locks_stop around fs/seq_file.c seq_read_iter), and the next read(2) goes on at the
// next line's position in the list as it then stands. Locks let go between two reads ahead of that position move
// every line after them up, so the lines that were next are never printed, whoever holds them. So the table is read
// a page a time (procLocksTable), which leaves no seam at all in a table of up to a page, and a pass that finds no
// holder of a file in one read looks again in a second read whose seams fall half a page from the first's
// (lockHolders); a lock is shown held when either read lists it.

// procLock is one flock(2) lock the table lists as held, not waited for.
type procLock struct {
	write        bool
	pid          int
	major, minor uint32
	ino          uint64
}

// procLocksLimit bounds the table read: a host with more locks than this is not one a timer's liveness can be read
// on, and it is answered as unknown (procLocksTable's error) rather than read without end.
const procLocksLimit = 16 << 20

// procLocksTable reads /proc/locks once, a page or more a read(2), so that each read prints a whole page from one
// view of the list; first, when it is not 0, is how many bytes the first read asks for, which moves every seam of the
// read by as much (lockHolders' second read). SweepOptions.lockTable stands in for it in a test.
func procLocksTable(first int) ([]byte, error) {
	f, err := os.Open("/proc/locks")
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := readTable(f, first, procLocksLimit)
	if err != nil {
		return nil, fmt.Errorf("read /proc/locks: %w", err)
	}
	return b, nil
}

// readTable reads r to its end: a first read of first bytes when first is positive, then reads of at least two
// pages (tableReadSize), so that what ends each of those is the kernel's page, never the buffer. It fails on a table
// longer than limit.
func readTable(r io.Reader, first, limit int) ([]byte, error) {
	buf := make([]byte, tableReadSize())
	var out []byte
	for want := first; ; want = len(buf) {
		if want <= 0 || want > len(buf) {
			want = len(buf)
		}
		n, err := r.Read(buf[:want])
		out = append(out, buf[:n]...)
		if len(out) > limit {
			return nil, fmt.Errorf("longer than %d bytes", limit)
		}
		if errors.Is(err, io.EOF) || (n == 0 && err == nil) {
			return out, nil
		}
		if err != nil {
			return nil, err
		}
	}
}

// tableReadSize is the size of procLocksTable's reads after the first: 64 KiB, or two pages where a page is larger.
func tableReadSize() int { return max(64<<10, 2*os.Getpagesize()) }

// lockHolders is a re-arm pass's reading of the kernel's lock table, read only when a build's timer file shows no
// live timer, at most twice. The first read is procLocksTable's whole pages. A file it shows no holder of is looked
// up again in a second read whose first read(2) asks for half a page, so every seam of that read falls half a page
// of lines from the first read's: a lock left out at a seam of the first lies well inside a page of the second, and
// is missed by both only if half a page of the locks listed before it came or went between the two. A file either
// read lists is held: it was, at a moment of the pass, and its holder is a launcher, which starts the build's timer
// when it leaves (its reaper, if it dies), or a timer. A table the first read cannot read shows no holder, and is
// not read again.
type lockHolders struct {
	read  func(first int) ([]byte, error)
	locks []procLock
	reads int
	err   error
}

// held reports whether a read of the table lists a held flock lock on the file st describes, a write one only when
// write is set (heldOn).
func (l *lockHolders) held(st unix.Stat_t, write bool) bool {
	if l.reads == 0 {
		l.add(0)
	}
	if heldOn(l.locks, st, write) {
		return true
	}
	if l.reads == 1 && l.err == nil {
		l.add(os.Getpagesize() / 2)
		return heldOn(l.locks, st, write)
	}
	return false
}

// add reads the table once more, its first read(2) asking for first bytes, and keeps the locks it lists beside the
// ones read before.
func (l *lockHolders) add(first int) {
	b, err := l.read(first)
	l.reads++
	if l.reads == 1 {
		l.err = err
	}
	l.locks = append(l.locks, parseProcLocks(b)...)
}

// parseProcLocks returns the flock locks a /proc/locks table lists as held. A line of any other kind (POSIX, OFD,
// a lease, a waiter's) or in any other shape is skipped: the table is kernel text, read as data.
func parseProcLocks(table []byte) []procLock {
	var out []procLock
	for len(table) > 0 {
		line := table
		if i := bytes.IndexByte(table, '\n'); i >= 0 {
			line, table = table[:i], table[i+1:]
		} else {
			table = nil
		}
		if l, ok := parseProcLock(string(line)); ok {
			out = append(out, l)
		}
	}
	return out
}

// parseProcLock parses one line of the table, ok only for a held flock lock.
func parseProcLock(line string) (procLock, bool) {
	f := strings.Fields(line)
	if len(f) != 8 || f[1] != "FLOCK" || f[2] != "ADVISORY" {
		return procLock{}, false // a waiter's line has "->" in f[1]
	}
	id, ok := strings.CutSuffix(f[0], ":")
	if !ok {
		return procLock{}, false
	}
	if _, err := strconv.ParseUint(id, 10, 64); err != nil {
		return procLock{}, false
	}
	var l procLock
	switch f[3] {
	case "WRITE":
		l.write = true
	case "READ":
	default:
		return procLock{}, false
	}
	pid, err := strconv.Atoi(f[4])
	if err != nil || pid < 0 {
		return procLock{}, false
	}
	l.pid = pid
	dev := strings.Split(f[5], ":")
	if len(dev) != 3 {
		return procLock{}, false // "<none>:0", a lock with no inode
	}
	major, err := strconv.ParseUint(dev[0], 16, 32)
	if err != nil {
		return procLock{}, false
	}
	minor, err := strconv.ParseUint(dev[1], 16, 32)
	if err != nil {
		return procLock{}, false
	}
	ino, err := strconv.ParseUint(dev[2], 10, 64)
	if err != nil {
		return procLock{}, false
	}
	l.major, l.minor, l.ino = uint32(major), uint32(minor), ino
	return l, true
}

// procRoot is the proc filesystem isTimerProcess looks for processes in.
const procRoot = "/proc"

// timerRunning reports whether build hash's timer file names a live timer: the pid its holder wrote into it
// (lockTimer) is a process that is (is, nil meaning isTimerProcess under procRoot as uid 0). It is Prepare's reading
// of a timer's liveness (ADR 0022, note 2026-10-16): it takes no lock, and it reads no lock table, whose read waits
// for an RCU grace period (fs/locks.c locks_start: percpu_down_write(&file_rwsem)), 8 ms on 6.17 and 48 ms on 6.1 in
// the guest, against prepare.lock-slot's 50 ms. False means not shown, not dead: a file with no pid (a timer of a
// tego from before the pid was written, or one whose write failed), a process gone, a pid another process has now,
// or a pid of another pid namespace. (A timer writes its pid only once it holds its lock, long after its execve set
// its command line up.) Its callers then start a timer, which exits on the timer lock when one was
// running: an exec, never a removal.
func timerRunning(d *hoststate.Dir, hash string, is func(pid int, hash string) bool) bool {
	return timerPID(d, hash, is) > 0
}

// timerPID is the pid of build hash's live timer as timerRunning reads it, 0 when none is shown: doctor's row
// (BuildInfo.TimerPID) names it.
func timerPID(d *hoststate.Dir, hash string, is func(pid int, hash string) bool) int {
	f, err := d.OpenFile("bpf-"+hash+".timer", os.O_RDONLY, 0)
	if err != nil {
		return 0
	}
	defer func() { _ = f.Close() }()
	var b [24]byte
	n, _ := f.ReadAt(b[:], 0)
	pid, err := strconv.Atoi(strings.TrimSuffix(string(b[:n]), "\n"))
	if err != nil || pid <= 0 {
		return 0
	}
	if is == nil {
		is = func(pid int, hash string) bool { return isTimerProcess(procRoot, pid, hash, 0) }
	}
	if !is(pid, hash) {
		return 0
	}
	return pid
}

// isTimerProcess reports whether process pid, under the proc filesystem at proc, is a timer of build hash: its
// command line is <exe> LingerCommand hash ..., and its real, effective, saved and filesystem uids are all uid. The
// process's directory is opened once and both files are read through it, so a pid a new process takes between the
// two reads is not mistaken for the old one: the old directory then answers an error. The uids are read from status,
// not from the directory's owner, which a process of any user makes root by making itself undumpable; a user can
// write any command line into its own process, but not those uids.
func isTimerProcess(proc string, pid int, hash string, uid uint32) bool {
	dir, err := sys.Own(unix.Open(filepath.Join(proc, strconv.Itoa(pid)), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		return false
	}
	defer func() { _ = dir.Close() }()
	cmdline, err := readProcFile(dir, "cmdline", 4<<10)
	if err != nil {
		return false
	}
	args := strings.Split(string(cmdline), "\x00")
	if len(args) < 3 || args[1] != LingerCommand || args[2] != hash {
		return false
	}
	status, err := readProcFile(dir, "status", 16<<10)
	if err != nil {
		return false
	}
	want := strconv.FormatUint(uint64(uid), 10)
	for _, line := range strings.Split(string(status), "\n") {
		rest, ok := strings.CutPrefix(line, "Uid:")
		if !ok {
			continue
		}
		ids := strings.Fields(rest)
		if len(ids) != 4 {
			return false
		}
		for _, id := range ids {
			if id != want {
				return false
			}
		}
		return true
	}
	return false
}

// readProcFile reads name under the directory dir, failing on one longer than limit.
func readProcFile(dir *sys.FD, name string, limit int64) ([]byte, error) {
	fd, err := dir.Openat(name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	f, err := fd.Release(name)
	if err != nil {
		_ = fd.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: longer than %d bytes", name, limit)
	}
	return b, nil
}

// heldOn reports whether locks lists a held flock lock on the file st describes, a write (exclusive) one only when
// write is set. It matches the device as well as the inode: two filesystems can each have the inode. A filesystem
// whose stat device is not its superblock's (a btrfs subvolume) matches nothing, which its callers read as no
// holder; on /run/tego, a tmpfs, the two are the same.
func heldOn(locks []procLock, st unix.Stat_t, write bool) bool {
	major, minor := unix.Major(uint64(st.Dev)), unix.Minor(uint64(st.Dev)) //nolint:unconvert // Dev is uint32 on some arches
	for _, l := range locks {
		if l.ino == st.Ino && l.major == major && l.minor == minor && (l.write || !write) {
			return true
		}
	}
	return false
}
