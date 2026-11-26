// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A full pool of helpers older than any check can live (ADR 0144, "A full pool of helpers older than any check can
// live is stuck", fix29). A helper slot is held by the helper that took it until that helper exits. No healthy helper
// lives longer than helperMaxLifetime: its caller abandons it at its own bounds (the start-up budget, the location
// cap, a compile's pause), which closes its pipes and ends it, unless it is stuck in the kernel on a location that
// does not answer. So a holder that is still alive past that age is stuck by definition, and when every slot a request
// may take is held by such a helper nothing the request can wait for would free one.

// helperLifetimeMargin is what a helper's age may exceed the sum of its bounds by before it counts as stuck: the time to
// fork and exec it (its start is the process's, not the check's), its caller's scheduling, and the helper's own exit.
// Ten seconds, times raceScale in a race build, as the budgets it covers are.
const helperLifetimeMargin = 10 * time.Second * raceScale

// helperMaxLifetime is the longest a healthy helper lives, from the constants of its bounds so that it cannot drift
// from them: the start-up budget, the location cap (locationCapSteps location budgets, or for a holder made for a local
// check localCapSteps), the longest a paused helper is waited for (PauseLimit, the compile's allowance) and a fixed
// margin. It uses the constants, not the variables a test swaps, so a test that shortens a budget does not shorten what
// counts as stuck.
//
// A reservation names no location, so the class of a holder in ANOTHER process is not known. The class asked about is
// the REQUEST's: a non-local request counts a holder stuck at the age it always has (so it is refused at once exactly when
// it was before the local wait existed), and a local request, whose own checks may legitimately hold a slot ten
// seconds longer, counts a holder stuck only past the longer lifetime, and so waits its start-up budget for a holder
// that is aged between the two. That is the only place a request of any class can wait longer, and it is the local class's.
func helperMaxLifetime(local bool) time.Duration {
	steps := locationCapSteps
	if local {
		steps = localCapSteps
	}
	return StartTimeout + time.Duration(steps)*CheckTimeout + PauseLimit + helperLifetimeMargin
}

// holderStarts says, for each reservation name, when the process that holds it started, as the time since boot (the
// scale of the clock below). A name with no entry has a holder that cannot be identified, or whose start cannot be
// read; an error means nothing could be identified at all. A test replaces it.
type holderStarts func(names []string) (map[string]time.Duration, error)

var readHolders holderStarts = procHolderStarts

// sinceBoot is the clock a holder's age is read against: the time since boot, on the scale of a process's start time.
// A test replaces it.
var sinceBoot = monotonicSinceBoot

// monotonicSinceBoot is CLOCK_MONOTONIC. /proc/<pid>/stat counts a process's start from boot including the time the
// machine was suspended (since Linux 5.5; before it, excluding it), and CLOCK_MONOTONIC never counts that time, so
// the age it gives is at most the real one, and exactly it on a machine that was never suspended: a holder is never
// judged older than it is.
func monotonicSinceBoot() (time.Duration, error) {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0, err
	}
	return time.Duration(ts.Nano()), nil
}

// holdersStuckForGood reports whether every one of names, the reservation names of slots held by helpers nothing else
// is known about, is held by a process that is identified and older than helperMaxLifetime. Any holder that is younger
// (or exactly as old), or whose start time cannot be read, or that cannot be identified, makes it false: the wait stays.
func holdersStuckForGood(names []string, local bool) bool {
	if len(names) == 0 {
		return false
	}
	starts, err := readHolders(names)
	if err != nil {
		return false
	}
	now, err := sinceBoot()
	if err != nil {
		return false
	}
	limit := helperMaxLifetime(local)
	for _, name := range names {
		start, ok := starts[name]
		if !ok || now-start <= limit {
			return false
		}
	}
	return true
}

// procHolderStarts finds the holders of the reservation names and reads their start times. A reservation is an
// abstract UNIX socket in this network namespace; the helper that holds it keeps it as its standard error (fd 2, see
// reserveHelper), and its worker takes a lock on it (holdReservation). /proc/net/unix names the socket's inode, and two
// things name the pid that holds it: /proc/locks gives the pid that locked the socket (a helper is undumpable, so no
// other process of the user may read its descriptors, but the lock table is not hidden by that), and /proc/<pid>/fd/2
// of each process gives the inode it holds there (a holder that is dumpable, or read by a process with the right to).
// /proc/<pid>/stat of that pid alone gives the start time. A slot held by a process that neither is named by a lock nor
// has a standard error this process may read, in another pid namespace, or as another descriptor, is not found: it has
// no entry and the wait stays. When several processes hold the socket (the launcher beside its worker) the youngest
// decides, as the slot is free only when the last of them is gone. A process that appeared after the socket list was
// read cannot hold a name that was already taken, and a pid that was reused is younger than the holder it replaces, so
// it only keeps the wait.
func procHolderStarts(names []string) (map[string]time.Duration, error) {
	inodes, err := reservationInodes(names)
	if err != nil {
		return nil, err
	}
	byInode := map[string]string{}
	for name, inode := range inodes {
		byInode["socket:["+inode+"]"] = name
	}
	holders := map[int]string{} // pid -> the reservation name it holds
	for pid, name := range lockHolders(inodes) {
		holders[pid] = name
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil || pid <= 0 {
			continue
		}
		link, err := os.Readlink("/proc/" + e.Name() + "/fd/2")
		if err != nil {
			continue
		}
		if name, ok := byInode[link]; ok {
			holders[pid] = name
		}
	}
	starts := map[string]time.Duration{}
	unreadable := map[string]bool{}
	for pid, name := range holders {
		start, ok := holderStart(pid)
		if !ok {
			unreadable[name] = true
			continue
		}
		if cur, seen := starts[name]; !seen || start > cur {
			starts[name] = start
		}
	}
	for name := range unreadable {
		delete(starts, name)
	}
	return starts, nil
}

// holdReservation locks the reservation this helper holds as its standard error, the way the lock table names its
// holder to a process that may not read this one's descriptors (an undumpable process hides them from every reader
// without CAP_SYS_PTRACE, and the table of locks is not hidden). The lock is on the socket's open file description, so it
// goes with the last descriptor that holds the reservation, as the slot does. A kernel without file locking, or any
// other refusal, leaves the holder as unidentified as it was: the wait stays.
func holdReservation() {
	var st unix.Stat_t
	if unix.Fstat(2, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return // not a reservation: never lock a terminal or a file somebody else holds
	}
	_ = unix.Flock(2, unix.LOCK_EX|unix.LOCK_NB)
}

// maxLockTable bounds the read of /proc/locks. A table cut short only leaves holders unidentified: the wait stays.
const maxLockTable = 8 << 20

// sockfsDevice is the device of the kernel's socket filesystem as /proc/locks prints a lock's device ("%02x:%02x",
// major and minor), read from a socket this process makes. A reservation is a socket, so a lock that names it names
// this device too; a lock on a file of another filesystem whose inode number happens to equal a socket's is not the
// reservation's. "" when no socket can be made or read: then no lock names a holder, and the wait stays.
func sockfsDevice() string {
	s, err := sys.Own(unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0))
	if err != nil {
		return ""
	}
	defer func() { _ = s.Close() }()
	var st unix.Stat_t
	if s.Fstat(&st) != nil {
		return ""
	}
	dev := uint64(st.Dev) //nolint:unconvert // Stat_t.Dev is not uint64 on every architecture
	return fmt.Sprintf("%02x:%02x", unix.Major(dev), unix.Minor(dev))
}

// lockHolders reads /proc/locks, the file locks of the machine, and returns for each pid that holds a flock on one of
// the reservation sockets (inodes: name to the socket's inode) the name of the reservation. A lock counts only on the
// socket filesystem's device (sockfsDevice) and the socket's inode number. The pid is the one the reader's pid
// namespace names; a holder in a namespace it cannot see is given as 0 and is left out. A lock that is only waited for
// (a line with "->") holds nothing.
func lockHolders(inodes map[string]string) map[int]string {
	dev := sockfsDevice()
	if dev == "" {
		return nil
	}
	file, err := os.Open("/proc/locks")
	if err != nil {
		return nil
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, maxLockTable))
	if err != nil {
		return nil
	}
	byInode := map[string]string{}
	for name, inode := range inodes {
		byInode[inode] = name
	}
	out := map[int]string{}
	for _, line := range strings.Split(string(data), "\n") {
		// 1: FLOCK  ADVISORY  WRITE 1218142 00:09:945382108 0 EOF
		f := strings.Fields(line)
		if len(f) < 6 || f[1] != "FLOCK" {
			continue
		}
		id := strings.Split(f[5], ":")
		if len(id) != 3 || id[0]+":"+id[1] != dev {
			continue
		}
		name, ok := byInode[id[2]]
		if !ok {
			continue
		}
		if pid, err := strconv.Atoi(f[4]); err == nil && pid > 0 {
			out[pid] = name
		}
	}
	return out
}

// holderStart is the start time of the process pid (/proc/<pid>/stat, that pid only), as the time since boot.
func holderStart(pid int) (time.Duration, bool) {
	ticks := processStart(pid)
	if ticks == 0 {
		return 0, false
	}
	return time.Duration(ticks * proc.NanosPerTick), true
}

// reservationInodes reads /proc/net/unix, the sockets of this network namespace, and returns the inode of each of names
// that is there. The names are written there with the abstract socket's leading NUL as '@', as reserveHelper gives them.
func reservationInodes(names []string) (map[string]string, error) {
	data, err := os.ReadFile("/proc/net/unix")
	if err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, name := range names {
		want[name] = true
	}
	inodes := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		// Num RefCount Protocol Flags Type St Inode Path
		f := strings.Fields(line)
		if len(f) < 8 || !want[f[7]] {
			continue
		}
		if _, err := strconv.ParseUint(f[6], 10, 64); err != nil {
			return nil, fmt.Errorf("malformed /proc/net/unix line %q", line)
		}
		inodes[f[7]] = f[6]
	}
	return inodes, nil
}
