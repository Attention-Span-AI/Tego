// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// Errors of the /proc readers. Every one of them describes a process that has already exited or a file the
// kernel formatted differently than expected; none is fatal to a run (§7: a /proc read racing an exited pid
// degrades attribution, it does not stop anything).
var (
	// ErrProcGone is returned when the process disappeared between the event and the read.
	ErrProcGone = errors.New("cgroup: process is gone")
	// ErrProcFormat is returned when a /proc file does not have the shape its documentation promises.
	ErrProcFormat = errors.New("cgroup: unexpected /proc format")
)

// owner identifies a launcher process precisely enough to outlive pid reuse: a pid plus the start time the
// kernel reports for it. A slot whose owner's start time no longer matches is a slot whose owner died and
// whose pid was reused, and it is free.
type owner struct {
	PID        uint32
	StartTicks uint64
}

// alive reports whether the owner's process still exists with the same start time and has not exited. A pid of
// zero is never alive, which is what makes a zeroed slot record free.
func (o owner) alive() bool {
	return o.aliveBy(liveStartTicks)
}

// aliveBy is alive over a given reader of a pid's start ticks. Only ErrProcGone says the owner died: any other
// failure (a transient ENFILE or ENOMEM, a /proc line not parsed) says nothing of it, so the owner counts as
// alive and its slot is kept. Taken for dead, its slot would go to a second launcher while the first's rows
// and rings are live, which mixes two runs' policy or purges the first's rows.
func (o owner) aliveBy(startTicks func(int) (uint64, error)) bool {
	if o.PID == 0 {
		return false
	}
	ticks, err := startTicks(int(o.PID))
	if err != nil {
		return !errors.Is(err, ErrProcGone)
	}
	return ticks == o.StartTicks
}

// selfOwner returns this process's owner identity. It is ErrPidNamespace outside the initial pid namespace: an
// owner is a pid read in this process's /proc, and every launcher on the host shares the slot table, so the
// identities in it are good only where every launcher's pids are the same namespace's (§7).
func selfOwner() (owner, error) {
	if err := initialPidNamespace(selfPidNamespace); err != nil {
		return owner{}, err
	}
	pid := os.Getpid()
	ticks, err := procStartTicks(pid)
	if err != nil {
		return owner{}, err
	}
	return owner{PID: uint32(pid), StartTicks: ticks}, nil
}

// selfPidNamespace names this process's pid namespace; procPidInitIno is the inode the kernel gives the initial
// one (PROC_PID_INIT_INO, include/linux/proc_ns.h).
const (
	selfPidNamespace = "/proc/self/ns/pid"
	procPidInitIno   = 0xEFFFFFFC
)

// initialPidNamespace is ErrPidNamespace unless ns (a /proc/<pid>/ns/pid link) is the initial pid namespace. A
// link that cannot be read is refused as well: nothing then shows the pids to be the host's.
func initialPidNamespace(ns string) error {
	var st unix.Stat_t
	if err := unix.Stat(ns, &st); err != nil {
		return fmt.Errorf("%w: stat %s: %w", ErrPidNamespace, ns, err)
	}
	if st.Ino != procPidInitIno {
		return fmt.Errorf("%w: %s is pid namespace %d; tier 2 runs from the host's", ErrPidNamespace, ns, st.Ino)
	}
	return nil
}

// procStartTicks reads field 22 of /proc/<pid>/stat, the process's start time in clock ticks since boot.
func procStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return 0, fmt.Errorf("%w: pid %d", ErrProcGone, pid)
		}
		return 0, fmt.Errorf("cgroup: read /proc/%d/stat: %w", pid, err)
	}
	return parseStartTicks(data)
}

// liveStartTicks is procStartTicks for a process that has not exited: a zombie no parent has reaped yet keeps its
// /proc/<pid>/stat with the same start ticks, so a launcher killed under a parent that waits late still read as
// alive, and its slot was neither purged nor reclaimed until the parent reaped it. State X (dead), and state Z
// with one thread, are ErrProcGone. A zombie leader with live threads (num_threads above one, since the count
// drops only at reaping) is a process that still runs and stays alive.
func liveStartTicks(pid int) (uint64, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return 0, fmt.Errorf("%w: pid %d", ErrProcGone, pid)
		}
		return 0, fmt.Errorf("cgroup: read /proc/%d/stat: %w", pid, err)
	}
	return liveTicksOf(pid, data)
}

// liveTicksOf is liveStartTicks over the /proc/<pid>/stat line data.
func liveTicksOf(pid int, data []byte) (uint64, error) {
	st, err := proc.ParseStat(data)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrProcFormat, err)
	}
	if st.State == 'X' || (st.State == 'Z' && st.NumThreads <= 1) {
		return 0, fmt.Errorf("%w: pid %d has exited (state %c)", ErrProcGone, pid, st.State)
	}
	return st.StartTicks, nil
}

// parseStartTicks extracts the start time, in ticks, from a /proc/<pid>/stat line. It goes through
// proc.ParseStat, the one fuzzed parser of that line, so a slot owner's identity is read exactly as the lock
// file and an exec id read it; a malformed line is ErrProcFormat wrapping proc.ErrStat.
func parseStartTicks(data []byte) (uint64, error) {
	st, err := proc.ParseStat(data)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", ErrProcFormat, err)
	}
	return st.StartTicks, nil
}

// cgroupPathOfPID returns the cgroup v2 path of a process, as /proc/<pid>/cgroup reports it: an absolute path
// relative to the cgroup2 mount, such as "/user.slice/user-1000.slice/.../run-abc.scope".
//
// This is the lookup the fanotify listener does per permission event, because a fanotify event names a pid
// and the run is a cgroup subtree (§5 fanotify rules).
func cgroupPathOfPID(pid int) (string, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ESRCH) {
			return "", fmt.Errorf("%w: pid %d", ErrProcGone, pid)
		}
		return "", fmt.Errorf("cgroup: read /proc/%d/cgroup: %w", pid, err)
	}
	return parseCgroupFile(data)
}

// parseCgroupFile extracts the unified hierarchy's path from a /proc/<pid>/cgroup file. The v2 line is the
// one with hierarchy id 0 and an empty controller list ("0::/path"); v1 lines are ignored. The file is
// kernel-formatted but is parsed defensively because it is read for a pid the run does not control.
func parseCgroupFile(data []byte) (string, error) {
	for line := range strings.SplitSeq(strings.TrimRight(string(data), "\n"), "\n") {
		id, rest, ok := strings.Cut(line, ":")
		if !ok || id != "0" {
			continue
		}
		controllers, path, ok := strings.Cut(rest, ":")
		if !ok || controllers != "" {
			continue
		}
		if path == "" || !strings.HasPrefix(path, "/") {
			return "", fmt.Errorf("%w: unified line has path %q", ErrProcFormat, path)
		}
		// The kernel appends " (deleted)" for a removed cgroup a task is still in.
		path = strings.TrimSuffix(path, " (deleted)")
		return path, nil
	}
	return "", fmt.Errorf("%w: no unified (0::) line", ErrProcFormat)
}

// inSubtree reports whether a cgroup path is the run's own cgroup or one nested beneath it. This is the
// membership test the fanotify listener uses: it needs no kernel map, so a listener decision never depends on
// the run set being current.
func inSubtree(runPath, candidate string) bool {
	if runPath == "" || candidate == "" {
		return false
	}
	runPath = strings.TrimSuffix(runPath, "/")
	if candidate == runPath {
		return true
	}
	return strings.HasPrefix(candidate, runPath+"/")
}

// cgroupIDOfPath returns the 64-bit cgroup id of a path under the cgroup2 mount — the value
// bpf_get_current_cgroup_id() reports, the run set is keyed by, and Attach keys the run's tego_net_owners
// storage by. On cgroup2 that is the directory's inode number, which is exactly what the kernfs node id
// carries.
func cgroupIDOfPath(mount, path string) (uint64, error) {
	full := mount + path
	var st unix.Stat_t
	if err := unix.Stat(full, &st); err != nil {
		return 0, fmt.Errorf("cgroup: stat %s: %w", full, err)
	}
	return st.Ino, nil
}
