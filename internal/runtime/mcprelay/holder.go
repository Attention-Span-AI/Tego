// SPDX-License-Identifier: Apache-2.0

package mcprelay

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/peer"
)

// fdState is what a look at a process's descriptors found.
type fdState int

const (
	// fdsRead: the descriptors were listed.
	fdsRead fdState = iota
	// fdsHidden: the process hides them from this user (a process that is not dumpable, as hardened agent CLIs set with
	// PR_SET_DUMPABLE 0, has /proc/<pid>/fd owned by root): not a process that holds nothing.
	fdsHidden
	// fdsUnknown: they could not be listed for another reason, which says nothing of the process.
	fdsUnknown
)

// procView is how the relay reads the run's processes to name the one that holds a request's connection.
type procView interface {
	// Dir is the cgroup2 directory whose id is id.
	Dir(id uint64) (string, error)
	// Pids are the processes in the cgroup directory dir and below it.
	Pids(dir string) []int
	// Holds reports whether pid has a descriptor on socket inode, and how far its descriptors could be listed.
	Holds(pid int, inode uint64) (holds bool, state fdState)
	// Start is the process's start time (/proc/<pid>/stat), which with its pid names one process over time; false when it
	// cannot be read, as of a process that has gone.
	Start(pid int) (uint64, bool)
}

// realProcs is the host's /proc and cgroup tree.
type realProcs struct{}

// Dir is runCgroupDir: found by id once and kept.
func (realProcs) Dir(id uint64) (string, error) { return runCgroupDir(id) }

// Pids lists the thread-group leaders in dir and every cgroup below it (cgroup.procs, which any user may read).
func (realProcs) Pids(dir string) []int {
	var out []int
	seen := map[int]bool{}
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		b, rerr := os.ReadFile(filepath.Join(p, "cgroup.procs"))
		if rerr != nil {
			return nil
		}
		for _, f := range strings.Fields(string(b)) {
			if n, cerr := strconv.Atoi(f); cerr == nil && n > 0 && !seen[n] {
				seen[n] = true
				out = append(out, n)
			}
		}
		return nil
	})
	return out
}

// Holds reads pid's descriptor links. A permission error is a process that hides its descriptors (fdsHidden); a process
// that went while it was read holds nothing and is read as such; any other error says nothing (fdsUnknown).
func (realProcs) Holds(pid int, inode uint64) (bool, fdState) {
	dir := "/proc/" + strconv.Itoa(pid) + "/fd"
	ents, err := os.ReadDir(dir)
	switch {
	case err == nil:
	case errors.Is(err, fs.ErrPermission):
		return false, fdsHidden
	case errors.Is(err, fs.ErrNotExist) || errors.Is(err, syscall.ESRCH):
		return false, fdsRead
	default:
		return false, fdsUnknown
	}
	want := "socket:[" + strconv.FormatUint(inode, 10) + "]"
	for _, e := range ents {
		if l, err := os.Readlink(dir + "/" + e.Name()); err == nil && l == want {
			return true, fdsRead
		}
	}
	return false, fdsRead
}

func (realProcs) Start(pid int) (uint64, bool) {
	start, err := startOf(pid)
	return start, err == nil
}

// heldBy is the process found to hold one connection: its pid and start time, and how it was found. A process that hides
// its descriptors is named by exclusion (excluded): none of the run's other processes holds the socket, and this is the
// only one whose descriptors could not be read.
type heldBy struct {
	pid      int
	start    uint64
	inode    uint64
	excluded bool
}

// stillHolds is whether the connection's holder is the process it was and still holds the socket, or, for one named by
// exclusion, still hides its descriptors: a read of its start and at most one listing of its descriptors, not a new search.
func (h heldBy) stillHolds(procs procView) bool {
	if start, ok := procs.Start(h.pid); !ok || start != h.start {
		return false
	}
	holds, state := procs.Holds(h.pid, h.inode)
	if h.excluded {
		return state == fdsHidden
	}
	return holds
}

// holderSearch names the run's process that holds the socket info describes: the processes of the cgroup the socket was
// made in and below it, then of the run's cgroup and below it, each asked whether it holds the socket's inode, so the
// search lists the descriptors of the run's own processes only and never reads another user's.
//
// A process that hides its descriptors cannot be asked. When no process that can be read holds the socket and exactly
// one hides its descriptors, the socket is that one's: the connection's peer is in the run (the admission proved it
// by the socket's cgroup) and a socket is held by a process. With two such, or with any process whose descriptors could
// not be listed for another reason, none can be told from another by anything the launcher may read, and none is named:
// the caller's call is refused ask-unavailable, as a call whose holder cannot be placed always was. A pid is never guessed.
func holderSearch(procs procView, info peer.SocketInfo, runCgroup uint64) heldBy {
	if info.Inode == 0 {
		return heldBy{}
	}
	var roots []uint64
	if info.CgroupID != 0 {
		roots = append(roots, info.CgroupID)
	}
	if runCgroup != 0 && runCgroup != info.CgroupID {
		roots = append(roots, runCgroup)
	}
	checked := map[int]bool{}
	var hidden []int
	unknown := false
	for _, id := range roots {
		dir, err := procs.Dir(id)
		if err != nil {
			continue
		}
		for _, pid := range procs.Pids(dir) {
			if checked[pid] {
				continue
			}
			checked[pid] = true
			holds, state := procs.Holds(pid, info.Inode)
			switch {
			case holds:
				if start, ok := procs.Start(pid); ok {
					return heldBy{pid: pid, start: start, inode: info.Inode}
				}
			case state == fdsHidden:
				hidden = append(hidden, pid)
			case state == fdsUnknown:
				unknown = true
			}
		}
	}
	if len(hidden) == 1 && !unknown {
		if start, ok := procs.Start(hidden[0]); ok {
			return heldBy{pid: hidden[0], start: start, inode: info.Inode, excluded: true}
		}
	}
	return heldBy{}
}
