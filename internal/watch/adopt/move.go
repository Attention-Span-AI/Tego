// SPDX-License-Identifier: Apache-2.0

package adopt

import (
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// CgroupFS is the cgroup filesystem an adoption writes. Every path is absolute (under the cgroup2 mount).
type CgroupFS interface {
	// Add moves pid's whole process (every thread) into dir: one write of the pid to dir/cgroup.procs.
	Add(dir string, pid int) error
	// Procs lists dir's cgroup.procs.
	Procs(dir string) ([]int, error)
	// Threads lists dir's cgroup.threads: the live tasks in dir, of every process. A process whose leader exited
	// while its other threads run is listed in cgroup.procs where its leader stayed, not where its threads were moved
	// (proc.Stat.LeaderExited), so only this listing finds it there.
	Threads(dir string) ([]int, error)
	// Freeze writes dir's cgroup.freeze: frozen, no process in dir runs (and none forks) until it is thawed.
	Freeze(dir string, frozen bool) error
	// Exists reports whether dir is a cgroup.
	Exists(dir string) bool
}

// Liveness tells, without being a process's parent, whether it has exited: a pidfd.
type Liveness interface {
	Watch(pid int) (Watch, error)
}

// Watch is a hold on one process instance, taken by pid.
type Watch interface {
	// Exited reports whether the process the watch was taken on has exited.
	Exited() bool
	Close() error
}

// Env is what Move and Release read and write.
type Env struct {
	Proc Proc
	FS   CgroupFS
	Live Liveness
	// Mount is the cgroup2 mount the relative cgroup paths of /proc are under; "" is /sys/fs/cgroup.
	Mount string
}

func (e Env) mount() string {
	if e.Mount == "" {
		return "/sys/fs/cgroup"
	}
	return e.Mount
}

// abs is a /proc cgroup path under the mount.
func (e Env) abs(rel string) string { return filepath.Join(e.mount(), rel) }

// rel is an absolute cgroup directory as /proc names it.
func (e Env) rel(abs string) string {
	r := strings.TrimPrefix(filepath.Clean(abs), filepath.Clean(e.mount()))
	if r == "" {
		return "/"
	}
	return r
}

// MaxRounds bounds Move's passes. Each pass moves what the last left in the source cgroup (children forked by a
// member before that member moved); an agent whose tree keeps growing faster than it is moved is left with the rest
// counted, not chased for ever.
const MaxRounds = 16

// MoveResult is what Move did.
type MoveResult struct {
	// Moved are the processes moved, in order: root first, then each one after its parent.
	Moved []Process
	// Skipped are the processes of the tree not moved, and why.
	Skipped []Skip
	// Rounds is how many passes over /proc it took.
	Rounds int
	// Left counts members still in the source cgroup when the passes ran out.
	Left int
	// Misplaced are pids written to the run's cgroup.procs that, by the time the write was checked, named a process
	// other than the member identified (the member exited and its pid was reused within the write): each was moved
	// back to its parent's cgroup at once.
	Misplaced []int
}

// Move moves root's tree into dest, an existing cgroup directory (absolute): root first, then every descendant
// still in root's cgroup (root.Cgroup), each after its parent, and again over a fresh /proc snapshot until no member
// is left there or MaxRounds pass. extra are identities of descendants the caller followed by fork events.
//
// Each move re-checks the member's identity right before the write: a pidfd is taken, the start time is read, and
// only a process whose start time is still the one it was identified with, and still in root's cgroup, is written.
// A root that fails it moves nothing, and Move returns ErrIdentityChanged; a member that fails it is skipped. After
// the write the pidfd says whether that process is still alive, which proves the pid the kernel moved was its own;
// one that exited is checked again, and a pid found reused is moved back to its parent's cgroup (Misplaced).
func Move(env Env, dest string, root Process, extra []Identity) (MoveResult, error) {
	var res MoveResult
	from, to := root.Cgroup, env.rel(dest)
	if from == to {
		return res, fmt.Errorf("adopt: pid %d is already in %s", root.PID, dest)
	}
	skipped := map[int]bool{}
	for round := 1; round <= MaxRounds; round++ {
		res.Rounds = round
		todo, skips, err := walk(env.Proc, root.Identity, from, to, extra)
		if err != nil {
			if round == 1 {
				return res, err
			}
			break // the root exited: what moved stays moved, its tree has nothing left to grow
		}
		for _, s := range skips {
			if !skipped[s.PID] {
				skipped[s.PID] = true
				res.Skipped = append(res.Skipped, s)
			}
		}
		var fresh []Process
		for _, t := range todo {
			if !skipped[t.PID] {
				fresh = append(fresh, t)
			}
		}
		if len(fresh) == 0 {
			return res, nil
		}
		if round == MaxRounds {
			res.Left = len(fresh)
			break
		}
		for _, t := range fresh {
			why, misplaced, err := moveOne(env, dest, from, t)
			if misplaced {
				res.Misplaced = append(res.Misplaced, t.PID)
			}
			if why != "" && t.PID == root.PID && len(res.Moved) == 0 {
				// The root goes first: one that does not move leaves the whole tree where it is.
				if err == nil {
					err = fmt.Errorf("adopt: pid %d: %s", t.PID, why)
				}
				return res, err
			}
			if why != "" {
				skipped[t.PID] = true
				res.Skipped = append(res.Skipped, Skip{PID: t.PID, Why: why})
				continue
			}
			res.Moved = append(res.Moved, t)
		}
	}
	return res, nil
}

// moveOne moves one identified process into dest, from from (relative), with the identity checks Move describes. It
// returns why it did not move it ("" when it did), whether the write landed on another process, and, for the root's
// identity failing, ErrIdentityChanged.
func moveOne(env Env, dest, from string, t Process) (why string, misplaced bool, err error) {
	w, err := env.Live.Watch(t.PID)
	if err != nil {
		return SkipGone, false, fmt.Errorf("adopt: pid %d: %w", t.PID, ErrGone)
	}
	defer func() { _ = w.Close() }()
	st, err := env.Proc.Stat(t.PID)
	switch {
	case err != nil:
		return SkipGone, false, fmt.Errorf("adopt: pid %d: %w", t.PID, ErrGone)
	case st.StartTicks != t.Start || st.Gone():
		return SkipReused, false, fmt.Errorf("%w: pid %d started at %d, identified at %d", ErrIdentityChanged, t.PID,
			st.StartTicks, t.Start)
	}
	if cg, err := cgroupOf(env.Proc, t.PID, st); err != nil || cg != from {
		return SkipOtherCgroup + " (" + cg + ")", false, nil
	}
	if err := env.FS.Add(dest, t.PID); err != nil {
		if errors.Is(err, syscall.ESRCH) {
			return SkipGone, false, nil
		}
		return SkipMoveFailed + ": " + err.Error(), false, nil
	}
	if !w.Exited() {
		return "", false, nil // alive throughout: its pid could not have been reused, so the write moved it
	}
	// It exited around the write. The pid may name a process born since, which the write moved instead.
	st2, err := env.Proc.Stat(t.PID)
	if err != nil || st2.StartTicks == t.Start {
		return SkipGone, false, nil
	}
	if cg, err := CgroupOf(env.Proc, t.PID); err == nil && cg == env.rel(dest) {
		if pst, err := CgroupOf(env.Proc, st2.PPID); err == nil {
			_ = env.FS.Add(env.abs(pst), t.PID)
		}
		return SkipReused, true, nil
	}
	return SkipGone, false, nil
}

// ReleaseResult is what Release did.
type ReleaseResult struct {
	// To maps each cgroup (absolute) processes went to, to their pids.
	To map[string][]int
	// Left are the processes still in the run's cgroup: none of the targets took them.
	Left []int
	// Frozen says the run's cgroup was frozen while its processes left (cgroup.freeze, Linux 5.2+).
	Frozen bool
	// Misplaced are pids whose write, by the time it was checked, had moved a process other than the member read from
	// the scope (the member exited and its pid was reused within the write): each was put back in its parent's cgroup.
	Misplaced []int
}

// releaseRounds bounds Release's passes over a frozen cgroup: a process can still be forking as the freeze lands.
const releaseRounds = 8

// Release moves every process with a live thread in dest (absolute; scopeProcs, so one whose leader exited and stayed
// elsewhere too) to the first of targets (absolute) that takes it. dest is
// frozen first, so no process in it forks or execs while they leave, and thawed after; a process thaws as it
// arrives in an unfrozen cgroup. Release never signals a process, and it leaves one no target takes where it is.
//
// The pid of each process scopeProcs finds (the thread group of a task dest's cgroup.threads lists) is written as root,
// and a member can still die meanwhile (SIGKILL reaches a frozen process, and with no cgroup.freeze nothing holds the
// tree): each is held by a pidfd first, and written only while that process is still in dest by the cgroup of a live
// thread of it (cgroupOf: a leader that exited elsewhere keeps naming that cgroup); after the write the pidfd says
// whether it was alive throughout, and a write that landed on a pid reused within it is put back in its parent's
// cgroup (Misplaced), as Move does. So no unrelated process, of any user, is moved by a release.
func Release(env Env, dest string, targets []string) ReleaseResult {
	res := ReleaseResult{To: map[string][]int{}}
	if err := env.FS.Freeze(dest, true); err == nil {
		res.Frozen = true
		defer func() { _ = env.FS.Freeze(dest, false) }()
	}
	from := env.rel(dest)
	for range releaseRounds {
		pids, err := scopeProcs(env, dest)
		if err != nil || len(pids) == 0 {
			break
		}
		moved := 0
		for _, pid := range pids {
			to, done, misplaced := releaseOne(env, from, pid, targets)
			if to != "" {
				res.To[to] = append(res.To[to], pid)
			}
			if misplaced {
				res.Misplaced = append(res.Misplaced, pid)
			}
			if done {
				moved++
			}
		}
		if moved == 0 {
			break
		}
	}
	res.Left, _ = scopeProcs(env, dest)
	return res
}

// releaseOne moves one pid read from the scope (from, relative) to the first target that takes it, with the checks
// Release describes. to is where it went ("" when it did not move); done says the pid needs nothing more (moved, gone,
// or no longer in the scope); misplaced that the write moved another process, which was put back.
func releaseOne(env Env, from string, pid int, targets []string) (to string, done, misplaced bool) {
	w, err := env.Live.Watch(pid)
	if err != nil {
		return "", true, false // gone: nothing to move
	}
	defer func() { _ = w.Close() }()
	st, err := env.Proc.Stat(pid)
	if err != nil || st.Gone() {
		return "", true, false
	}
	if cg, err := cgroupOf(env.Proc, pid, st); err != nil || cg != from {
		return "", true, false // it left the scope by itself, or the pid already names another process
	}
	for _, t := range targets {
		if !env.FS.Exists(t) {
			continue
		}
		err := env.FS.Add(t, pid)
		if errors.Is(err, syscall.ESRCH) {
			return "", true, false
		}
		if err != nil {
			continue
		}
		if !w.Exited() {
			return t, true, false // alive throughout: the write moved the process held
		}
		// It exited around the write. The pid may name a process born since, which the write moved instead.
		st2, err := env.Proc.Stat(pid)
		if err != nil || st2.StartTicks == st.StartTicks {
			return "", true, false
		}
		if cg, err := CgroupOf(env.Proc, pid); err == nil && cg == env.rel(t) {
			if pcg, err := CgroupOf(env.Proc, st2.PPID); err == nil {
				_ = env.FS.Add(env.abs(pcg), pid)
			}
			return "", true, true
		}
		return "", true, false
	}
	return "", false, false
}

// ReleaseTargets are where Release sends an adopted tree back: the cgroup it came from (relative from), then its
// ancestors up to, but not including, the cgroup2 root, for a source that is gone (its scope ended with the session
// that made it); the kernel refuses a parent that has controllers enabled for its children, and the next is tried.
// The root cgroup is never one: a process left where no target takes it stays in the adoption's cgroup, released.
func ReleaseTargets(mount, from string) []string {
	var out []string
	for p := path.Clean("/" + from); p != "/"; p = path.Dir(p) {
		out = append(out, filepath.Join(mount, p))
	}
	return out
}

// Cgroups is the system's cgroup filesystem as a CgroupFS.
type Cgroups struct{}

// Add writes pid to dir/cgroup.procs.
func (Cgroups) Add(dir string, pid int) error {
	f, err := os.OpenFile(filepath.Join(dir, "cgroup.procs"), os.O_WRONLY, 0)
	if err != nil {
		return err
	}
	_, werr := f.WriteString(strconv.Itoa(pid))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	return werr
}

// Procs reads dir/cgroup.procs.
func (Cgroups) Procs(dir string) ([]int, error) { return readIDs(filepath.Join(dir, "cgroup.procs")) }

// Threads reads dir/cgroup.threads.
func (Cgroups) Threads(dir string) ([]int, error) {
	return readIDs(filepath.Join(dir, "cgroup.threads"))
}

// readIDs reads a cgroup file of one id per line.
func readIDs(path string) ([]int, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []int
	for _, f := range strings.Fields(string(b)) {
		if n, err := strconv.Atoi(f); err == nil {
			out = append(out, n)
		}
	}
	return out, nil
}

// Freeze writes dir/cgroup.freeze.
func (Cgroups) Freeze(dir string, frozen bool) error {
	v := "0"
	if frozen {
		v = "1"
	}
	return os.WriteFile(filepath.Join(dir, "cgroup.freeze"), []byte(v), 0)
}

// Exists reports whether dir is a directory holding a cgroup.procs.
func (Cgroups) Exists(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, "cgroup.procs"))
	return err == nil
}

// Pidfds is the system's pidfd_open as a Liveness.
type Pidfds struct{}

// Watch opens a pidfd on pid.
func (Pidfds) Watch(pid int) (Watch, error) {
	fd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		return nil, err
	}
	return pidfdWatch(fd), nil
}

type pidfdWatch int

// Exited polls the pidfd without waiting: it is readable once the process has exited.
func (w pidfdWatch) Exited() bool {
	for {
		n, err := unix.Poll([]unix.PollFd{{Fd: int32(w), Events: unix.POLLIN}}, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err == nil && n > 0
	}
}

func (w pidfdWatch) Close() error { return unix.Close(int(w)) }
