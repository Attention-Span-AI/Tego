// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
)

// threadLimit is one bound on how many more OS threads this process can create, and what imposes it.
type threadLimit struct {
	headroom int64
	source   string
}

// threadBudget is the smallest headroom among the limits that make thread creation fail, measured once when a
// listener starts (§6 E34). Each of them ends the launcher the same way: Go's runtime aborts past
// runtime/debug.SetMaxThreads, and it also aborts ("failed to create new OS thread", throw("newosproc")) when
// clone(2) fails, which it does with EAGAIN at a pids.max anywhere on the launcher's own cgroup chain or at
// kernel.threads-max. An abort runs no teardown, so whichever of these is nearest is the one the overdue
// ceiling has to stay clear of.
//
// RLIMIT_NPROC is not measured, because it cannot bind here: copy_process lets a task holding CAP_SYS_ADMIN
// or CAP_SYS_RESOURCE past it, and this listener exists only in a process holding CAP_SYS_ADMIN, which
// fanotify_init requires for FAN_CLASS_CONTENT.
//
// The measurement is a snapshot. Tasks that the rest of the launcher, or anything else in the launcher's
// cgroup, adds after the listener starts come out of the same headroom, which is why overdueCeilingFor keeps
// only half of what the listener's own worst case leaves.
func threadBudget(procRoot, cgroupRoot string) threadLimit {
	goLimit := goMaxThreads()
	best := threadLimit{headroom: int64(goLimit), source: fmt.Sprintf("the Go runtime's %d-thread limit", goLimit)}
	if n, ok := readStatusThreads(filepath.Join(procRoot, "self", "status")); ok {
		best.headroom -= n
	}
	for _, l := range append(pidsLimits(procRoot, cgroupRoot), threadsMaxLimit(procRoot)...) {
		if l.headroom < best.headroom {
			best = l
		}
	}
	return best
}

// maxThreadsMu serializes goMaxThreads: two overlapping read-and-restore swaps could restore each other's
// temporary value and leave the runtime's limit raised for good.
var maxThreadsMu sync.Mutex

// goMaxThreads reads the Go runtime's thread limit. SetMaxThreads returns the limit it replaces, and is the
// only way to read it; raising it for an instant and restoring it never lowers it below the threads that
// already exist, which would abort.
func goMaxThreads() int {
	maxThreadsMu.Lock()
	defer maxThreadsMu.Unlock()
	limit := debug.SetMaxThreads(math.MaxInt32)
	debug.SetMaxThreads(limit)
	return limit
}

// pidsLimits returns the pids.max headroom of every level of this process's own cgroup that has one. The
// limit is hierarchical: a clone fails when any ancestor's pids.current would pass its pids.max, so each
// level counts and the smallest wins. A level without the pids controller has no files and no limit.
func pidsLimits(procRoot, cgroupRoot string) []threadLimit {
	data, err := os.ReadFile(filepath.Join(procRoot, "self", "cgroup"))
	if err != nil {
		return nil
	}
	path, err := parseCgroupFile(data)
	if err != nil {
		return nil
	}
	var out []threadLimit
	for dir := path; ; dir = filepath.Dir(dir) {
		full := filepath.Join(cgroupRoot, dir)
		maxRaw, errMax := os.ReadFile(filepath.Join(full, "pids.max"))
		curRaw, errCur := os.ReadFile(filepath.Join(full, "pids.current"))
		if errMax == nil && errCur == nil {
			maxText := strings.TrimSpace(string(maxRaw))
			if maxText != "max" {
				limit, errL := strconv.ParseInt(maxText, 10, 64)
				cur, errC := strconv.ParseInt(strings.TrimSpace(string(curRaw)), 10, 64)
				if errL == nil && errC == nil {
					out = append(out, threadLimit{
						headroom: limit - cur,
						source:   fmt.Sprintf("pids.max %d of %s (pids.current %d)", limit, full, cur),
					})
				}
			}
		}
		if dir == "/" || dir == "." {
			return out
		}
	}
}

// threadsMaxLimit returns kernel.threads-max less the threads that exist, which is the fourth field of
// /proc/loadavg ("running/total"). Either file can be masked in a container; then this limit is not known
// and the others decide.
func threadsMaxLimit(procRoot string) []threadLimit {
	maxRaw, err := os.ReadFile(filepath.Join(procRoot, "sys", "kernel", "threads-max"))
	if err != nil {
		return nil
	}
	limit, err := strconv.ParseInt(strings.TrimSpace(string(maxRaw)), 10, 64)
	if err != nil {
		return nil
	}
	load, err := os.ReadFile(filepath.Join(procRoot, "loadavg"))
	if err != nil {
		return nil
	}
	fields := strings.Fields(string(load))
	if len(fields) < 4 {
		return nil
	}
	_, total, ok := strings.Cut(fields[3], "/")
	if !ok {
		return nil
	}
	n, err := strconv.ParseInt(total, 10, 64)
	if err != nil {
		return nil
	}
	return []threadLimit{{headroom: limit - n, source: fmt.Sprintf("kernel.threads-max %d (%d threads exist)", limit, n)}}
}

// readStatusThreads reads the Threads: line of a /proc/<pid>/status file.
func readStatusThreads(path string) (int64, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if rest, ok := strings.CutPrefix(line, "Threads:"); ok {
			n, err := strconv.ParseInt(strings.TrimSpace(rest), 10, 64)
			return n, err == nil
		}
	}
	return 0, false
}

// errThreadBudget is wrapped in ErrFanotify when a listener could not stay clear of the nearest thread limit
// even with the smallest ceiling it may run with.
var errThreadBudget = errors.New("thread budget too small for the fanotify listener")

// overdueCeilingFor sizes the overdue ceiling to a measured thread budget (§6 E34). loop() checks the count
// between reads, so it can pass the ceiling by fanOverdueOvershoot before it stops; the ceiling is whatever
// keeps ceiling + overshoot inside half of the headroom, and never more than fanotifyOverdueCeiling.
//
// Below fanotifyWorkers the listener refuses to start rather than run with a ceiling one deadline's worth of
// stalls would already cross: a budget that small cannot hold even one round of the pool's own stalls plus
// the overshoot, and a listener started anyway risks exactly the no-teardown abort the ceiling exists to
// prevent. Refusing fails Prepare, and the run with it, before the agent starts (fail-closed).
func overdueCeilingFor(budget threadLimit) (int64, error) {
	ceiling := min(int64(fanotifyOverdueCeiling), (budget.headroom/2)-fanOverdueOvershoot)
	if ceiling < fanotifyWorkers {
		return 0, fmt.Errorf("%w: %d more threads can be created, bound by %s; a listener needs at least %d "+
			"(twice its ceiling floor of %d plus the %d decisions one read can leave overdue past it)",
			errThreadBudget, budget.headroom, budget.source, 2*(fanotifyWorkers+fanOverdueOvershoot),
			fanotifyWorkers, fanOverdueOvershoot)
	}
	return ceiling, nil
}
