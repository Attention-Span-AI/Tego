// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// TreeFigure is a measurement of work that may run in this process and in child processes it starts: the CPU time of
// the whole process tree, and the wall clock beside it.
type TreeFigure struct {
	// CPU is the CPU time, user and system, of every thread of this process and of every child process the work
	// started and had waited for by the time MinOfTree returns it: the work itself, with every wait left out, the
	// scheduler's and the code's own alike. Another tenant's slice and a full run queue do not count, so it measures
	// the code, not the machine's load at the moment (a busy machine still slows the CPU's own speed: a lower clock,
	// a busy sibling hyperthread).
	CPU time.Duration
	// Wall is the fastest wall clock of the rounds, which holds every wait a read makes and every wait the machine adds.
	Wall time.Duration
	// Samples is how many rounds the figures are the fastest of.
	Samples int
}

// childrenWait is how long MinOfTree waits for a round's child processes to end and be waited for.
const childrenWait = 10 * time.Second

// prSetChildSubreaper is PR_SET_CHILD_SUBREAPER; the syscall package does not name it.
const prSetChildSubreaper = 36

// MinOfTree runs each of fns rounds times, the order rotated from round to round (as MinOf does, so that a change in
// the machine's load over the measurement is on every side alike), and returns each one's fastest CPU time of the
// process tree and fastest wall clock. CLOCK_THREAD_CPUTIME_ID, the thread clock MinOfThread reads, sees only the calling thread: a read that
// hands its work to a helper process (rulesview.InForce does: its work runs in a worker that a short launcher
// started and left, so the worker is the launcher's orphan, not this process's child) is invisible to it, and so is
// RUSAGE_CHILDREN for a process this one never waits for.
//
// So while it measures, this process is a child subreaper (prctl PR_SET_CHILD_SUBREAPER): an orphaned descendant is
// adopted by it instead of by init. A round reads the process's own CPU clock (all its threads) over fn, then waits
// for every child there is (the adopted worker included, once it ends) with wait4 on its pid, which adds each one's
// CPU time to RUSAGE_CHILDREN, and takes that growth over the round. fn must wait for the children it starts itself
// (exec.Cmd.Run, or Wait before it returns): one it leaves for another goroutine to wait for is waited for here
// instead, and that goroutine's Wait fails. A child that does not end within childrenWait fails the measurement by
// panic: a figure that left work out would only be a smaller number.
func MinOfTree(rounds int, fns ...func()) []TreeFigure {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 1, 0); errno != 0 {
		panic("testutil: prctl(PR_SET_CHILD_SUBREAPER): " + errno.Error())
	}
	defer func() {
		reapChildren() // adopted ones that ended after the last round
		_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, prSetChildSubreaper, 0, 0)
	}()
	never := time.Duration(1<<63 - 1)
	best := make([]TreeFigure, len(fns))
	for i := range best {
		best[i] = TreeFigure{CPU: never, Wall: never, Samples: max(rounds, 1)}
	}
	for r := range max(rounds, 1) {
		for j := range fns {
			i := (j + r) % len(fns)
			reapChildren() // a child of an earlier sample must not count in this one
			p0, c0 := processCPU(), childrenCPU()
			w0 := Wall.read()
			fns[i]()
			w1 := Wall.read()
			p1 := processCPU()
			reapChildren()
			cpu := p1 - p0 + childrenCPU() - c0
			best[i].CPU, best[i].Wall = min(best[i].CPU, cpu), min(best[i].Wall, w1-w0)
		}
	}
	return best
}

// childrenCPU is the CPU time of the children this process has waited for, and their own descendants they waited for.
func childrenCPU() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_CHILDREN, &ru); err != nil {
		panic("testutil: getrusage(RUSAGE_CHILDREN): " + err.Error())
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// reapChildren returns when this process has no child left: it waits (wait4 on each pid, so as to take no other
// than a child it lists) for the ones that ended, polling /proc for the ones that have not.
func reapChildren() {
	deadline := time.Now().Add(childrenWait)
	for {
		pids := childPIDs()
		if len(pids) == 0 {
			return
		}
		for _, pid := range pids {
			var ws syscall.WaitStatus
			_, _ = syscall.Wait4(pid, &ws, syscall.WNOHANG, nil)
		}
		if time.Now().After(deadline) {
			panic("testutil: a child process of this test did not end within " + childrenWait.String())
		}
		time.Sleep(2 * time.Millisecond)
	}
}

// childPIDs lists the processes, a zombie included, that have this one for their parent.
func childPIDs() []int {
	me := os.Getpid()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		panic("testutil: reading /proc: " + err.Error())
	}
	var out []int
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		b, err := os.ReadFile("/proc/" + e.Name() + "/stat")
		if err != nil {
			continue // gone since the listing
		}
		// pid (comm) state ppid ...: comm may hold spaces and parentheses, so the fields start after the last ')'.
		s := string(b)
		i := strings.LastIndexByte(s, ')')
		if i < 0 {
			continue
		}
		f := strings.Fields(s[i+1:])
		if len(f) > 1 {
			if ppid, err := strconv.Atoi(f[1]); err == nil && ppid == me {
				out = append(out, pid)
			}
		}
	}
	return out
}
