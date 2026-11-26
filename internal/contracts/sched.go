// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// A starved checker is not a stuck location (ADR 0144, "A starved checker is not a stuck location"). When the
// location budget of a helper runs out, or the compile budget of a compiler child, the kernel's own counters say
// what the process did in the window: how long it was runnable but waiting for a CPU, and what state it is in. The
// decision is arithmetic on those counters and nothing else.

// Thread is one task of a process, as the kernel counts it: its state letter (/proc/<pid>/task/<tid>/stat), and the
// time it has run on a CPU and the time it has waited on a run queue (the first two fields of schedstat), and for a
// task in state D what it waits in (WChan).
type Thread struct {
	State     byte
	Run, Wait time.Duration
	// WChan is the kernel function a thread in state D sleeps in (/proc/<pid>/task/<tid>/wchan), "" for any other
	// state, for a name the kernel hides ("0") and when it could not be read.
	WChan string
}

// SchedReader reads the tasks of the process pid, by thread id. start, when not zero, is the start time (in clock
// ticks since boot) the process must have, so a pid that has been given to another process is refused. An error
// means the counters cannot be read: the process has gone, or the kernel has no schedstat.
type SchedReader func(pid int, start uint64) (map[int]Thread, error)

// readScheduler is what the exchange reads a helper's counters with; a test replaces it.
var readScheduler SchedReader = procScheduler

// ErrNoSchedstat is the reading error of a kernel that does not count run-queue time: /proc/<pid>/schedstat is only
// there where the kernel is built with CONFIG_SCHED_INFO, and a masked /proc has no such file either.
var ErrNoSchedstat = errors.New("this kernel does not report scheduler statistics (no /proc/<pid>/schedstat)")

// procScheduler reads /proc/<pid>/stat for the process's start time and then, for every task of the process,
// /proc/<pid>/task/<tid>/stat (its state) and /proc/<pid>/task/<tid>/schedstat (run and wait). The process-wide
// files only describe the thread-group leader, and the helper's filesystem work runs on whichever thread its
// goroutine was locked to. Only the pid of a process Tego started is ever read: a helper's, or a compiler child's.
func procScheduler(pid int, start uint64) (map[int]Thread, error) {
	if pid <= 0 {
		return nil, errors.New("no process to read")
	}
	dir := "/proc/" + strconv.Itoa(pid)
	leader, err := proc.ReadParsedStat(func() ([]byte, error) { return os.ReadFile(dir + "/stat") })
	if err != nil {
		return nil, err
	}
	if leader.Gone() {
		return nil, errors.New("the process has ended")
	}
	if start != 0 && leader.StartTicks != start {
		return nil, errors.New("the pid belongs to another process now")
	}
	tasks, err := os.ReadDir(dir + "/task")
	if err != nil {
		return nil, err
	}
	out := map[int]Thread{}
	for _, task := range tasks {
		tid, err := strconv.Atoi(task.Name())
		if err != nil {
			continue
		}
		path := dir + "/task/" + task.Name()
		st, err := proc.ReadParsedStat(func() ([]byte, error) { return os.ReadFile(path + "/stat") })
		if err != nil {
			continue // the thread ended while the directory was read
		}
		raw, err := os.ReadFile(path + "/schedstat")
		if errors.Is(err, os.ErrNotExist) {
			return nil, ErrNoSchedstat
		}
		if err != nil {
			continue
		}
		run, wait, err := parseSchedstat(raw)
		if err != nil {
			return nil, err
		}
		thread := Thread{State: st.State, Run: run, Wait: wait}
		if st.State == 'D' {
			// Only a task that is blocked is asked what it waits in; unreadable or hidden ("0") is "".
			if b, err := os.ReadFile(path + "/wchan"); err == nil {
				if name := strings.TrimSpace(string(b)); name != "0" {
					thread.WChan = name
				}
			}
		}
		out[tid] = thread
	}
	if len(out) == 0 {
		return nil, errors.New("the process has no readable task")
	}
	return out, nil
}

// parseSchedstat decodes "run wait timeslices": nanoseconds on a CPU, nanoseconds waiting on a run queue, and the
// number of times it ran there.
func parseSchedstat(raw []byte) (run, wait time.Duration, err error) {
	fields := strings.Fields(string(raw))
	if len(fields) < 2 {
		return 0, 0, fmt.Errorf("malformed schedstat %q", raw)
	}
	r, err := strconv.ParseUint(fields[0], 10, 63)
	if err != nil {
		return 0, 0, fmt.Errorf("malformed schedstat %q", raw)
	}
	w, err := strconv.ParseUint(fields[1], 10, 63)
	if err != nil {
		return 0, 0, fmt.Errorf("malformed schedstat %q", raw)
	}
	return time.Duration(r), time.Duration(w), nil
}

// Verdict is what a process's counters say about a window in which it did not finish.
type Verdict int

const (
	// Blocked: a task was in uninterruptible sleep when it was read (state D), or the process was asleep: it waited
	// for a CPU for less than half of the window and ran on one for less than half. A stuck mount.
	Blocked Verdict = iota
	// BlockedDisk: Blocked, and every task in state D sleeps in a function of the disk family of the wchan table
	// (wchan.go): this computer's own disk or journal, not a mount. Slow, not stuck: it is given the extensions a
	// starved helper is.
	BlockedDisk
	// Starved: runnable and waiting on a run queue for at least half of the window, and not in state D. The
	// machine is busy.
	Starved
	// Running: not starved, and on a CPU for at least half of the window, and not in state D. The process was
	// working, not stuck: a long operation of its own.
	Running
	// Unreadable: the counters could not be read (no schedstat in this kernel, or the process has gone).
	Unreadable
)

// starvedShare is the part of a window a process must have spent waiting for a CPU to be starved, and runningShare
// the part it must have spent on one to be running: a half each (wait*starvedShare >= window, run*runningShare >=
// window). A window with neither is the process asleep, and with a task in state D it is blocked whatever else it did.
const (
	starvedShare = 2
	runningShare = 2
)

// Watch collects the counters of one process over the windows of a budget. It is begun when the budget starts (the
// helper's ready frame, the compiler child's ready mark), stops counting while the budget is paused, and Judge
// closes a window, says what it showed, and opens the next one. A Watch is used by one goroutine.
type Watch struct {
	read   SchedReader
	pid    int
	start  uint64
	now    func() time.Time
	base   map[int]Thread
	at     time.Time
	paused bool
	// window is the time counted in the current window, wait the longest run-queue wait and run the most time on a
	// CPU of any one task in it, summed over the parts of the window that were not paused. unreadable says a part
	// could not be counted.
	window, wait, run time.Duration
	unreadable        bool
}

// NewWatch begins watching the process pid (start is its start time in clock ticks, or 0 when it is not known) now.
func NewWatch(pid int, start uint64) *Watch { return NewWatchWith(readScheduler, pid, start, time.Now) }

// NewWatchWith is NewWatch with the way the counters and the clock are read, for a test.
func NewWatchWith(read SchedReader, pid int, start uint64, now func() time.Time) *Watch {
	w := &Watch{read: read, pid: pid, start: start, now: now}
	w.open()
	return w
}

// open takes the baseline of a part of the window.
func (w *Watch) open() {
	threads, err := w.read(w.pid, w.start)
	w.at = w.now()
	if err != nil {
		w.base = nil
		return
	}
	w.base = threads
}

// collect adds the part of the window since the baseline, and reports the threads as they are now (nil when they
// cannot be read).
func (w *Watch) collect() map[int]Thread {
	threads, err := w.read(w.pid, w.start)
	at := w.now()
	if err != nil {
		w.unreadable = true
		w.base, w.at = nil, at
		return nil
	}
	if w.base == nil { // no baseline to count from
		w.unreadable = true
		w.base, w.at = threads, at
		return threads
	}
	var longestWait, longestRun time.Duration
	for tid, t := range threads {
		before := w.base[tid] // a task born in this part of the window waited and ran from zero
		longestWait = max(longestWait, t.Wait-before.Wait)
		longestRun = max(longestRun, t.Run-before.Run)
	}
	w.window += at.Sub(w.at)
	w.wait += longestWait
	w.run += longestRun
	w.base, w.at = threads, at
	return threads
}

// Pause stops counting: the process is doing something that is not what the budget bounds (a helper waiting for a
// compile). What it showed so far stays in the window.
func (w *Watch) Pause() {
	if w.paused {
		return
	}
	w.collect()
	w.paused = true
}

// Resume starts counting again from now.
func (w *Watch) Resume() {
	if !w.paused {
		return
	}
	w.paused = false
	w.open()
}

// Judge closes the window and says what it showed. The window that follows begins now.
func (w *Watch) Judge() Verdict { return w.JudgeAt(false) }

// JudgeAt is Judge for a check whose location is local or not (ADR 0144, "A local location is a busy disk, not a stuck
// mount"). For a local location a helper with a thread in uninterruptible sleep (state D) is waiting for this
// computer's own disk, and it is BlockedDisk whatever the wait function says or whether it can be read at all: the
// kernel hides it for every undumpable helper. Only that evidence counts: a helper that is merely asleep (state S: a
// deadlock of Tego's own code, a pipe to the dashboard) and counters that cannot be read keep the verdict they have for
// every class. The wait function can only make a verdict more exact: a thread that does wait in a network or
// user-space filesystem (the location was remounted since it was classified, or something else is at fault) keeps
// Blocked, the mount words. For any other location it is Judge exactly.
func (w *Watch) JudgeAt(local bool) Verdict {
	var threads map[int]Thread
	if w.paused {
		threads = nil
	} else {
		threads = w.collect()
	}
	verdict := Blocked
	switch {
	case w.unreadable || threads == nil:
		verdict = Unreadable
	case onlyDiskWaits(threads):
		verdict = BlockedDisk
	case anyUninterruptible(threads):
		verdict = Blocked
		if local && !anyNetworkWait(threads) {
			verdict = BlockedDisk
		}
	case w.window > 0 && w.wait*starvedShare >= w.window:
		verdict = Starved
	case w.window > 0 && w.run*runningShare >= w.window:
		verdict = Running
	}
	w.window, w.wait, w.run, w.unreadable = 0, 0, 0, false
	if !w.paused {
		w.open()
	}
	return verdict
}

// anyNetworkWait reports whether a thread in state D waits in a function the wchan table knows as a network or
// user-space filesystem's.
func anyNetworkWait(threads map[int]Thread) bool {
	for _, t := range threads {
		if t.State == 'D' && classifyWchan(t.WChan) == wchanNetwork {
			return true
		}
	}
	return false
}

func anyUninterruptible(threads map[int]Thread) bool {
	for _, t := range threads {
		if t.State == 'D' {
			return true
		}
	}
	return false
}
