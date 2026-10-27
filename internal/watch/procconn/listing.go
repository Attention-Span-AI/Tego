// SPDX-License-Identifier: Apache-2.0

package procconn

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"
)

// TaskState is what /proc says of one task of a listing.
type TaskState int

// The states List tells apart.
const (
	TaskRunning TaskState = iota // neither dead nor a zombie, and not exiting
	TaskExiting                  // in do_exit (PF_EXITING), before exit_notify
	TaskZombie                   // past exit_notify, not reaped: an exited leader with threads, a traced thread
	TaskDying                    // dead ('X') or gone since it was enumerated: a moment of a change, listed again
)

// listTries bounds List's attempts at a listing no task changed under.
const listTries = 8

// List lists the tasks of a process for a Group (NewGroup, Group.Resync): since read first (Monotonic), then the tasks
// tasks enumerates, each one's state, and the enumeration again. /proc gives no snapshot, so a listing taken while a
// task changed is taken again: a task read dead or gone since it was enumerated (an exec's de_thread swaps the leader's
// tid with the exec'ing thread's and releases the old leader under the swapped one), or a task the second enumeration
// shows and the first did not (a thread made meanwhile, whose creator may have exited before it was read). After
// listTries such listings the last is kept, Unstable, with the tasks only its second enumeration showed counted as
// running (they were made after since, so their exits are filled after it): its status is unknown, and its end is
// checked with a fresh listing (Group). A process whose tasks cannot be enumerated (it has gone) lists none.
func List(tasks func() ([]int32, error), state func(tid int32) TaskState) Listing {
	var l Listing
	for try := 0; try < listTries; try++ {
		l = Listing{Since: Monotonic(), Exiting: true}
		tids, err := tasks()
		if err != nil {
			return Listing{Since: l.Since, Exiting: true}
		}
		stable := true
		for _, tid := range tids {
			switch state(tid) {
			case TaskRunning:
				l.Live, l.Exiting = append(l.Live, tid), false
			case TaskExiting:
				l.Live = append(l.Live, tid)
			case TaskDying:
				stable = false
			case TaskZombie:
			}
		}
		again, err := tasks()
		if err != nil {
			return Listing{Since: l.Since, Exiting: true}
		}
		var fresh []int32
		for _, tid := range again {
			if !slices.Contains(tids, tid) {
				fresh, stable = append(fresh, tid), false
			}
		}
		if stable {
			return l
		}
		if try == listTries-1 {
			l.Live, l.Unstable = append(l.Live, fresh...), true
		}
	}
	return l
}

// Monotonic is CLOCK_MONOTONIC as the kernel's ktime_get_ns reads it, the clock of Event.TimestampNS: tego's own
// reading less its time namespace's monotonic offset (/proc/self/timens_offsets, absent on a kernel without time
// namespaces). 0 when either cannot be read: the group then has no lower bound and states no status.
func Monotonic() uint64 {
	off, ok := timensOffset()
	if !ok {
		return 0
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	ns := ts.Nano() - off
	if ns <= 0 {
		return 0
	}
	return uint64(ns)
}

var (
	timensOnce sync.Once
	timensOff  int64
	timensOK   bool
)

// timensOffset is the monotonic offset of tego's time namespace in nanoseconds, read once: a process's time namespace
// does not change.
func timensOffset() (int64, bool) {
	timensOnce.Do(func() {
		b, err := os.ReadFile("/proc/self/timens_offsets")
		switch {
		case errors.Is(err, fs.ErrNotExist):
			timensOK = true // no time namespaces on this kernel: the clocks are the kernel's
		case err == nil:
			timensOff, timensOK = parseTimensOffsets(b)
		}
	})
	return timensOff, timensOK
}

// parseTimensOffsets reads the monotonic line of a timens_offsets file ("monotonic <secs> <nanosecs>"); false when it
// has none or it does not parse.
func parseTimensOffsets(b []byte) (int64, bool) {
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		f := bytes.Fields(sc.Bytes())
		if len(f) != 3 || (string(f[0]) != "monotonic" && string(f[0]) != strconv.Itoa(unix.CLOCK_MONOTONIC)) {
			continue
		}
		s, err1 := strconv.ParseInt(string(f[1]), 10, 64)
		n, err2 := strconv.ParseInt(string(f[2]), 10, 64)
		if err1 != nil || err2 != nil {
			return 0, false
		}
		return s*1_000_000_000 + n, true
	}
	return 0, false
}
