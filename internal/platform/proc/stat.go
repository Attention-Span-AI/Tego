// SPDX-License-Identifier: Apache-2.0

package proc

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"strconv"
)

// TicksPerSecond is USER_HZ, the unit /proc/<pid>/stat reports times in. The kernel fixes it at 100
// on every architecture this project supports (include/asm-generic/param.h), so it is a constant
// here rather than a sysconf(_SC_CLK_TCK) call cgo would be needed for.
const TicksPerSecond = 100

// NanosPerTick converts a USER_HZ tick count to nanoseconds.
const NanosPerTick = 1_000_000_000 / TicksPerSecond

// ErrStat is a /proc/<pid>/stat line this package could not parse. It is wrapped, never returned
// bare, so a caller can tell a malformed line from a vanished process (ErrGone).
var ErrStat = errors.New("proc: malformed stat line")

// statFieldStartTime is starttime, field 22 of proc(5)'s stat table, counted from 1.
const statFieldStartTime = 22

// statFieldNumThreads is num_threads, field 20.
const statFieldNumThreads = 20

// statFieldFlags is flags, field 9: the task's PF_* flags.
const statFieldFlags = 9

// pfExiting is PF_EXITING (include/linux/sched.h), set as do_exit begins, before exit_notify makes the task a zombie.
const pfExiting = 0x00000004

// statFirstFieldAfterComm is state, field 3: the first field of the space-separated tail that
// follows the parenthesised comm. Field n of proc(5) is tail[n-statFirstFieldAfterComm].
const statFirstFieldAfterComm = 3

// Stat is the subset of /proc/<pid>/stat this project reads. Comm is the kernel's 15-byte
// executable name with its parentheses removed; it may contain spaces and parentheses itself, which
// is why it is cut at the *last* ')' and never split on.
type Stat struct {
	PID        int
	Comm       string
	State      byte
	PPID       int
	Pgrp       int    // field 5: the process group id
	StartTicks uint64 // field 22: USER_HZ ticks between boot and this process's start
	NumThreads int
	Flags      uint32 // field 9: the task's PF_* flags
}

// Exiting reports a task in do_exit that has not yet passed exit_notify (PF_EXITING): its exit code is fixed and its
// exit event, if any, is still to be filled.
func (s Stat) Exiting() bool { return s.Flags&pfExiting != 0 }

// StartBootNS is the process start time in nanoseconds since boot, the last component of an exec id
// (spec/identity/RUN-IDENTITY.md), at /proc's resolution: the kernel rounds task->start_boottime
// down to a whole USER_HZ tick (10 ms) for this field. The tier-2 exec event carries the same
// task->start_boottime unrounded (bpf/trace_proc.bpf.c), so for one process the two values differ by
// less than a tick — when the reader of /proc is in the initial time namespace, or in one with no
// boottime offset. fs/proc/array.c adds the reader's time-namespace boottime offset
// (timens_add_boottime_ns) before rounding, and the BPF program reads the raw value, so a launcher in a
// time namespace with an offset (unshare -T, a CRIU-restored container) sees the two differ by that
// offset: SameProcess then answers false for one process, and ExecStartNS gives it two ids. Within that
// condition, one tick is the tolerance SameProcess allows, and ExecID builds an exec id from either value
// through ExecStartNS, which rounds the exact one the way the kernel rounds it here, so both producers
// name the process with one id.
func (s Stat) StartBootNS() uint64 { return s.StartTicks * NanosPerTick }

// LeaderExited reports a process whose thread-group leader has exited while other threads of it run on (pthread_exit
// in main, or a raw exit(2) from the leader): its stat says Z, the leader's state, and counts more than one task. A
// zombie's num_threads counts the leader until it is reaped, and the kernel releases each other thread as it exits, so
// a zombie whose group has ended counts one. Such a process is alive: its threads run its program and may fork, and a
// child they fork names it its parent (ADR 0055, What was measured (d)).
func (s Stat) LeaderExited() bool { return s.State == 'Z' && s.NumThreads > 1 }

// Gone reports a stat of a process with no task left: dead (X), or a zombie whose whole group has exited. It is the
// one test of a process's end every reader of /proc in the watch packages applies, so a process whose leader exited
// is alive to all of them.
func (s Stat) Gone() bool { return s.State == 'X' || s.State == 'Z' && !s.LeaderExited() }

// SameProcess reports whether two start-times, at least one of which came from /proc, describe the
// same process. /proc rounds down to a whole USER_HZ tick while the kernel's own timestamp is exact,
// so anything inside one tick is the same process and anything beyond it is a reused pid
// (docs/p0/enforce-cgroup-observe.md §6 E14).
func SameProcess(a, b uint64) bool {
	if a > b {
		a, b = b, a
	}
	return b-a < NanosPerTick
}

// ParseStat decodes one /proc/<pid>/stat line. It is pure and total: every malformed shape returns
// an error wrapping ErrStat, none panics (fuzzed by FuzzParseStat).
func ParseStat(line []byte) (Stat, error) {
	lparen := bytes.IndexByte(line, '(')
	rparen := bytes.LastIndexByte(line, ')')
	if lparen < 0 || rparen < lparen {
		return Stat{}, fmt.Errorf("%w: no parenthesised comm", ErrStat)
	}
	pid, err := strconv.Atoi(string(bytes.TrimSpace(line[:lparen])))
	if err != nil {
		return Stat{}, fmt.Errorf("%w: pid: %v", ErrStat, err)
	}
	tail := bytes.Fields(line[rparen+1:])
	field := func(n int) ([]byte, error) {
		i := n - statFirstFieldAfterComm
		if i < 0 || i >= len(tail) {
			return nil, fmt.Errorf("%w: field %d of %d missing", ErrStat, n, len(tail)+statFirstFieldAfterComm-1)
		}
		return tail[i], nil
	}
	state, err := field(statFirstFieldAfterComm)
	if err != nil {
		return Stat{}, err
	}
	ppid, err := field(statFirstFieldAfterComm + 1)
	if err != nil {
		return Stat{}, err
	}
	nppid, err := strconv.Atoi(string(ppid))
	if err != nil || nppid < 0 {
		return Stat{}, fmt.Errorf("%w: ppid %q", ErrStat, ppid)
	}
	pgrp, err := field(statFirstFieldAfterComm + 2)
	if err != nil {
		return Stat{}, err
	}
	npgrp, err := strconv.Atoi(string(pgrp))
	if err != nil || npgrp < 0 {
		return Stat{}, fmt.Errorf("%w: pgrp %q", ErrStat, pgrp)
	}
	flags, err := field(statFieldFlags)
	if err != nil {
		return Stat{}, err
	}
	nflags, err := strconv.ParseUint(string(flags), 10, 32)
	if err != nil {
		return Stat{}, fmt.Errorf("%w: flags %q", ErrStat, flags)
	}
	threads, err := field(statFieldNumThreads)
	if err != nil {
		return Stat{}, err
	}
	nthreads, err := strconv.Atoi(string(threads))
	if err != nil || nthreads < 0 {
		return Stat{}, fmt.Errorf("%w: num_threads %q", ErrStat, threads)
	}
	start, err := field(statFieldStartTime)
	if err != nil {
		return Stat{}, err
	}
	nstart, err := strconv.ParseUint(string(start), 10, 64)
	// A starttime StartBootNS cannot turn into nanoseconds is not one a kernel wrote: 2^64/1e7 ticks is
	// 58,000 years of uptime. Taken as it was, it wrapped to a small time, which could read as the start of
	// another process (FuzzParseStat).
	if err != nil || nstart > math.MaxUint64/NanosPerTick {
		return Stat{}, fmt.Errorf("%w: starttime %q", ErrStat, start)
	}
	return Stat{
		PID:        pid,
		Comm:       string(line[lparen+1 : rparen]),
		State:      state[0],
		PPID:       nppid,
		Pgrp:       npgrp,
		StartTicks: nstart,
		NumThreads: nthreads,
		Flags:      uint32(nflags),
	}, nil
}

// ParseCgroup reads /proc/<pid>/cgroup and returns the unified (cgroup v2) path, the line whose
// hierarchy id is 0 and whose controller list is empty ("0::/user.slice/..."). A process on a
// v1-only hierarchy has no such line and yields "" with no error: the caller decides whether that
// is fatal. Pure and total (fuzzed by FuzzParseCgroup).
func ParseCgroup(b []byte) string {
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		// hierarchy-ID:controller-list:cgroup-path, path may contain ':'.
		first := bytes.IndexByte(line, ':')
		if first < 0 {
			continue
		}
		second := bytes.IndexByte(line[first+1:], ':')
		if second < 0 {
			continue
		}
		if string(line[:first]) != "0" || second != 0 {
			continue
		}
		return string(line[first+2:])
	}
	return ""
}

// ParseArgv splits a /proc/<pid>/cmdline blob into arguments. The kernel NUL-terminates every
// argument including the last; a process that rewrote its own argv may leave no trailing NUL or
// embed none at all, so a trailing unterminated run is kept as a final argument and an empty blob
// yields nil (a kernel thread, or a process that exited between open and read). Pure and total.
func ParseArgv(b []byte) []string {
	if len(b) == 0 {
		return nil
	}
	// Only the last argument's terminator is removed. Earlier trailing NULs
	// delimit empty arguments, which must remain in the command line.
	b = bytes.TrimSuffix(b, []byte{0})
	parts := bytes.Split(b, []byte{0})
	argv := make([]string, len(parts))
	for i, p := range parts {
		argv[i] = string(p)
	}
	return argv
}
