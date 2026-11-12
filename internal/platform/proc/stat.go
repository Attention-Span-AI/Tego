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

// ErrReleased is the stat line do_task_stat writes for a task released while the line was read (released). It
// always comes wrapped together with ErrStat, so a caller that does not read again fails closed, as for a
// malformed line: the line says nothing of the process under the pid now. That process may be gone, or it may be
// a live one whose old leader an execve from another of its threads released. Only another read tells (ReadStat).
var ErrReleased = errors.New("proc: stat line of a task released while it was read")

// statReads is how many times in all ReadStat reads one stat file whose line keeps the released shape.
const statReads = 3

// ReadStat reads one /proc/<pid>/stat file through read, and reads it again while its line is that of a task
// released during the read (ErrReleased). __exit_signal unhashes a task from its pid before it clears the task's
// sighand (kernel/exit.c:206 and 214), so by the time a read prints the released line the pid no longer names that
// task. The next read then finds no process (ENOENT on the open, ESRCH on an open file), which read returns as its
// caller reads any vanished process, or the line of the task that holds the pid now: after an execve from a
// thread other than the leader, the thread that ran it. After statReads reads of the released line, the last one
// is returned, and ParseStat refuses it (ErrStat), so the caller handles it as a malformed line. read's own errors
// are returned unchanged.
func ReadStat(read func() ([]byte, error)) ([]byte, error) {
	var b []byte
	for range statReads {
		var err error
		if b, err = read(); err != nil {
			return nil, err
		}
		if _, err := ParseStat(b); !errors.Is(err, ErrReleased) {
			break
		}
	}
	return b, nil
}

// ReadParsedStat is ReadStat and then ParseStat, for a reader that needs the fields and keeps no pure half of its
// own (a reader with one calls ReadStat and then ParseStat itself). A released line read again is the next line's
// process (gone: read's own error; live: its line), one that stays released is ErrStat and ErrReleased, and read's
// own errors are returned unchanged.
func ReadParsedStat(read func() ([]byte, error)) (Stat, error) {
	b, err := ReadStat(read)
	if err != nil {
		return Stat{}, err
	}
	return ParseStat(b)
}

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
	Session    int    // field 6: the session id, 0 for a session outside the reader's pid namespace
	TTY        int    // field 7: tty_nr, the controlling terminal's device number, 0 for none
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
// less than a tick, when the reader of /proc is in the initial time namespace, or in one with no
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
// an error wrapping ErrStat, none panics (fuzzed by FuzzParseStat). The line of a task released while it was read
// returns an error wrapping both ErrStat and ErrReleased (released): one line cannot tell whether the process is
// gone, so a reader of the file reads it again (ReadStat).
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
	// Field 1 is pid_nr_ns of the task's pid in the proc mount's pid namespace, printed unsigned (fs/proc/array.c,
	// do_task_stat). That pid is in that namespace, since /proc/<pid> was looked up there (proc_pid_lookup,
	// find_task_by_pid_ns), and a pid number is never 0 there, so a kernel never writes 0 or a negative pid. Both
	// are refused, as a negative ppid, pgrp and num_threads are below, so no caller holds a Stat whose PID kill(2)
	// would take for a process group (0, or below -1) or for every process (-1) (FuzzParseStat).
	if pid <= 0 {
		return Stat{}, fmt.Errorf("%w: pid %d", ErrStat, pid)
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
	// A process group of -1 is decided below, once the rest of the line has parsed (released).
	npgrp, err := strconv.Atoi(string(pgrp))
	if err != nil || npgrp < -1 {
		return Stat{}, fmt.Errorf("%w: pgrp %q", ErrStat, pgrp)
	}
	// A session of -1, like a process group of -1, is a released task's (released), decided below.
	session, err := field(statFirstFieldAfterComm + 3)
	if err != nil {
		return Stat{}, err
	}
	nsession, err := strconv.Atoi(string(session))
	if err != nil || nsession < -1 {
		return Stat{}, fmt.Errorf("%w: session %q", ErrStat, session)
	}
	tty, err := field(statFirstFieldAfterComm + 4)
	if err != nil {
		return Stat{}, err
	}
	// tty_nr is new_encode_dev of the terminal's device number printed with %d, so a minor at or above 2^19 prints
	// negative: any integer is one a kernel may write.
	ntty, err := strconv.Atoi(string(tty))
	if err != nil {
		return Stat{}, fmt.Errorf("%w: tty_nr %q", ErrStat, tty)
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
	if npgrp == -1 {
		if released(tail) {
			return Stat{}, fmt.Errorf("%w: %w: pid %d, process group -1", ErrStat, ErrReleased, pid)
		}
		return Stat{}, fmt.Errorf("%w: pgrp %q", ErrStat, pgrp)
	}
	// Under the sighand lock a session is 0 or a pid, never -1, so a -1 with a real process group is no line a
	// kernel writes.
	if nsession == -1 {
		return Stat{}, fmt.Errorf("%w: session %q", ErrStat, session)
	}
	return Stat{
		PID:        pid,
		Comm:       string(line[lparen+1 : rparen]),
		State:      state[0],
		PPID:       nppid,
		Pgrp:       npgrp,
		Session:    nsession,
		TTY:        ntty,
		StartTicks: nstart,
		NumThreads: nthreads,
		Flags:      uint32(nflags),
	}, nil
}

// released reports a stat line, given as the fields after its comm, that do_task_stat wrote for a task released
// after the read took a reference to it and before it took the task's sighand lock (fs/proc/array.c:474-475 and
// 518-541, torvalds/linux 1d4ee94a51bd): __exit_signal had set task->sighand to NULL, so lock_task_sighand failed
// and ppid 0, process group -1, session -1, tty_nr 0, tty_pgrp -1 and num_threads 0 kept the values they were
// declared with. Under the lock a process group or session is never -1 (task_pgrp_nr_ns is 0 or a pid), so this
// shape, all six together, is a released task. It does not say the process is gone: an execve from a thread other
// than the leader releases the old leader (de_thread, fs/exec.c), and the process goes on under the same pid with
// the same start time. A reader on kernel 6.17 got this line about once in 9,000 reads of such a process, and
// never got ENOENT. Any other negative process group stays malformed.
func released(tail [][]byte) bool {
	for _, f := range [...]struct {
		n int
		v string
	}{{4, "0"}, {5, "-1"}, {6, "-1"}, {7, "0"}, {8, "-1"}, {statFieldNumThreads, "0"}} {
		i := f.n - statFirstFieldAfterComm
		if i >= len(tail) || string(tail[i]) != f.v {
			return false
		}
	}
	return true
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
