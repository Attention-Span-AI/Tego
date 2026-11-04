// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ruleSignalScope names a signal refused because it would reach a process outside the run. The reason is
// landlock-topology, the domain-scope code: from Landlock ABI 6 the ruleset's LANDLOCK_SCOPE_SIGNAL makes the
// same refusal in the kernel, and below it this loop stands in for it (R33).
const ruleSignalScope = "signal-scope"

// f_owner_ex's owner types (linux/fcntl.h), which golang.org/x/sys/unix does not define.
const (
	fOwnerTid  = 0
	fOwnerPgrp = 2
)

// The signal syscalls and fcntl commands the signal-scope arm notifies (enforce-landlock signalScopeTest).
func handleKill(l *Loop, n *notif)             { l.answerSignal(n, "kill") }
func handleTkill(l *Loop, n *notif)            { l.answerSignal(n, "tkill") }
func handleTgkill(l *Loop, n *notif)           { l.answerSignal(n, "tgkill") }
func handleRtSigqueueinfo(l *Loop, n *notif)   { l.answerSignal(n, "rt_sigqueueinfo") }
func handleRtTgsigqueueinfo(l *Loop, n *notif) { l.answerSignal(n, "rt_tgsigqueueinfo") }
func handleIoctl(l *Loop, n *notif) {
	if uint32(n.args[1]) == unix.TIOCGPTPEER {
		l.ptyPeer(n)
		return
	}
	l.answerSignal(n, "ioctl")
}

// handleFcntl answers the two fcntl(2) commands a filter notifies: F_NOTIFY, a dnotify watch, which the watch arm
// notifies (enforce-landlock R11e) and handleDnotify decides (R36), and F_SETOWN or F_SETOWN_EX, which the signal-scope
// arm notifies below Landlock ABI 6. The command is an unsigned int the kernel reads as it is here; any other
// command is continued, as answerSignal continues it.
func handleFcntl(l *Loop, n *notif) {
	if uint32(n.args[1]) == unix.F_NOTIFY {
		handleDnotify(l, n)
		return
	}
	l.answerSignal(n, "fcntl")
}

// sigTarget is what one signalling call reaches: one task, a process group, or every process.
type sigTarget struct {
	pid       int  // a task (a process, or with thread a thread) when > 0
	thread    bool // pid is a thread id (tkill), not a process
	group     int  // a process group when > 0; -1 the caller's own, until targetInside resolves it
	broadcast bool // kill(-1): every process the caller may signal
	user      bool // PRIO_USER, IOPRIO_WHO_USER: every process of uid (the caller's when 0)
	uid       uint32
	clear     bool // F_SETOWN 0: no owner, nothing is signalled
}

// String names the target for the refused line.
func (t sigTarget) String() string {
	switch {
	case t.broadcast:
		return "every process (-1)"
	case t.user && t.uid == 0:
		return "every process of the caller's uid"
	case t.user:
		return fmt.Sprintf("every process of uid %d", t.uid)
	case t.group == -1:
		return "the caller's own process group" // its group could not be read
	case t.group > 0:
		return fmt.Sprintf("process group %d", t.group)
	case t.thread:
		return fmt.Sprintf("thread %d", t.pid)
	}
	return fmt.Sprintf("pid %d", t.pid)
}

// answerSignal decides a signal below Landlock ABI 6, as LANDLOCK_SCOPE_SIGNAL decides it from ABI 6: a
// signal to a process inside the run (its cgroup or one beneath it) is continued, and one that would reach
// any process outside it — the launcher and its supervisor, another run, the user's shell — is refused
// EPERM, the scope's own errno, and recorded. Signal 0 is decided the same way, as the scope decides it.
//
// A signal to the caller's own process (tgkill and raise's shape, and the Go runtime's preemption
// signals) is continued with no /proc read once the caller's thread group is cached (tgidOf; the first
// signal of a thread reads /proc/<tid>/status once), and no cgroup read. Every other target is read from /proc, and the kernel
// re-resolves the pid when the call continues: a target that exits and whose pid a process outside the run
// takes in between gets the signal. That is a best-effort decision like every one this loop continues
// (supervisor.md §1); the kernel's scope from ABI 6 has no such window. A target that no longer exists is
// continued, and the kernel answers ESRCH as it would have.
func (l *Loop) answerSignal(n *notif, op string) {
	t, ok := signalTarget(op, n.args)
	if !ok || t.clear || l.observing() {
		l.respond(n, respContinue())
		return
	}
	// R2: every read below is keyed by the bare tid the notification carried (the owner in its memory,
	// its group in /proc), so it is bracketed by ID_VALID: a thread that died and whose tid was reused
	// would otherwise have a stranger's memory or group decided on and recorded.
	if !l.valid(n) {
		return
	}
	t, inside, err := l.signalInside(n, t)
	if !l.valid(n) {
		return
	}
	switch {
	case err == nil && inside, errors.Is(err, unix.ESRCH):
		l.respond(n, respContinue())
		return
	case err != nil:
		l.log.Warn("supervisor: signal target unreadable, refused", "op", op, "err", err)
	}
	l.respond(n, respErrno(unix.EPERM))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = ruleSignalScope, record.ReasonLandlockTopology
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: t.String(), Reason: record.ReasonLandlockTopology,
		Rule: ruleSignalScope})
}

// signalTarget reads the target of one signalling call from its scalar arguments: kill(pid, sig),
// tkill(tid, sig), tgkill(tgid, tid, sig), rt_sigqueueinfo(tgid, sig, info), rt_tgsigqueueinfo(tgid, tid, sig,
// info) and fcntl(fd, F_SETOWN, owner); F_SETOWN_EX's owner is in memory and is read by the caller of this
// function. ok is false for an fcntl command the arm does not notify, and for a non-positive target of the
// calls that name one process or thread: the kernel signals nothing there (tkill and tgkill answer EINVAL,
// the rt_*sigqueueinfo pair EINVAL or ESRCH), and read as a group it would cost a whole-host /proc scan per
// call, since no group 0 or below is ever in the snapshot.
func signalTarget(op string, args [6]uint64) (sigTarget, bool) {
	a0 := int(int32(args[0]))
	switch op {
	case "tkill", "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo":
		if a0 <= 0 {
			return sigTarget{}, false
		}
	}
	switch op {
	case "kill":
		switch {
		case a0 > 0:
			return sigTarget{pid: a0}, true
		case a0 == 0:
			return sigTarget{group: -1}, true // the caller's own group, resolved by signalInside
		case a0 == -1:
			return sigTarget{broadcast: true}, true
		}
		return sigTarget{group: -a0}, true
	case "tkill":
		return sigTarget{pid: a0, thread: true}, true
	case "tgkill", "rt_sigqueueinfo", "rt_tgsigqueueinfo":
		return sigTarget{pid: a0}, true
	case "fcntl":
		if int32(args[1]) != unix.F_SETOWN {
			return sigTarget{}, int32(args[1]) == unix.F_SETOWN_EX
		}
		owner := int(int32(args[2]))
		switch {
		case owner == 0:
			return sigTarget{clear: true}, true
		case owner > 0:
			return sigTarget{pid: owner}, true
		}
		return sigTarget{group: -owner}, true
	case "ioctl":
		// FIOSETOWN or SIOCSPGRP, whose owner is an int in memory, read by the caller (signalInside).
		// The kernel takes cmd as an unsigned int (and the filter matches its low 32 bits), so the high half is
		// ignored here too: a request with junk above bit 31 is still FIOSETOWN or SIOCSPGRP to sock_ioctl.
		req := uint32(args[1])
		return sigTarget{}, req == ioctlFIOSETOWN || req == ioctlSIOCSPGRP
	}
	return sigTarget{}, false
}

// ioctlFIOSETOWN and ioctlSIOCSPGRP are the ioctl requests that set a socket's signal owner (sock_ioctl).
const ioctlFIOSETOWN, ioctlSIOCSPGRP = 0x8901, 0x8902

// ioctlOwner reads the int owner FIOSETOWN and SIOCSPGRP take by pointer: a pid when positive, a process
// group when negative, none when 0 (f_setown). Best effort like setownEx.
func (l *Loop) ioctlOwner(n *notif) (sigTarget, error) {
	var buf [4]byte
	got, err := l.k.ReadMem(n.pid, n.args[2], buf[:])
	if err != nil || got < len(buf) {
		return sigTarget{}, fmt.Errorf("read the ioctl owner: %d bytes, %v", got, err)
	}
	owner := int(int32(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24))
	switch {
	case owner == 0:
		return sigTarget{clear: true}, nil
	case owner > 0:
		return sigTarget{pid: owner}, nil
	}
	return sigTarget{group: -owner}, nil
}

// ioctlNR is this architecture's ioctl(2).
func ioctlNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMIoctl
	}
	return nrX86Ioctl
}

// signalInside reports whether every process the target names is inside the run's cgroup, and returns the
// target with an owner read from memory (F_SETOWN_EX, FIOSETOWN, SIOCSPGRP) filled in, for the refused line.
// Its reads are keyed by n.pid; the caller brackets them with ID_VALID (R2).
func (l *Loop) signalInside(n *notif, t sigTarget) (sigTarget, bool, error) {
	if l.table.Load().pol.Cgroup == "" {
		return t, false, errors.New("the run's cgroup is unknown")
	}
	if n.nr == fcntlNR() && int32(n.args[1]) == unix.F_SETOWN_EX {
		var err error
		if t, err = l.setownEx(n); err != nil || t.clear {
			return t, t.clear, err
		}
	}
	if n.nr == ioctlNR() {
		var err error
		if t, err = l.ioctlOwner(n); err != nil || t.clear {
			return t, t.clear, err
		}
	}
	in, err := l.targetInside(n, &t)
	return t, in, err
}

// targetInside is signalInside once the target is known. It resolves the caller's own group (-1) into t, so
// a refused line names that group.
func (l *Loop) targetInside(n *notif, t *sigTarget) (bool, error) {
	if t.broadcast || t.user {
		return false, nil
	}
	if t.pid > 0 {
		// The caller's own process, which the filter reached from inside the run. tgidOf is the cached thread
		// group, checked with one lookup and no read; a tid it cannot read is its own group, which is the
		// caller's own process whenever it matches.
		if !t.thread && t.pid == l.tgidOf(n.pid) {
			return true, nil
		}
		return l.inRun(t.pid)
	}
	if t.group == -1 {
		g, err := l.k.ProcPgrp(n.pid)
		if err != nil {
			return false, err
		}
		t.group = g
	}
	members, err := l.groupMembers(t.group)
	if err != nil {
		return false, err
	}
	if len(members) == 0 {
		return false, unix.ESRCH
	}
	for _, pid := range members {
		in, err := l.inRun(pid)
		if errors.Is(err, unix.ESRCH) {
			continue
		}
		if err != nil || !in {
			return false, err
		}
	}
	return true, nil
}

// groupScanTTL is how long one /proc scan of the host's process groups answers later group signals. The
// scan reads every process's stat, ~15 ms on a desktop's 500 processes, on one of the pool's workers; a
// test runner or job-control shell that signals a group in a loop would otherwise pay it on every call.
// 50 ms is an unsourced P0 default: short beside the scan it saves, and a window of the same class as the
// best-effort one every continued signal already has (answerSignal).
const groupScanTTL = 50 * time.Millisecond

// groupCache is the last /proc scan of the host's process groups (groupMembers).
type groupCache struct {
	mu      sync.Mutex
	at      time.Time // when the scan started, so its age is never understated
	byGroup map[int][]int
}

// groupMembers lists the processes of process group pgid, from a scan at most groupScanTTL old when that
// scan found the group. What a snapshot can miss is a process that joined the group after it: only a
// process of the same session can join, for itself or a child it has not exec'd yet (setpgid), so from
// outside the run that is the launcher's side acting on its own. A group the snapshot does not hold is
// scanned again rather than answered empty, because an empty group is continued (ESRCH): a group a run
// process has just made would otherwise be continued unread for the rest of the window. Only a group whose
// leader is in it now is scanned again, though: a group is made by setpgid(p, p) or setsid, both of which put
// process p in group p, so one made since the scan has had its leader in it. A pgid whose process is gone or
// in another group is answered empty from the snapshot, with one stat read instead of a whole-host scan, so
// kill(-N) in a loop on a group that does not exist costs no /proc scan per call. A group made since the scan
// whose leader has already exited or left it is answered empty too: its other members joined it from the
// leader's session or are the leader's children, the best-effort class a snapshot already has. A member that
// has since exited is ESRCH to inRun and skipped, and a pid reused outside the run reads as outside and refuses.
func (l *Loop) groupMembers(pgid int) ([]int, error) {
	g := &l.groups
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.byGroup != nil && time.Since(g.at) < groupScanTTL {
		if m, ok := g.byGroup[pgid]; ok {
			return m, nil
		}
		if lead, err := l.k.ProcPgrp(pgid); errors.Is(err, unix.ESRCH) || (err == nil && lead != pgid) {
			return nil, nil
		}
	}
	start := time.Now()
	snap, err := l.k.ProcessGroups()
	if err != nil {
		return nil, err
	}
	g.byGroup, g.at = snap, start
	return snap[pgid], nil
}

// setownEx reads F_SETOWN_EX's struct f_owner_ex {int type; pid_t pid;} from the caller's memory. The read is
// best effort like every memory read this loop decides on: another thread can change it before the kernel
// copies it (the continue of every decided syscall shares that window, supervisor.md §1).
func (l *Loop) setownEx(n *notif) (sigTarget, error) {
	var buf [8]byte
	got, err := l.k.ReadMem(n.pid, n.args[2], buf[:])
	if err != nil || got < len(buf) {
		return sigTarget{}, fmt.Errorf("read f_owner_ex: %d bytes, %v", got, err)
	}
	typ := int32(uint32(buf[0]) | uint32(buf[1])<<8 | uint32(buf[2])<<16 | uint32(buf[3])<<24)
	pid := int(int32(uint32(buf[4]) | uint32(buf[5])<<8 | uint32(buf[6])<<16 | uint32(buf[7])<<24))
	switch {
	case pid == 0:
		return sigTarget{clear: true}, nil
	case pid < 0:
		return sigTarget{}, fmt.Errorf("f_owner_ex pid %d", pid)
	case typ == fOwnerPgrp:
		return sigTarget{group: pid}, nil
	case typ == fOwnerTid:
		return sigTarget{pid: pid, thread: true}, nil
	}
	return sigTarget{pid: pid}, nil
}

// inRun reports whether pid's cgroup is the run's or one beneath it.
func (l *Loop) inRun(pid int) (bool, error) {
	cg, err := l.k.ProcCgroup(pid)
	if err != nil {
		return false, err
	}
	run := strings.TrimSuffix(l.table.Load().pol.Cgroup, "/")
	return cg == run || strings.HasPrefix(cg, run+"/"), nil
}

// fcntlNR is fcntl's number on this build's architecture.
func fcntlNR() int32 {
	if nativeAuditArch() == auditArchARM {
		return nrARMFcntl
	}
	return nrX86Fcntl
}
