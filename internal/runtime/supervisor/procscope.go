// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// ruleProcessScope names a resource-limit or scheduling change refused because it would reach a process outside
// the run (R35). The reason is landlock-topology, as signal-scope's: the refusal is the run's process boundary,
// which the domain draws for signals and ptrace and this loop draws for the calls Landlock has no hook for.
const ruleProcessScope = "process-scope"

// Syscall numbers of the process-scope arm (enforce-landlock procScopeTest).
const (
	nrX86Prlimit64         = 302
	nrX86SchedSetparam     = 142
	nrX86SchedSetscheduler = 144
	nrX86SchedSetaffinity  = 203
	nrX86SchedSetattr      = 314
	nrX86Setpriority       = 141
	nrX86IoprioSet         = 251
	nrARMPrlimit64         = 261
	nrARMSchedSetparam     = 118
	nrARMSchedSetscheduler = 119
	nrARMSchedSetaffinity  = 122
	nrARMSchedSetattr      = 274
	nrARMSetpriority       = 140
	nrARMIoprioSet         = 30
)

// The which values of setpriority(2) (PRIO_*) and ioprio_set(2) (IOPRIO_WHO_*).
const (
	prioProcess, prioPgrp, prioUser                = 0, 1, 2
	ioprioWhoProcess, ioprioWhoPgrp, ioprioWhoUser = 1, 2, 3
)

// procScopeTarget reads what one process-control call reaches from its scalar arguments; clear marks the
// caller itself. ok is false for a call the kernel refuses on its arguments alone (a negative pid or who, an
// unknown which), which is continued so the kernel answers it as it would have.
func procScopeTarget(op string, args [6]uint64) (sigTarget, bool) {
	a0, a1 := int(int32(args[0])), int(int32(args[1]))
	var process, pgrp, user int
	switch op {
	case "setpriority":
		process, pgrp, user = prioProcess, prioPgrp, prioUser
	case "ioprio_set":
		process, pgrp, user = ioprioWhoProcess, ioprioWhoPgrp, ioprioWhoUser
	default: // prlimit64 and the sched_set* calls: one task in args[0], 0 the caller
		switch {
		case a0 == 0:
			return sigTarget{clear: true}, true
		case a0 < 0:
			return sigTarget{}, false
		}
		return sigTarget{pid: a0}, true
	}
	switch {
	case a0 == user:
		// Every process of a uid, the caller's own when who is 0: at tier 1 that is the launcher's.
		return sigTarget{user: true, uid: uint32(a1)}, true
	case a1 < 0:
		return sigTarget{}, false
	case a0 == process && a1 == 0:
		return sigTarget{clear: true}, true
	case a0 == process:
		return sigTarget{pid: a1}, true
	case a0 == pgrp && a1 == 0:
		return sigTarget{group: -1}, true // the caller's own group, resolved by targetInside
	case a0 == pgrp:
		return sigTarget{group: a1}, true
	}
	return sigTarget{}, false
}

// answerProcScope decides a resource-limit or scheduling change on another process (R35), as answerSignal
// decides a signal: continued when every process it reaches is in the run's cgroup or one beneath it, refused
// EPERM (the kernel's own errno for a target the caller may not change) and recorded otherwise. A task of the
// caller's own thread group is continued with no cgroup read. A target that no longer exists is continued and
// the kernel answers ESRCH.
func (l *Loop) answerProcScope(n *notif, op string) {
	t, ok := procScopeTarget(op, n.args)
	if !ok || t.clear || l.observing() {
		l.respond(n, respContinue())
		return
	}
	// R2: the reads below are keyed by the bare tid the notification carried, as answerSignal's are.
	if !l.valid(n) {
		return
	}
	inside, err := l.procTargetInside(n, &t)
	if !l.valid(n) {
		return
	}
	switch {
	case err == nil && inside, errors.Is(err, unix.ESRCH):
		l.respond(n, respContinue())
		return
	case err != nil:
		l.log.Warn("supervisor: process-scope target unreadable, refused", "op", op, "err", err)
	}
	l.respond(n, respErrno(unix.EPERM))
	ev := l.event(n, record.KindRefused, record.SourceSupervisor)
	ev.Rule, ev.Reason = ruleProcessScope, record.ReasonLandlockTopology
	l.emitFor(n, ev, record.RefusedPayload{Op: op, Target: t.String(), Reason: record.ReasonLandlockTopology,
		Rule: ruleProcessScope})
}

// procTargetInside is targetInside for these calls, whose pid names a task (a thread's id names that thread):
// a task of the caller's own thread group is inside with no cgroup read.
func (l *Loop) procTargetInside(n *notif, t *sigTarget) (bool, error) {
	if l.table.Load().pol.Cgroup == "" {
		return false, errors.New("the run's cgroup is unknown")
	}
	if t.pid > 0 {
		if t.pid == n.pid {
			return true, nil
		}
		if g := l.tgidOf(n.pid); t.pid == g || l.k.InGroup(g, t.pid) {
			return true, nil
		}
		return l.inRun(t.pid)
	}
	return l.targetInside(n, t)
}

// addProcScope adds the process-scope arm's entries for arch: decision kinds, since a handler that cannot finish
// must not let a change leave the run.
func addProcScope(arch uint32, add func(int32, entry)) {
	e := func(name string) entry {
		return entry{name: name, fn: func(l *Loop, n *notif) { l.answerProcScope(n, name) }}
	}
	if arch == auditArchARM {
		add(nrARMPrlimit64, e("prlimit64"))
		add(nrARMSchedSetparam, e("sched_setparam"))
		add(nrARMSchedSetscheduler, e("sched_setscheduler"))
		add(nrARMSchedSetaffinity, e("sched_setaffinity"))
		add(nrARMSchedSetattr, e("sched_setattr"))
		add(nrARMSetpriority, e("setpriority"))
		add(nrARMIoprioSet, e("ioprio_set"))
		return
	}
	add(nrX86Prlimit64, e("prlimit64"))
	add(nrX86SchedSetparam, e("sched_setparam"))
	add(nrX86SchedSetscheduler, e("sched_setscheduler"))
	add(nrX86SchedSetaffinity, e("sched_setaffinity"))
	add(nrX86SchedSetattr, e("sched_setattr"))
	add(nrX86Setpriority, e("setpriority"))
	add(nrX86IoprioSet, e("ioprio_set"))
}
