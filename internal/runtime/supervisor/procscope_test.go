// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestProcessScope: prlimit64, setpriority, the sched_set* calls and ioprio_set on a process outside the
// run are refused EPERM with a refused process-scope line, at every ABI, since no Landlock scope covers them. At
// tier 1 the agent shares its launcher's uid, and a hard RLIMIT_CPU on the launcher had the kernel SIGKILL it,
// supervisor and ledger writer with it. A call on a process in the run, or on a thread of the caller's own
// process, is continued with no line.
func TestProcessScope(t *testing.T) {
	const (
		agent    = 100 // the caller, in the run
		thread   = 107 // a thread of the caller
		child    = 101 // in the run, beneath its cgroup
		launcher = 50  // outside the run
		agentPG  = 100
		mixedPG  = 50 // the launcher's group, which the agent shares
	)
	nr := func(x86, arm int32) int32 {
		if nativeAuditArch() == auditArchARM {
			return arm
		}
		return x86
	}
	prlimit := nr(nrX86Prlimit64, nrARMPrlimit64)
	setprio := nr(nrX86Setpriority, nrARMSetpriority)
	ioprio := nr(nrX86IoprioSet, nrARMIoprioSet)
	affinity := nr(nrX86SchedSetaffinity, nrARMSchedSetaffinity)
	sched := nr(nrX86SchedSetscheduler, nrARMSchedSetscheduler)
	for _, tc := range []struct {
		name  string
		nr    int32
		args  []uint64
		allow bool
	}{
		{"prlimit64 of the launcher", prlimit, []uint64{launcher, unix.RLIMIT_CPU, 0x1000}, false},
		{"prlimit64 of a child", prlimit, []uint64{child, unix.RLIMIT_CPU, 0x1000}, true},
		{"prlimit64 of its own thread", prlimit, []uint64{thread, unix.RLIMIT_NOFILE, 0x1000}, true},
		{"prlimit64 of a pid that is gone", prlimit, []uint64{999, unix.RLIMIT_CPU, 0x1000}, true},
		{"sched_setaffinity of the launcher", affinity, []uint64{launcher, 8, 0x1000}, false},
		{"sched_setscheduler of a child", sched, []uint64{child, 5, 0x1000}, true},
		{"setpriority of the launcher", setprio, []uint64{prioProcess, launcher, 19}, false},
		{"setpriority of a child", setprio, []uint64{prioProcess, child, 19}, true},
		{"setpriority of its own group, which holds the launcher", setprio, []uint64{prioPgrp, 0, 19}, false},
		{"setpriority of a group all in the run", setprio, []uint64{prioPgrp, agentPG, 19}, true},
		{"setpriority of its uid", setprio, []uint64{prioUser, 0, 19}, false},
		{"ioprio_set of the launcher", ioprio, []uint64{ioprioWhoProcess, launcher, 0}, false},
		{"ioprio_set of its uid", ioprio, []uint64{ioprioWhoUser, 0, 0}, false},
		{"ioprio_set of a child", ioprio, []uint64{ioprioWhoProcess, child, 0}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.tgid = map[int]int{thread: agent}
			f.cgroups = map[int]string{agent: "/user.slice/run-1.scope", child: "/user.slice/run-1.scope/sub",
				102: "/user.slice/run-1.scope", launcher: "/user.slice/tego.scope"}
			f.pgrps = map[int]int{agent: mixedPG, child: agentPG, 102: agentPG, launcher: mixedPG}
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/user.slice/run-1.scope"
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(tc.nr, agent, tc.args...))
			got, _ := f.lastResp()
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.allow {
				t.Fatalf("response %+v: continued=%v, want %v", got, cont, tc.allow)
			}
			evs := sink.all()
			if tc.allow {
				if len(evs) != 0 {
					t.Errorf("an allowed call was recorded: %+v", evs)
				}
				return
			}
			if got.Error != -int32(unix.EPERM) {
				t.Errorf("refused with %d, want EPERM", got.Error)
			}
			if len(evs) != 1 || evs[0].Kind != record.KindRefused || evs[0].Rule != ruleProcessScope ||
				evs[0].Reason != record.ReasonLandlockTopology {
				t.Errorf("events %+v, want one refused process-scope line", evs)
			}
		})
	}
}

// TestProcessScopeFailsClosedWithNoCgroup: a loop that does not know its run's cgroup cannot tell the launcher from
// a child, so it refuses rather than continuing; an observe run continues and refuses nothing (R30).
func TestProcessScopeFailsClosedWithNoCgroup(t *testing.T) {
	prlimit := int32(nrX86Prlimit64)
	if nativeAuditArch() == auditArchARM {
		prlimit = nrARMPrlimit64
	}
	f := newFake()
	f.cgroups = map[int]string{100: "/user.slice/run-1.scope", 50: "/user.slice/tego.scope"}
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(prlimit, 100, 50, unix.RLIMIT_CPU, 0x1000))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.EPERM) {
		t.Errorf("prlimit64 with no run cgroup: %+v, want EPERM", got)
	}
	f = newFake()
	pol := testPolicy(nil, nil, nil)
	pol.Observe = true
	l, _ = newTestLoop(t, f, pol)
	l.handle(notifFor(prlimit, 100, 50, unix.RLIMIT_CPU, 0x1000))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Errorf("prlimit64 under observe: %+v, want continued", got)
	}
}
