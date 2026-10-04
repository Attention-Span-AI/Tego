// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSignalsToANonPositiveTaskAreTheKernels: tkill and tgkill with an id <= 0 are EINVAL to the kernel,
// and rt_sigqueueinfo and rt_tgsigqueueinfo with one are ESRCH or EINVAL. The loop read such a pid as
// process group 0 — the host's kernel threads, all outside the run — and refused EPERM with a refused line,
// or continued on a host where no process reports group 0. They are continued, so the kernel answers.
func TestSignalsToANonPositiveTaskAreTheKernels(t *testing.T) {
	const agent = 100
	nrs := map[string]int32{"tkill": nrX86Tkill, "tgkill": nrX86Tgkill, "rt_sigqueueinfo": nrX86RtSigqueue,
		"rt_tgsigqueueinfo": nrX86RtTgsigq}
	if nativeAuditArch() == auditArchARM {
		nrs = map[string]int32{"tkill": nrARMTkill, "tgkill": nrARMTgkill, "rt_sigqueueinfo": nrARMRtSigqueue,
			"rt_tgsigqueueinfo": nrARMRtTgsigq}
	}
	neg := ^uint64(0)
	for _, tc := range []struct {
		op   string
		args []uint64
	}{
		{"tkill", []uint64{0, 9}},
		{"tkill", []uint64{neg, 9}},
		{"tgkill", []uint64{neg, 5, 9}},
		{"tgkill", []uint64{0, 5, 9}},
		{"rt_sigqueueinfo", []uint64{0, 9, 0}},
		{"rt_tgsigqueueinfo", []uint64{neg, 5, 9, 0}},
	} {
		f := newFake()
		f.cgroups = map[int]string{agent: "/user.slice/run-1.scope", 2: "/"}
		f.pgrps = map[int]int{agent: agent, 2: 0} // kthreadd and the kernel threads report group 0
		pol := testPolicy(nil, nil, nil)
		pol.Cgroup = "/user.slice/run-1.scope"
		l, sink := newTestLoop(t, f, pol)
		l.handle(notifFor(nrs[tc.op], agent, tc.args...))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Errorf("%s%v: %+v, want continued for the kernel to answer", tc.op, tc.args, got)
		}
		if evs := sink.all(); len(evs) != 0 {
			t.Errorf("%s%v recorded %+v", tc.op, tc.args, evs)
		}
	}
}

// TestARefusedLineNamesItsTarget: kill(0), setpriority(PRIO_PGRP, 0) and ioprio_set(IOPRIO_WHO_PGRP, 0)
// name the caller's own process group, and the refused line read "pid 0"; setpriority(PRIO_USER) and
// ioprio_set(IOPRIO_WHO_USER) name a uid, and the line read "every process (-1)", kill(-1)'s wording. The
// line names the group the decision resolved and the uid the call named (R33, R35).
func TestARefusedLineNamesItsTarget(t *testing.T) {
	const agent, launcher, mixedPG = 100, 50, 50
	nr := func(x86, arm int32) int32 {
		if nativeAuditArch() == auditArchARM {
			return arm
		}
		return x86
	}
	kill, setprio, ioprio := nr(nrX86Kill, nrARMKill), nr(nrX86Setpriority, nrARMSetpriority), nr(nrX86IoprioSet, nrARMIoprioSet)
	for _, tc := range []struct {
		name string
		nr   int32
		args []uint64
		want string
	}{
		{"kill(0)", kill, []uint64{0, 9}, "process group 50"},
		{"kill(-1)", kill, []uint64{^uint64(0), 9}, "every process (-1)"},
		{"setpriority(PRIO_PGRP, 0)", setprio, []uint64{prioPgrp, 0, 19}, "process group 50"},
		{"ioprio_set(IOPRIO_WHO_PGRP, 0)", ioprio, []uint64{ioprioWhoPgrp, 0, 0}, "process group 50"},
		{"setpriority(PRIO_USER, 0)", setprio, []uint64{prioUser, 0, 19}, "every process of the caller's uid"},
		{"setpriority(PRIO_USER, 1000)", setprio, []uint64{prioUser, 1000, 19}, "every process of uid 1000"},
		{"ioprio_set(IOPRIO_WHO_USER, 1000)", ioprio, []uint64{ioprioWhoUser, 1000, 0}, "every process of uid 1000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.cgroups = map[int]string{agent: "/user.slice/run-1.scope", launcher: "/user.slice/tego.scope"}
			f.pgrps = map[int]int{agent: mixedPG, launcher: mixedPG}
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/user.slice/run-1.scope"
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(tc.nr, agent, tc.args...))
			evs := sink.all()
			if len(evs) != 1 {
				t.Fatalf("events %+v, want one refused line", evs)
			}
			var p record.RefusedPayload
			if err := evs[0].DecodePayload(&p); err != nil || p.Target != tc.want {
				t.Errorf("target %q (%v), want %q", p.Target, err, tc.want)
			}
		})
	}
}
