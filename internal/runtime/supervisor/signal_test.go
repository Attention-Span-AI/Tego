// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"encoding/binary"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSignalScopeBelowABI6: below Landlock ABI 6 the ruleset has no signal scope, and the agent, sharing its
// launcher's uid at tier 1, could SIGKILL or SIGSTOP the launcher and signal every other process of the user.
// The loop continues a signal whose every target is in the run's cgroup and refuses any other EPERM, with a
// refused line, as the ABI-6 scope would.
func TestSignalScopeBelowABI6(t *testing.T) {
	const (
		agent    = 100 // the caller, in the run
		child    = 101 // in the run, beneath its cgroup
		launcher = 50  // outside the run
		shell    = 40  // outside the run
		agentPG  = 100
		mixedPG  = 50 // the launcher's group, which the agent shares
	)
	nrs := map[string]int32{"kill": nrX86Kill, "tkill": nrX86Tkill, "tgkill": nrX86Tgkill, "rt_sigqueueinfo": nrX86RtSigqueue,
		"rt_tgsigqueueinfo": nrX86RtTgsigq, "fcntl": nrX86Fcntl}
	if nativeAuditArch() == auditArchARM {
		nrs = map[string]int32{"kill": nrARMKill, "tkill": nrARMTkill, "tgkill": nrARMTgkill, "rt_sigqueueinfo": nrARMRtSigqueue,
			"rt_tgsigqueueinfo": nrARMRtTgsigq, "fcntl": nrARMFcntl}
	}
	neg := func(v int) uint64 { return uint64(int64(v)) }
	for _, tc := range []struct {
		name  string
		op    string
		args  []uint64
		allow bool
	}{
		{"kill a child in the run", "kill", []uint64{child, 9}, true},
		{"kill itself", "kill", []uint64{agent, 15}, true},
		{"kill the launcher", "kill", []uint64{launcher, 9}, false},
		{"probe the launcher with signal 0", "kill", []uint64{launcher, 0}, false},
		{"kill the user's shell", "kill", []uint64{shell, 1}, false},
		{"kill every process", "kill", []uint64{neg(-1), 9}, false},
		{"kill a group all in the run", "kill", []uint64{neg(-agentPG), 15}, true},
		{"kill the launcher's group", "kill", []uint64{neg(-mixedPG), 19}, false},
		{"kill its own group, which holds the launcher", "kill", []uint64{0, 9}, false},
		{"kill a pid that is gone", "kill", []uint64{999, 9}, true},
		{"tgkill its own thread", "tgkill", []uint64{agent, 7, 23}, true},
		{"tgkill the launcher", "tgkill", []uint64{launcher, launcher, 9}, false},
		{"tkill a thread in the run", "tkill", []uint64{child, 10}, true},
		{"tkill a launcher thread", "tkill", []uint64{launcher, 19}, false},
		{"rt_sigqueueinfo to the launcher", "rt_sigqueueinfo", []uint64{launcher, 9, 0}, false},
		{"rt_tgsigqueueinfo in the run", "rt_tgsigqueueinfo", []uint64{child, child, 10, 0}, true},
		{"F_SETOWN to the launcher", "fcntl", []uint64{3, unix.F_SETOWN, launcher}, false},
		{"F_SETOWN to a child", "fcntl", []uint64{3, unix.F_SETOWN, child}, true},
		{"F_SETOWN cleared", "fcntl", []uint64{3, unix.F_SETOWN, 0}, true},
		{"F_SETOWN to the launcher's group", "fcntl", []uint64{3, unix.F_SETOWN, neg(-mixedPG)}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.cgroups = map[int]string{agent: "/user.slice/run-1.scope", child: "/user.slice/run-1.scope/sub",
				launcher: "/user.slice/tego.scope", shell: "/user.slice/session.scope"}
			f.pgrps = map[int]int{agent: mixedPG, child: agentPG, 102: agentPG, launcher: mixedPG, shell: shell}
			f.cgroups[102] = "/user.slice/run-1.scope"
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/user.slice/run-1.scope"
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(nrs[tc.op], agent, tc.args...))
			got, _ := f.lastResp()
			cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
			if cont != tc.allow {
				t.Fatalf("response %+v: continued=%v, want %v", got, cont, tc.allow)
			}
			evs := sink.all()
			if tc.allow {
				if len(evs) != 0 {
					t.Errorf("an allowed signal was recorded: %d events", len(evs))
				}
				return
			}
			if got.Error != -int32(unix.EPERM) {
				t.Errorf("refused with %d, want EPERM", got.Error)
			}
			if len(evs) != 1 || evs[0].Kind != record.KindRefused || evs[0].Rule != ruleSignalScope ||
				evs[0].Reason != record.ReasonLandlockTopology {
				t.Errorf("events %+v, want one refused signal-scope line", evs)
			}
		})
	}
}

// TestSignalToItselfReadsNoProcStatus: raise, abort and pthread_kill signal the caller's own process, and
// below ABI 6 each one is notified. The caller's thread group is read once and then taken from the cache,
// never again from /proc/<tid>/status per signal, and a tkill, which names a thread, reads none.
func TestSignalToItselfReadsNoProcStatus(t *testing.T) {
	const agent, thread = 100, 107
	f := newFake()
	f.tgid = map[int]int{thread: agent}
	f.cgroups = map[int]string{agent: "/user.slice/run-1.scope", thread: "/user.slice/run-1.scope"}
	pol := testPolicy(nil, nil, nil)
	pol.Cgroup = "/user.slice/run-1.scope"
	l, _ := newTestLoop(t, f, pol)
	tgkill, tkill := int32(nrX86Tgkill), int32(nrX86Tkill)
	if nativeAuditArch() == auditArchARM {
		tgkill, tkill = nrARMTgkill, nrARMTkill
	}
	for i := 0; i < 5; i++ {
		l.handle(notifFor(tgkill, thread, agent, thread, 6))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("tgkill of its own thread: %+v, want continued", got)
		}
	}
	if f.tgidReads > 1 {
		t.Errorf("%d /proc/<tid>/status reads for five signals to its own process, want at most one", f.tgidReads)
	}
	reads := f.tgidReads
	l.handle(notifFor(tkill, thread, thread, 6))
	if f.tgidReads != reads {
		t.Errorf("a tkill read the caller's thread group (%d reads), which a thread target never uses", f.tgidReads-reads)
	}
}

// TestSignalScopeReadsFSetownEx: F_SETOWN_EX's owner is a struct in the caller's memory.
func TestSignalScopeReadsFSetownEx(t *testing.T) {
	nr := int32(nrX86Fcntl)
	if nativeAuditArch() == auditArchARM {
		nr = nrARMFcntl
	}
	owner := func(typ, pid uint32) []byte {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, typ)
		binary.LittleEndian.PutUint32(b[4:], pid)
		return b
	}
	for _, tc := range []struct {
		name  string
		owner []byte
		allow bool
	}{
		{"a pid outside", owner(1, 50), false},
		{"a thread inside", owner(0, 101), true},
		{"a group outside", owner(2, 50), false},
		{"cleared", owner(1, 0), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.cgroups = map[int]string{100: "/run.scope", 101: "/run.scope", 50: "/other.scope"}
			f.pgrps = map[int]int{50: 50}
			f.put(0x1000, tc.owner)
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/run.scope"
			l, _ := newTestLoop(t, f, pol)
			l.handle(notifFor(nr, 100, 3, unix.F_SETOWN_EX, 0x1000))
			got, _ := f.lastResp()
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.allow {
				t.Errorf("continued=%v, want %v (%+v)", cont, tc.allow, got)
			}
		})
	}
}

// TestALineNamesTheProcessAndTheThread: seccomp reports the thread that trapped, and both pid and tid
// carried it, so every thread of a multi-threaded agent read as a process of its own.
func TestALineNamesTheProcessAndTheThread(t *testing.T) {
	f := newFake()
	f.tgid = map[int]int{101: 100}
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	ev := l.event(notifFor(1, 101), record.KindFS, record.SourceSeccomp)
	if ev.PID != 100 || ev.TID != 101 {
		t.Fatalf("pid %d tid %d, want the process 100 and the thread 101", ev.PID, ev.TID)
	}
	reads := f.tgidReads
	if ev := l.event(notifFor(1, 101), record.KindFS, record.SourceSeccomp); ev.PID != 100 || f.tgidReads != reads {
		t.Fatalf("pid %d on the second line after %d more reads, want the cached 100 and no read", ev.PID, f.tgidReads-reads)
	}
	// Thread 101 exits and the kernel hands its id to a new process's leader: the cached group no longer
	// holds it, so the id is read again rather than naming the dead thread's process.
	f.mu.Lock()
	f.tgid[101] = 101
	f.mu.Unlock()
	if ev := l.event(notifFor(1, 101), record.KindFS, record.SourceSeccomp); ev.PID != 101 {
		t.Fatalf("pid %d after tid 101 was reused as a process of its own, want 101", ev.PID)
	}
}

// TestGroupSignalsShareOneProcScan: below ABI 6 a group signal is decided over every member, and there is
// no kernel interface that lists a group, so the host's whole /proc is read (~15 ms at 500 processes, on
// one of four workers). A job-control shell or test runner polling a group with kill(-pgid, 0) paid that on
// every call; one scan now answers the group signals of the next groupScanTTL. A group the scan did not
// find is read again, since an empty group is continued: one a run process just made must not ride on a
// snapshot from before it existed.
func TestGroupSignalsShareOneProcScan(t *testing.T) {
	kill := int32(nrX86Kill)
	if nativeAuditArch() == auditArchARM {
		kill = nrARMKill
	}
	neg := func(v int) uint64 { return uint64(int64(v)) }
	f := newFake()
	f.cgroups = map[int]string{100: "/run.scope", 101: "/run.scope", 50: "/other.scope"}
	f.pgrps = map[int]int{100: 50, 101: 101, 50: 50}
	pol := testPolicy(nil, nil, nil)
	pol.Cgroup = "/run.scope"
	l, _ := newTestLoop(t, f, pol)
	for i := 0; i < 5; i++ {
		l.handle(notifFor(kill, 100, neg(-101), 0))
		if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
			t.Fatalf("kill(-101) %d refused: %+v, want the in-run group continued", i, got)
		}
	}
	if f.groupScans != 1 {
		t.Errorf("five group signals within the window scanned /proc %d times, want 1", f.groupScans)
	}
	// A group the snapshot does not hold: a run process makes it (setpgid(0, 0), so it leads it) and signals
	// it at once.
	f.mu.Lock()
	f.cgroups[103], f.pgrps[103] = "/run.scope", 103
	f.cgroups[102], f.pgrps[102] = "/other.scope", 103 // and one outside the run is in it
	f.mu.Unlock()
	l.handle(notifFor(kill, 100, neg(-103), 9))
	if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) {
		t.Errorf("kill(-103) = %+v, want EPERM: the new group holds a process outside the run", got)
	}
	if f.groupScans != 2 {
		t.Errorf("scans = %d, want a fresh one for a group the snapshot did not hold", f.groupScans)
	}
}

// TestASignalToNoGroupScansNothingNew: a group absent from the snapshot was scanned for again on every call,
// under the group cache's lock, so kill(-99999, 0) in a loop cost one whole-host /proc scan per call, on
// host CPU the run's cpu.max does not count. A group made since the scan has its leader in it (setpgid(p, p),
// setsid), so a pgid whose process is gone, or in another group, is answered empty from the snapshot.
func TestASignalToNoGroupScansNothingNew(t *testing.T) {
	kill := int32(nrX86Kill)
	if nativeAuditArch() == auditArchARM {
		kill = nrARMKill
	}
	neg := func(v int) uint64 { return uint64(int64(v)) }
	f := newFake()
	f.cgroups = map[int]string{100: "/run.scope", 101: "/run.scope", 50: "/other.scope"}
	f.pgrps = map[int]int{100: 100, 101: 100, 50: 50}
	pol := testPolicy(nil, nil, nil)
	pol.Cgroup = "/run.scope"
	l, _ := newTestLoop(t, f, pol)
	// 99999 names no process; 101 is a process, but of group 100.
	for _, pgid := range []int{99999, 101} {
		for i := 0; i < 20; i++ {
			l.handle(notifFor(kill, 100, neg(-pgid), 0))
			if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Fatalf("kill(-%d) %d = %+v, want continued for the kernel to answer ESRCH", pgid, i, got)
			}
		}
	}
	if f.groupScans != 1 {
		t.Errorf("40 signals to groups that do not exist scanned /proc %d times, want 1", f.groupScans)
	}
	// An unreadable leader is not read as absent: the group is scanned for, and the scan's failure refuses.
	f.mu.Lock()
	f.pgrpErrs = map[int]error{77: unix.EACCES}
	f.mu.Unlock()
	l.handle(notifFor(kill, 100, neg(-77), 9))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Errorf("kill(-77) with its leader unreadable was continued: %+v", got)
	}
}

// TestANonPositiveThreadTargetScansNothing: tkill, tgkill and the rt_*sigqueueinfo pair name one process or
// thread, and the kernel signals nothing for a target of 0 or below. Such a call was read as group 0, which
// no snapshot holds, so every one rescanned the whole host's /proc under the group cache's lock. It is
// continued unread now, and the kernel answers it.
func TestANonPositiveThreadTargetScansNothing(t *testing.T) {
	nrs := map[string]int32{"tkill": nrX86Tkill, "tgkill": nrX86Tgkill, "rt_sigqueueinfo": nrX86RtSigqueue,
		"rt_tgsigqueueinfo": nrX86RtTgsigq}
	if nativeAuditArch() == auditArchARM {
		nrs = map[string]int32{"tkill": nrARMTkill, "tgkill": nrARMTgkill, "rt_sigqueueinfo": nrARMRtSigqueue,
			"rt_tgsigqueueinfo": nrARMRtTgsigq}
	}
	neg := func(v int) uint64 { return uint64(int64(v)) }
	for op, nr := range nrs {
		for _, target := range []uint64{0, neg(-1), neg(-50)} {
			f := newFake()
			f.cgroups = map[int]string{100: "/run.scope", 50: "/other.scope"}
			f.pgrps = map[int]int{100: 100, 50: 50}
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/run.scope"
			l, sink := newTestLoop(t, f, pol)
			for i := 0; i < 3; i++ {
				l.handle(notifFor(nr, 100, target, 0, 9, 0))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("%s(%d) = %+v, want continued for the kernel to answer", op, int64(target), got)
				}
			}
			if f.groupScans != 0 || f.memReads != 0 {
				t.Errorf("%s(%d) x3: %d group scans, %d memory reads, want none", op, int64(target), f.groupScans, f.memReads)
			}
			if evs := sink.all(); len(evs) != 0 {
				t.Errorf("%s(%d) was recorded: %+v", op, int64(target), evs)
			}
		}
	}
}

// TestAGroupScanThatCannotReadAProcessRefuses: the /proc scan behind a group signal skipped every process
// whose stat it failed to read, whatever the error. Out of descriptors (EMFILE), the launcher's own
// process dropped out of the snapshot of its group, the run's members were all that was left, and
// kill(-launcher's group) was continued to the launcher (R33). Only a process that exited is skipped now;
// any other failure refuses the signal, and the failed scan is not cached.
func TestAGroupScanThatCannotReadAProcessRefuses(t *testing.T) {
	kill := int32(nrX86Kill)
	if nativeAuditArch() == auditArchARM {
		kill = nrARMKill
	}
	neg := func(v int) uint64 { return uint64(int64(v)) }
	f := newFake()
	f.cgroups = map[int]string{100: "/run.scope", 50: "/other.scope"}
	f.pgrps = map[int]int{100: 50, 50: 50}
	f.pgrpErrs = map[int]error{50: fmt.Errorf("read /proc/50/stat: %w", unix.EMFILE), 60: unix.ESRCH}
	pol := testPolicy(nil, nil, nil)
	pol.Cgroup = "/run.scope"
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(kill, 100, neg(-50), 9))
	if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) {
		t.Fatalf("kill(-50) with the launcher's stat unreadable = %+v, want EPERM", got)
	}
	if evs := sink.all(); len(evs) != 1 || evs[0].Kind != record.KindRefused {
		t.Errorf("events %+v, want one refused line", evs)
	}
	// The descriptors come back: the next signal scans again rather than answering from the failed scan,
	// and it still refuses, now because it reads the launcher as outside the run.
	f.mu.Lock()
	delete(f.pgrpErrs, 50)
	f.mu.Unlock()
	l.handle(notifFor(kill, 100, neg(-50), 9))
	if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) {
		t.Errorf("kill(-50) = %+v, want EPERM", got)
	}
	if f.groupScans != 2 {
		t.Errorf("scans = %d, want 2: a failed scan is not cached", f.groupScans)
	}
}
