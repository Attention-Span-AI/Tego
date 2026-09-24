// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fakeMembers is a runMembers whose two kernel reads are tables, counting how often each is asked.
func fakeMembers(runPath string, runID uint64, ids map[int]uint64, paths map[uint64]string) (*runMembers, *int, *int) {
	var idCalls, pathCalls int
	m := &runMembers{mount: "/sys/fs/cgroup", runPath: runPath, runID: runID, mountFD: -1, known: map[uint64]bool{}}
	m.idOf = func(pid int) (uint64, error) {
		idCalls++
		id, ok := ids[pid]
		if !ok {
			return 0, unix.ESRCH
		}
		return id, nil
	}
	m.pathOf = func(id uint64) (string, error) {
		pathCalls++
		p, ok := paths[id]
		if !ok {
			return "", unix.ESTALE
		}
		return p, nil
	}
	return m, &idCalls, &pathCalls
}

// TestRunMembersAnswersByCgroupID is membership by cgroup id (§6 E34): the run's own cgroup is answered from its id
// alone, a descendant and a host cgroup are named once through the cgroup filesystem and then answered from
// what that said, and whatever the id path cannot answer (an exited opener, a cgroup removed before it was
// named) is left to /proc/<pid>/cgroup rather than guessed.
func TestRunMembersAnswersByCgroupID(t *testing.T) {
	t.Parallel()
	const run = "/tego.slice/run-1.scope"
	m, idCalls, pathCalls := fakeMembers(run, 10,
		map[int]uint64{100: 10, 101: 11, 102: 12, 103: 13, 104: 14},
		map[uint64]string{11: run + "/agent", 12: "/system.slice/cron.service", 13: "/tego.slice/run-1.scopex"})

	for _, tc := range []struct {
		pid    int
		member bool
		ok     bool
	}{
		{100, true, true},   // the run's own cgroup, by id
		{101, true, true},   // a descendant
		{102, false, true},  // a host service
		{103, false, true},  // a sibling whose name only starts like the run's
		{104, false, false}, // a cgroup gone before it was named: /proc decides
		{105, false, false}, // an opener gone: /proc decides, and says ErrProcGone
	} {
		member, ok := m.lookup(tc.pid)
		if member != tc.member || ok != tc.ok {
			t.Errorf("lookup(%d) = %v, %v; want %v, %v", tc.pid, member, ok, tc.member, tc.ok)
		}
	}
	if *pathCalls != 4 {
		t.Fatalf("named %d cgroups, want 4: the run's own id needs no name", *pathCalls)
	}
	// A cgroup never moves and its id names it alone, so what one id was is what it stays.
	for range 3 {
		for _, pid := range []int{101, 102, 103} {
			m.lookup(pid)
		}
	}
	if *pathCalls != 4 {
		t.Fatalf("named %d cgroups after asking again, want the 4 of the first round", *pathCalls)
	}
	// An id that could not be named is not remembered: the next event from it asks again.
	m.lookup(104)
	if *pathCalls != 5 {
		t.Fatalf("named %d cgroups, want a fresh attempt for the unnamed one", *pathCalls)
	}
	if *idCalls == 0 {
		t.Fatal("no id was read")
	}
}

// TestRunMembersStopsAskingAKernelWithoutTheIoctl: on a kernel without PIDFD_GET_INFO every call fails the same
// way (pidfdInfoErr), and asking it on every event would add a pidfd and a failed ioctl to each membership read
// /proc then answers anyway.
func TestRunMembersStopsAskingAKernelWithoutTheIoctl(t *testing.T) {
	t.Parallel()
	m, idCalls, _ := fakeMembers("/run.scope", 10, nil, nil)
	m.idOf = func(int) (uint64, error) { *idCalls++; return 0, errNoPidfdInfo }
	for range 5 {
		if _, ok := m.lookup(1); ok {
			t.Fatal("a kernel without the ioctl answered")
		}
	}
	if *idCalls != 1 {
		t.Fatalf("asked the kernel %d times, want once", *idCalls)
	}
	// An exited opener is no reason to stop asking.
	m2, idCalls2, _ := fakeMembers("/run.scope", 10, nil, nil)
	for range 3 {
		m2.lookup(1)
	}
	if *idCalls2 != 3 {
		t.Fatalf("asked %d times after ESRCH, want every time", *idCalls2)
	}
}

// TestPidfdInfoErrorsThatMeanNoIoctl pins which refusals of PIDFD_GET_INFO say the kernel has no such ioctl
// (§6 E34). Below 6.11 a pidfd has no ioctl handler and the answer is ENOTTY; on 6.11 and 6.12 it has one for
// the namespace ioctls, which refuses a non-zero argument with EINVAL first, and Debian 13's and AL2023's 6.12
// answer PIDFD_GET_INFO so. Reading only ENOTTY as "no ioctl" left the id path asking on every event there, and
// failed TestCgroupIDOfPIDMatchesTheDirectory. An exited opener's ESRCH, and anything else, is not the kernel's
// answer about the ioctl and must not latch it off.
func TestPidfdInfoErrorsThatMeanNoIoctl(t *testing.T) {
	t.Parallel()
	for _, errno := range []unix.Errno{unix.ENOTTY, unix.EINVAL} {
		if err := pidfdInfoErr(errno); !errors.Is(err, errNoPidfdInfo) {
			t.Errorf("PIDFD_GET_INFO refused with %v read as %v, want errNoPidfdInfo", errno, err)
		}
	}
	for _, errno := range []unix.Errno{unix.ESRCH, unix.EFAULT, unix.E2BIG, unix.EPERM, unix.EREMOTE} {
		if err := pidfdInfoErr(errno); errors.Is(err, errNoPidfdInfo) || !errors.Is(err, errno) {
			t.Errorf("PIDFD_GET_INFO refused with %v read as %v, want it as it is", errno, err)
		}
	}
}

// TestRunMembersForgetsPastItsCap keeps the cache bounded on a host with more cgroups than it holds, and
// still answers correctly after it starts over.
func TestRunMembersForgetsPastItsCap(t *testing.T) {
	t.Parallel()
	const run = "/run.scope"
	m, _, _ := fakeMembers(run, 1, nil, nil)
	m.idOf = func(pid int) (uint64, error) { return uint64(pid), nil }
	m.pathOf = func(id uint64) (string, error) {
		if id%2 == 0 {
			return run + "/c", nil
		}
		return "/host", nil
	}
	for pid := 2; pid < membersCap*2+10; pid++ {
		member, ok := m.lookup(pid)
		if !ok || member != (pid%2 == 0) {
			t.Fatalf("lookup(%d) = %v, %v", pid, member, ok)
		}
	}
	if n := len(m.known); n > membersCap {
		t.Fatalf("%d ids remembered, cap %d", n, membersCap)
	}
}

// TestDecideEventAsksByIDBeforeProc: the listener takes the id's answer when there is one, and reads
// /proc/<pid>/cgroup only when there is not.
func TestDecideEventAsksByIDBeforeProc(t *testing.T) {
	t.Parallel()
	const run = "/tego.slice/run-1.scope"
	dir := t.TempDir()
	secret := dir + "/secret"
	if err := os.WriteFile(secret, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(secret, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	procReads := 0
	l := &fanotifyListener{
		policy: &policy{runCgroup: run, denyRead: newPathSet([]fsEntry{{path: secret, dir: true, rule: "fs.deny_read[secret]"}})},
		run:    Run{CgroupPath: run, CgroupID: 10}, now: time.Now,
		cgroupOfPID: func(int) (string, error) { procReads++; return run, nil },
	}
	l.members, _, _ = fakeMembers(run, 10, map[int]uint64{100: 10, 102: 12}, map[uint64]string{12: "/host.slice"})

	ev := func(pid int32) fanEvent {
		return fanEvent{Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(fd), PID: pid}
	}
	if v, err := l.decideEvent(ev(100)); err != nil || v.allow {
		t.Fatalf("an opener in the run's cgroup: %+v, %v; want the refusal", v, err)
	}
	if v, err := l.decideEvent(ev(102)); err != nil || !v.allow {
		t.Fatalf("a host opener: %+v, %v; want an allow", v, err)
	}
	if procReads != 0 {
		t.Fatalf("read /proc %d times though the id answered", procReads)
	}
	// No id for this opener: /proc decides, and its answer (the run's own path here) stands.
	if v, err := l.decideEvent(ev(103)); err != nil || v.allow {
		t.Fatalf("an opener the id path cannot answer: %+v, %v; want /proc's refusal", v, err)
	}
	if procReads != 1 {
		t.Fatalf("read /proc %d times, want once for the opener with no id", procReads)
	}
}

// TestCgroupIDOfPIDMatchesTheDirectory asks the running kernel for this process's cgroup id through a pidfd
// and compares it with the inode of the cgroup directory /proc names: the two routes must agree, since the id
// path answers what the /proc path used to. A kernel without the ioctl (ENOTTY below 6.11, EINVAL on 6.11 and
// 6.12 unless it was backported) is the fallback's case, and skips; any other refusal is a failure.
func TestCgroupIDOfPIDMatchesTheDirectory(t *testing.T) {
	t.Parallel()
	id, err := cgroupIDOfPID(os.Getpid())
	if errors.Is(err, errNoPidfdInfo) {
		t.Skipf("this kernel has no PIDFD_GET_INFO cgroup id, and /proc answers alone: %v", err)
	}
	if err != nil {
		t.Fatalf("cgroupIDOfPID(self): %v", err)
	}
	path, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Skipf("no cgroup v2 path for this process: %v", err)
	}
	want, err := cgroupIDOfPath(identity.SystemCgroupRoot, path)
	if err != nil {
		t.Skipf("cgroup directory %s not visible here: %v", path, err)
	}
	if id != want {
		t.Fatalf("pidfd cgroup id %d, directory %s has id %d", id, path, want)
	}
	if _, err := cgroupIDOfPID(1 << 30); err == nil {
		t.Fatal("an impossible pid had a cgroup id")
	}
}

// TestRunMembersClosesWhileADecisionNames: a decision answered at E16's deadline keeps running after the
// listener has closed, and may still be naming a cgroup then; the close must wait for that read rather than
// race it on the mount descriptor. Run under -race, this is what the detector would see.
func TestRunMembersClosesWhileADecisionNames(t *testing.T) {
	t.Parallel()
	m := newRunMembers(Run{CgroupPath: "/run.scope", CgroupID: 1})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 200 {
			_, _ = m.pathOf(12345)
		}
	}()
	m.close()
	<-done
	if _, err := m.pathOf(12345); !errors.Is(err, unix.EBADF) {
		t.Fatalf("naming after close: %v, want EBADF", err)
	}
	m.close()
}
