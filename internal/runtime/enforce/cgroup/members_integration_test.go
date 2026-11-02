// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// res11Tree builds cgroups of its own under the cgroup2 root, a run with a descendant and a sibling outside
// it, each holding a sleeping process, and returns the run's path and the pids by place. It needs root.
func res11Tree(t testing.TB) (string, map[string]int) {
	t.Helper()
	base := fmt.Sprintf("/ey-res11-%d", os.Getpid())
	root := identity.SystemCgroupRoot
	dirs := []string{base, base + "/run", base + "/run/child", base + "/out"}
	for _, d := range dirs {
		if err := os.Mkdir(root+d, 0o755); err != nil {
			t.Skipf("make cgroup %s needs root: %v", d, err)
		}
	}
	pids := map[string]int{}
	var procs []*exec.Cmd
	t.Cleanup(func() {
		for _, c := range procs {
			_ = c.Process.Kill()
			_ = c.Wait()
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			_ = os.Remove(root + dirs[i])
		}
	})
	for _, place := range []string{"/run", "/run/child", "/out"} {
		c := exec.Command("sleep", "600")
		if err := c.Start(); err != nil {
			t.Fatalf("start a process for %s: %v", place, err)
		}
		procs = append(procs, c)
		if err := os.WriteFile(root+base+place+"/cgroup.procs", []byte(strconv.Itoa(c.Process.Pid)), 0o644); err != nil {
			t.Fatalf("move %d into %s: %v", c.Process.Pid, place, err)
		}
		pids[place] = c.Process.Pid
	}
	return base + "/run", pids
}

// TestRunMembersMatchesProc is the id path's acceptance on a kernel with PIDFD_GET_INFO's cgroup id (§6 E34;
// upstream from 6.13, and RHEL 9's 5.14 by backport): for a process in the run's own cgroup, one in a
// descendant, one outside the run, the launcher itself and pid 1, the id path answers, and answers what
// /proc/<pid>/cgroup does; an opener that has exited, and a cgroup removed before it was named, are left to
// /proc rather than answered. A kernel without the ioctl, whichever errno it refuses it with (pidfdInfoErr), holds
// the other half: the id path answers nothing, says so once, and /proc still tells the same processes apart. It takes
// no skip, since root-must-pass.txt holds this test on every kernel a full root run meets. One that refuses the ioctl
// otherwise fails here.
func TestRunMembersMatchesProc(t *testing.T) {
	_, infoErr := cgroupIDOfPID(os.Getpid())
	run, pids := res11Tree(t)
	runID, err := cgroupIDOfPath(identity.SystemCgroupRoot, run)
	if err != nil {
		t.Fatal(err)
	}
	m := newRunMembers(Run{CgroupPath: run, CgroupID: runID})
	defer m.close()
	if errors.Is(infoErr, errNoPidfdInfo) {
		for name, tc := range map[string]struct {
			pid  int
			want bool
		}{"run": {pids["/run"], true}, "descendant": {pids["/run/child"], true}, "outside": {pids["/out"], false}} {
			if _, ok := m.lookup(tc.pid); ok {
				t.Fatalf("%s (%d): the id path answered on a kernel without PIDFD_GET_INFO", name, tc.pid)
			}
			path, err := cgroupPathOfPID(tc.pid)
			if err != nil {
				t.Fatalf("%s (%d): /proc: %v", name, tc.pid, err)
			}
			if got := inSubtree(run, path); got != tc.want {
				t.Fatalf("%s (%d): /proc says %v (%s), want %v", name, tc.pid, got, path, tc.want)
			}
		}
		if !m.unsupported.Load() {
			t.Fatal("a kernel without PIDFD_GET_INFO was not latched, so every event would ask it again")
		}
		return
	}
	if m.mountFD < 0 {
		t.Fatal("the cgroup2 mount could not be opened for handles")
	}
	for name, pid := range map[string]int{"run": pids["/run"], "descendant": pids["/run/child"],
		"outside": pids["/out"], "launcher": os.Getpid(), "init": 1} {
		path, err := cgroupPathOfPID(pid)
		if err != nil {
			t.Fatalf("%s (%d): /proc: %v", name, pid, err)
		}
		want := inSubtree(run, path)
		// Twice: the second answer comes from what the first learned.
		for round := range 2 {
			got, ok := m.lookup(pid)
			if !ok {
				id, idErr := m.idOf(pid)
				rel, pathErr := m.pathOf(id)
				t.Fatalf("%s (%d), round %d: the id path had no answer on a kernel with PIDFD_GET_INFO (id %d, %v; "+
					"path %q, %v; /proc %s)", name, pid, round, id, idErr, rel, pathErr, path)
			}
			if got != want {
				t.Fatalf("%s (%d), round %d: id path says %v, /proc says %v (%s)", name, pid, round, got, want, path)
			}
		}
	}

	// An exited opener: no answer here, and /proc says it is gone.
	c := exec.Command("true")
	if err := c.Run(); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.lookup(c.Process.Pid); ok {
		t.Fatal("an exited process was answered by the id path")
	}
	if _, err := cgroupPathOfPID(c.Process.Pid); !errors.Is(err, ErrProcGone) {
		t.Fatalf("/proc for an exited process: %v, want ErrProcGone", err)
	}

	// A cgroup removed after its id was read: the handle is stale, and the id is not remembered.
	gone := run + "/gone"
	if err := os.Mkdir(identity.SystemCgroupRoot+gone, 0o755); err != nil {
		t.Fatal(err)
	}
	goneID, err := cgroupIDOfPath(identity.SystemCgroupRoot, gone)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(identity.SystemCgroupRoot + gone); err != nil {
		t.Fatal(err)
	}
	if _, err := m.pathOf(goneID); !errors.Is(err, unix.ESTALE) {
		t.Fatalf("naming a removed cgroup: %v, want ESTALE", err)
	}
	m.idOf = func(int) (uint64, error) { return goneID, nil }
	if _, ok := m.lookup(12345); ok {
		t.Fatal("a removed cgroup was answered")
	}
	if _, seen := m.known[goneID]; seen {
		t.Fatal("a removed cgroup's id was remembered")
	}
}

// BenchmarkMembership measures what the listener's membership read costs per event, for an opener outside the
// run (the host's exec of a binary the contract did not name, §6 E34): /proc/<pid>/cgroup read, parsed and
// compared, against the pidfd's cgroup id checked against what the first event from that cgroup learned.
func BenchmarkMembership(b *testing.B) {
	if _, err := cgroupIDOfPID(os.Getpid()); errors.Is(err, errNoPidfdInfo) {
		b.Skipf("this kernel has no PIDFD_GET_INFO cgroup id: %v", err)
	}
	run, pids := res11Tree(b)
	runID, err := cgroupIDOfPath(identity.SystemCgroupRoot, run)
	if err != nil {
		b.Fatal(err)
	}
	host := pids["/out"]
	b.Run("proc", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			path, err := cgroupPathOfPID(host)
			if err != nil || inSubtree(run, path) {
				b.Fatalf("proc: %s, %v", path, err)
			}
		}
	})
	b.Run("pidfd id", func(b *testing.B) {
		m := newRunMembers(Run{CgroupPath: run, CgroupID: runID})
		defer m.close()
		b.ReportAllocs()
		for b.Loop() {
			if in, ok := m.lookup(host); !ok || in {
				b.Fatalf("id path: %v, %v", in, ok)
			}
		}
	})
}
