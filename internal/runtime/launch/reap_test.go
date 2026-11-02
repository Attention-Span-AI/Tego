// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// TestReapOrphansReapsAdoptedZombies pins that a descendant the subreaper adopted is waited for once it
// exits (it stays charged to the cgroup's pids.current until then), and that the main child is left for
// Wait: its status is the run's exit.
func TestReapOrphansReapsAdoptedZombies(t *testing.T) {
	testReapOrphans(t, procCgroup(os.Getpid()))
}

// TestReapOrphansWithoutProcChildren pins the same on a kernel without CONFIG_PROC_CHILDREN, where
// /proc/<pid>/task/<tid>/children does not exist: the reaper falls back to scanning /proc/<pid>/stat for
// PPid == self rather than finding no candidates and leaving the zombies charged to limits.pids.
func TestReapOrphansWithoutProcChildren(t *testing.T) {
	old := procChildrenGlob
	procChildrenGlob = "/nonexistent-tego/task/*/children"
	t.Cleanup(func() { procChildrenGlob = old })
	testReapOrphans(t, procCgroup(os.Getpid()))
}

// TestReapOrphansInASubCgroup pins that a zombie in a sub-cgroup of the run's cgroup is reaped too: the
// scope's pids.current counts its descendants, so a zombie that a tool of the agent's moved into a child
// cgroup of the scope would otherwise stay charged to limits.pids and get a healthy run killed as
// reason=pids. An unprivileged test cannot move a process into a new cgroup, so it names the parent of its
// own cgroup as the run's: the helpers then sit in a descendant of it, as the moved zombie would.
func TestReapOrphansInASubCgroup(t *testing.T) {
	own := procCgroup(os.Getpid())
	i := strings.LastIndexByte(own, '/')
	if !strings.HasPrefix(own, "0::/") || i <= len("0::") {
		t.Skipf("not in a non-root cgroup v2 cgroup: %q", own)
	}
	testReapOrphans(t, own[:i])
}

// TestReapOrphansKeepsTheDeputy pins that the child named by KeepUnreaped (the run's open deputy, ADR 0041 D2) is left
// a zombie while the other adopted zombies are reaped: its zombie holds its pid, so the kernel cannot give that pid to
// a later process of the run while the kernel recorder drops the deputy's records (supervisor.md R7a). The agent can
// end the deputy; the run's closeDeputy reaps it at the end.
func TestReapOrphansKeepsTheDeputy(t *testing.T) {
	if err := sys.SetChildSubreaper(true); err != nil {
		t.Skip("PR_SET_CHILD_SUBREAPER unavailable:", err)
	}
	t.Cleanup(func() { _ = sys.SetChildSubreaper(false) })
	main := exec.Command("/bin/true")
	if err := main.Start(); err != nil {
		t.Fatal(err)
	}
	deputy := exec.Command("/bin/true")
	if err := deputy.Start(); err != nil {
		t.Fatal(err)
	}
	other := exec.Command("/bin/true")
	if err := other.Start(); err != nil {
		t.Fatal(err)
	}
	c := &Child{PID: main.Process.Pid, cgroup: procCgroup(os.Getpid())}
	c.KeepUnreaped(deputy.Process.Pid)
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.ReapOrphans()
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", other.Process.Pid)); err != nil && procZombie(deputy.Process.Pid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the other zombie was never reaped, or the deputy never became a zombie")
		}
		time.Sleep(10 * time.Millisecond)
	}
	for range 3 {
		c.ReapOrphans()
	}
	if !procZombie(deputy.Process.Pid) {
		t.Fatalf("the kept deputy %d was reaped; its pid is free for another process", deputy.Process.Pid)
	}
	if err := deputy.Wait(); err != nil {
		t.Fatalf("the deputy's own wait: %v", err)
	}
	if err := main.Wait(); err != nil {
		t.Fatalf("main child's status was stolen by the reaper: %v", err)
	}
}

// TestInCgroupTree pins the match: the cgroup itself and its descendants, never a sibling that only shares a
// name prefix, and nothing that is not a single cgroup v2 line.
func TestInCgroupTree(t *testing.T) {
	const own = "0::/tego.slice/run-1.scope"
	for _, tc := range []struct {
		line string
		want bool
	}{
		{own, true},
		{own + "/sub", true},
		{own + "/sub/deeper", true},
		{"0::/tego.slice/run-1.scope2", false},
		{"0::/tego.slice", false},
		{"0::/other.slice/run-1.scope/sub", false},
		{"", false},
		{"1:name=systemd:" + "/tego.slice/run-1.scope/sub", false},
		{"1:name=systemd:/x\n0::/tego.slice/run-1.scope/sub", false},
	} {
		if got := inCgroupTree(tc.line, own); got != tc.want {
			t.Errorf("inCgroupTree(%q, %q) = %v, want %v", tc.line, own, got, tc.want)
		}
	}
	if !inCgroupTree("0::/a/b", "0::/") {
		t.Error("a cgroup under the namespace root must match own 0::/")
	}
}

// TestUnifiedLineLeavesV1HierarchiesOut pins what the reaper compares: the unified hierarchy's line of
// /proc/<pid>/cgroup, whatever cgroup v1 hierarchies the host lists beside it, so a zombie in a sub-cgroup of the
// run is the run's on such a host too.
func TestUnifiedLineLeavesV1HierarchiesOut(t *testing.T) {
	for _, tc := range []struct{ text, want string }{
		{"0::/tego.slice/run-1.scope\n", "0::/tego.slice/run-1.scope"},
		{"1:name=tegoedge:/\n0::/system.slice/hosted-compute-agent.service\n", "0::/system.slice/hosted-compute-agent.service"},
		{"12:pids:/user.slice\n1:name=systemd:/user.slice/a.scope\n0::/user.slice/a.scope\n", "0::/user.slice/a.scope"},
		{"0::/\n", "0::/"},
		{"1:name=systemd:/a.scope\n", ""},
		{"", ""},
	} {
		if got := unifiedLine(tc.text); got != tc.want {
			t.Errorf("unifiedLine(%q) = %q, want %q", tc.text, got, tc.want)
		}
	}
	own := unifiedLine("1:name=systemd:/x\n0::/tego.slice/run-1.scope\n")
	if !inCgroupTree(unifiedLine("1:name=systemd:/x\n0::/tego.slice/run-1.scope/sub\n"), own) {
		t.Error("beside a named v1 hierarchy, a sub-cgroup of the run is not the run's")
	}
	if inCgroupTree(unifiedLine("1:name=systemd:/x\n0::/tego.slice/run-2.scope\n"), own) {
		t.Error("beside a named v1 hierarchy, another run's cgroup is the run's")
	}
}

func testReapOrphans(t *testing.T, runCgroup string) {
	if err := sys.SetChildSubreaper(true); err != nil {
		t.Skip("PR_SET_CHILD_SUBREAPER unavailable:", err)
	}
	t.Cleanup(func() { _ = sys.SetChildSubreaper(false) })

	main := exec.Command("/bin/true")
	if err := main.Start(); err != nil {
		t.Fatal(err)
	}
	// Five backgrounded helpers whose parent subshell exits at once: orphaned to this process, then zombies.
	out, err := exec.Command("/bin/sh", "-c", `for i in 1 2 3 4 5; do (/bin/true & echo $!); done`).Output()
	if err != nil {
		t.Fatal(err)
	}
	var pids []int
	for _, f := range strings.Fields(string(out)) {
		n, err := strconv.Atoi(f)
		if err != nil {
			t.Fatal(err)
		}
		pids = append(pids, n)
	}
	if len(pids) != 5 {
		t.Fatalf("helper pids %v", pids)
	}
	c := &Child{PID: main.Process.Pid, cgroup: runCgroup}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.ReapOrphans()
		left := 0
		for _, p := range pids {
			if _, err := os.Stat(fmt.Sprintf("/proc/%d", p)); err == nil {
				left++
			}
		}
		if left == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d adopted zombies never reaped", left)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := main.Wait(); err != nil {
		t.Fatalf("main child's status was stolen by the reaper: %v", err)
	}
}
