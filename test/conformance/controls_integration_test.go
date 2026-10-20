// SPDX-License-Identifier: Apache-2.0

//go:build integration

package conformance

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// memfdNoexec is the pid namespace's memfd sealing setting (6.3+): 1 seals every memfd made without MFD_EXEC against
// exec, 2 refuses MFD_EXEC as well.
const memfdNoexec = "/proc/sys/vm/memfd_noexec"

// memfdControlChildEnv carries the vm.memfd_noexec value TestMemfdControlSeesTheSysctl's child sets in its own pid
// namespace before it runs memfdControl.
const memfdControlChildEnv = "TEGO_CONFORMANCE_TEST_MEMFD_NOEXEC"

// TestMemfdControlSeesTheSysctl holds memfdControl to its purpose: on a machine whose vm.memfd_noexec seals a memfd
// against exec, a memfd cell's EACCES would be the machine's and not the run's, and the control must fail the fixture.
// Each value runs in a child that is pid 1 of a pid namespace of its own, where it raises the setting for itself
// alone: 0 must pass the control, 1 and 2 must fail it.
func TestMemfdControlSeesTheSysctl(t *testing.T) {
	fx := Fixture{Name: "memfd-control", Contract: "version: 0\nname: conformance\n",
		Cells: []Cell{{Name: "create", Op: OpMemfdCreate}, {Name: "exec", Op: OpMemfdExec}}}
	if v := os.Getenv(memfdControlChildEnv); v != "" {
		if err := os.WriteFile(memfdNoexec, []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
		// Not t.TempDir(): its parent is 0700, and the agent (the sudo caller) must reach the scripts through it.
		dir, err := os.MkdirTemp("", "eyconf")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.RemoveAll(dir) })
		memfdControl(t, materialize(t, dir, &fx, buildActor(t)), &fx)
		return
	}
	if os.Geteuid() != 0 {
		t.Skip("needs root: the child is pid 1 of a pid namespace of its own and raises its vm.memfd_noexec")
	}
	if _, err := os.Stat(memfdNoexec); err != nil {
		t.Logf("n/a: this kernel has no %s (before 6.3), so no machine setting seals a memfd against exec", memfdNoexec)
		return
	}
	for _, tc := range []struct {
		value string
		fail  bool
	}{{"0", false}, {"1", true}, {"2", true}} {
		cmd := exec.Command(os.Args[0], "-test.run=^TestMemfdControlSeesTheSysctl$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), memfdControlChildEnv+"="+tc.value)
		cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
		out, err := cmd.CombinedOutput()
		switch {
		case !tc.fail && err != nil:
			t.Errorf("vm.memfd_noexec %s: the memfd control failed where the machine refuses nothing (%v):\n%s", tc.value, err, out)
		case tc.fail && err == nil:
			t.Errorf("vm.memfd_noexec %s: the memfd control passed where the machine seals a memfd against exec:\n%s", tc.value, out)
		case tc.fail && !bytes.Contains(out, []byte("the memfd control: the agent's uid, outside every run, cannot memfd-exec")):
			t.Errorf("vm.memfd_noexec %s: the child failed, but not on the memfd control (%v):\n%s", tc.value, err, out)
		default:
			t.Logf("vm.memfd_noexec %s: the memfd control %s", tc.value, map[bool]string{true: "fails the fixture", false: "passes"}[tc.fail])
		}
	}
}

// TestHostControlSeesARefusingMachine holds hostControl to its purpose:
// the agent's attach outside every run must fail the fixture wherever the machine refuses it, so a ptrace cell's EPERM
// is never the machine's. The host stage the cells name opts out of Yama's ptrace_scope 1 (PR_SET_PTRACER_ANY) and
// passes below 2; a plain process of the agent's uid that does not opt out is refused from 1 up, so dropping the
// opt-out fails the control on every runner with Yama 1; and a kernel thread is refused on every machine, the
// control's refusing case wherever Yama is off. An agent that is root (no sudo caller) holds CAP_SYS_PTRACE, which
// only Yama's 3 refuses.
func TestHostControlSeesARefusingMachine(t *testing.T) {
	scope := 0
	if b, err := os.ReadFile("/proc/sys/kernel/yama/ptrace_scope"); err == nil {
		scope, _ = strconv.Atoi(strings.TrimSpace(string(b)))
	}
	_, _, dropped := sudoIDs()
	privileged := os.Geteuid() == 0 && !dropped
	refuses := func(min int) bool {
		if privileged {
			return scope >= 3
		}
		return scope >= min
	}
	fx := Fixture{Name: "host-control", Contract: "version: 0\nname: conformance\n",
		Cells: []Cell{{Name: "ptrace-host", Op: OpPtraceAttach, Target: TargetHost}}}
	// Not t.TempDir(): its parent is 0700, and the agent (the sudo caller) must reach the actor through it.
	dir, err := os.MkdirTemp("", "eyconf")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	e := materialize(t, dir, &fx, buildActor(t))
	check := func(what string, want bool) {
		t.Helper()
		err := hostCheck(t, e)
		switch {
		case want && err == nil:
			t.Errorf("%s (ptrace_scope %d): the host control passed where the machine refuses the attach", what, scope)
		case !want && err != nil:
			t.Errorf("%s (ptrace_scope %d): the host control failed where the machine allows the attach: %v", what, scope, err)
		default:
			t.Logf("%s (ptrace_scope %d): the host control %s", what, scope, map[bool]string{true: "fails the fixture", false: "passes"}[want])
		}
	}
	check("the host stage", refuses(2))

	plain := exec.Command("sleep", "120")
	plain.Env = []string{}
	asAgent(plain)
	if err := plain.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = plain.Process.Kill(); _ = plain.Wait() })
	e.hostPID = plain.Process.Pid
	check("a plain process of the agent's uid", refuses(1))

	if b, err := os.ReadFile("/proc/2/comm"); err != nil || strings.TrimSpace(string(b)) != "kthreadd" {
		t.Logf("n/a: pid 2 is not kthreadd here (%q, %v): no kernel thread to attach to", b, err)
		return
	}
	e.hostPID = 2
	check("a kernel thread", true)
}
