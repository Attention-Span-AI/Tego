// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// procTicks returns the utime+stime clock ticks and the state letter of a process from /proc/<pid>/stat. The
// command name sits in parentheses and may contain spaces, so the fields are counted after the last ')'.
func procTicks(t *testing.T, pid int) (ticks uint64, state string) {
	t.Helper()
	b, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat")
	if err != nil {
		t.Fatalf("read stat of %d: %v", pid, err)
	}
	s := string(b)
	f := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
	// After the comm: state is f[0], utime is f[11] and stime f[12] (fields 14 and 15 of proc(5)).
	u, err1 := strconv.ParseUint(f[11], 10, 64)
	k, err2 := strconv.ParseUint(f[12], 10, 64)
	if err1 != nil || err2 != nil {
		t.Fatalf("parse stat of %d: %v %v", pid, err1, err2)
	}
	return u + k, f[0]
}

// agentSpins reports whether the agent's CPU time rises by 10 ticks (100 ms of CPU at USER_HZ 100) within limit, in
// a state other than stopped (T) or waiting uninterruptibly (D): an agent spinning in user space. A starved guest
// gives a spinning agent its ticks slowly, so the limit is a deadline, not a rate.
func agentSpins(t *testing.T, agent int, limit time.Duration) bool {
	t.Helper()
	start, _ := procTicks(t, agent)
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		if now, st := procTicks(t, agent); now >= start+10 && st != "T" && st != "D" {
			return true
		}
	}
	return false
}

// TestIntegrationStoppedLauncherLeavesTheAgentRunning is runtime-launch.md E14: SIGSTOP on the launcher does not
// stop the agent. The launcher is a real tego process at the unprivileged tier; the agent is a shell spinning on
// a builtin, so it makes no syscall the (stopped) supervisor would have to answer, and its CPU time must keep
// advancing for as long as the launcher stays stopped. Continuing the launcher and stopping the run then ends it.
func TestIntegrationStoppedLauncherLeavesTheAgentRunning(t *testing.T) {
	bin := tegoBinary(t)
	f := newFixture(t, contractFor("istoplauncher", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh"}))
	cfg := writeMachineConfig(t, f)
	cmd := exec.Command(bin, "run", filepath.Join(f.dir, "agent.yaml"), "--", "/bin/sh", "-c", "while :; do :; done")
	cmd.Dir = f.dir
	cmd.Env = append(os.Environ(), "TEGO_CONFIG="+cfg)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	pid := cmd.Process.Pid
	done := make(chan struct{})
	go func() { _ = cmd.Wait(); close(done) }()
	t.Cleanup(func() {
		_ = syscall.Kill(pid, syscall.SIGCONT)
		_ = cmd.Process.Kill()
		<-done
	})
	dir := waitForStartedRunNot(t, f.root, 20*time.Second, 0)

	// The agent is the launcher's only child once the run has started: the child stage execs into it.
	var agent int
	for deadline := time.Now().Add(10 * time.Second); agent == 0 && time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		// The clone came from whichever thread ran it, so every task's list is read.
		files, _ := filepath.Glob("/proc/" + strconv.Itoa(pid) + "/task/*/children")
		for _, cf := range files {
			b, _ := os.ReadFile(cf)
			if fs := strings.Fields(string(b)); len(fs) > 0 {
				agent, _ = strconv.Atoi(fs[0])
			}
		}
	}
	if agent == 0 {
		t.Fatal("the launcher has no child: no agent to watch")
	}
	// run_start is written before the child stage execs the shell, and the shell's exec and its first syscalls are
	// the supervisor's to answer: stopped then, the launcher leaves the agent waiting in the kernel for an answer
	// (state D, no ticks), which is not what E14 is about. So the launcher is stopped only once the agent spins,
	// its CPU time rising in its loop (the KVM root suites, host load ~80: "agent state D, ticks 7 -> 7").
	if !agentSpins(t, agent, 30*time.Second) {
		before, st := procTicks(t, agent)
		t.Fatalf("the agent never reached its loop: state %q, %d ticks after 30s", st, before)
	}

	if err := syscall.Kill(pid, syscall.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if _, st := procTicks(t, pid); st == "T" {
			break
		}
	}
	if _, st := procTicks(t, pid); st != "T" {
		t.Fatalf("the launcher is in state %q after SIGSTOP, want T", st)
	}
	before, _ := procTicks(t, agent)
	if !agentSpins(t, agent, 10*time.Second) {
		after, st := procTicks(t, agent)
		t.Errorf("agent state %q, ticks %d -> %d over 10s with the launcher stopped: E14 says it keeps running", st, before, after)
	}
	if _, st := procTicks(t, pid); st != "T" {
		t.Errorf("the launcher is in state %q while the agent ran, want T", st)
	}

	if err := syscall.Kill(pid, syscall.SIGCONT); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Kill(pid, syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatalf("the run did not end after SIGCONT and SIGTERM; run dir %s", dir)
	}
}
