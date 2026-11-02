// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// The helpers below run in a process of their own, started by the tests with these variables set, because
// what they reproduce is a launcher that stops answering its own group: in the test process itself that would
// stop the test too.
const (
	freezeModeEnv   = "TEGO_EY099_MODE"   // "stage", "hold" or "stop"
	freezeMountEnv  = "TEGO_EY099_MOUNT"  // the tmpfs the helper's group marks
	freezeRepeatEnv = "TEGO_EY099_REPEAT" // stage mode: how many stage execs
)

// freezeMount mounts a tmpfs of its own for the helper's group to mark, so a group nobody answers holds no
// open outside it, and copies this test binary onto it as the child stage's binary, as
// the launcher's is. It returns the mount and the stage's path.
func freezeMount(t *testing.T) (string, string) {
	t.Helper()
	requireFanotify(t)
	mnt := filepath.Join(t.TempDir(), "m")
	if err := os.Mkdir(mnt, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount("tego-freeze", mnt, "tmpfs", 0, "mode=0755"); err != nil {
		t.Skipf("mount a tmpfs needs CAP_SYS_ADMIN: %v", err)
	}
	t.Cleanup(func() { _ = unix.Unmount(mnt, unix.MNT_DETACH) })
	self, err := os.ReadFile("/proc/self/exe")
	if err != nil {
		t.Fatal(err)
	}
	stage := filepath.Join(mnt, "tego")
	if err := os.WriteFile(stage, self, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"secret", "plain"} {
		if err := os.WriteFile(filepath.Join(mnt, name), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// An executable the group was not told to ignore: its execve raises an event before anything else.
	if err := os.WriteFile(filepath.Join(mnt, "other"), []byte("#!/bin/true\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return mnt, stage
}

// startFreezeHelper starts TestFreezeHelper in the given mode. Its stdout is a pipe the test reads lines from;
// its stdin is a pipe too, since a nil one would have os/exec open /dev/null.
func startFreezeHelper(t *testing.T, mode, mnt string, repeat int) (*exec.Cmd, *bufio.Reader, *bytes.Buffer) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self, "-test.run=^TestFreezeHelper$")
	cmd.Env = append(os.Environ(), freezeModeEnv+"="+mode, freezeMountEnv+"="+mnt,
		freezeRepeatEnv+"="+strconv.Itoa(repeat))
	if _, err := cmd.StdinPipe(); err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr
	// The helper dies with this test, whatever the test does.
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the helper: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd, bufio.NewReader(stdout), stderr
}

// taskStacks is every thread of a process with its kernel stack, for a failure message that names the wait.
func taskStacks(pid int) string {
	var b strings.Builder
	tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*", pid))
	for _, task := range tasks {
		stack, _ := os.ReadFile(filepath.Join(task, "stack"))
		fmt.Fprintf(&b, "task %s:\n%s", filepath.Base(task), stack)
	}
	for _, child := range childrenOf(pid) {
		stack, _ := os.ReadFile(fmt.Sprintf("/proc/%d/stack", child))
		fmt.Fprintf(&b, "child %d:\n%s", child, stack)
	}
	return b.String()
}

// childrenOf lists a process's children, from every thread's children file.
func childrenOf(pid int) []int {
	var out []int
	files, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/children", pid))
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, field := range strings.Fields(string(data)) {
			if n, err := strconv.Atoi(field); err == nil {
				out = append(out, n)
			}
		}
	}
	return out
}

// openWithin opens path and reports whether the open finished within d; a false leaves the open running.
func openWithin(path string, d time.Duration) (bool, error) {
	done := make(chan error, 1)
	go func() {
		f, err := os.Open(path)
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		return true, err
	case <-time.After(d):
		return false, nil
	}
}

// TestStageExecUnderGCNeverWaitsOnItsOwnGroup is the root cause, reproduced through the code the launcher
// runs. The launcher starts the child stage with Go's os/exec, whose clone suspends the forking thread
// (CLONE_VFORK) until the stage's execve of the launcher binary is past its point of no return, and that
// thread keeps its scheduler slot the whole time, so the runtime cannot stop the world meanwhile. An event
// from that execve that only the launcher's own listener answers then deadlocks the launcher as soon as a
// garbage collection begins in the window: the collection waits for the thread, the thread for the execve,
// and the execve for a listener the collection has stopped. With the launcher's mark on /, every open and
// execve on the machine then waits behind it: the whole-guest freeze, which the guest reproduced
// with the exemption removed within 14 pairs of concurrent runs, with the stage in fanotify_get_response from
// execve, the launcher's forking thread in clone3's vfork wait and every other thread parked.
//
// ADR 0021 closes the cycle by ordering instead of the stage exemption this test used to pin: the group has no
// mark while the stage is started and execs, it is armed (Arm's marks) only once the stage has reported, and
// while any mark exists the process starts nothing (internal/platform/proc.Start). The helper does what
// Prepare and Arm do on a tmpfs of its own, which also holds the stage binary: it creates the group and starts
// RunListener, keeps the collector busy, and then, repeatedly, starts the stage with no mark (armedStage),
// marks once the stage says it has exec'd, checks that a process start is now refused, acks the stage, whose
// open of the deny_read file the group must refuse (the agent's actions are decided from its first), and
// removes the marks. Every decision is slowed to 5 ms, which widens the window an event would hold a forking
// thread in; with no mark during the exec, the exec raises no event. Should a stage exec ever wait on the group
// again, the helper stops; the test then names the wait from the helper's stacks, and checks that killing the
// stalled helper releases the mount, since a dead listener's marks must not block the host (§6 E15).
func TestStageExecUnderGCNeverWaitsOnItsOwnGroup(t *testing.T) {
	mnt, _ := freezeMount(t)
	const repeat = 60
	cmd, out, stderr := startFreezeHelper(t, "stage", mnt, repeat)
	done := make(chan error, 1)
	go func() {
		_, _ = io.Copy(io.Discard, out)
		done <- cmd.Wait()
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("the helper failed: %v\n%s", err, stderr.String())
		}
		if !strings.Contains(stderr.String(), fmt.Sprintf("stage execs: %d", repeat)) {
			t.Fatalf("the helper did not report its stage execs:\n%s", stderr.String())
		}
		return
	case <-time.After(90 * time.Second):
	}
	stacks := taskStacks(cmd.Process.Pid)
	_ = cmd.Process.Kill()
	<-done
	released, err := openWithin(filepath.Join(mnt, "plain"), 10*time.Second)
	t.Fatalf("the child stage's execve waited on its own launcher's group while a collection waited for the "+
		"forking thread; after SIGKILL the mount was released: %v (%v)\nhelper stacks:\n%s\nhelper stderr:\n%s",
		released, err, stacks, stderr.String())
}

// TestKilledListenerReleasesTheMount is the other half: a launcher that is SIGKILLed must take its marks
// with it, even with a child that is still in the execve the launcher forked and a child that outlives it.
// The kernel releases a group when its last descriptor closes, so what could keep one alive is a process that
// holds a copy: the child in its vfork window holds one until its execve completes, and dies with the
// launcher through PR_SET_PDEATHSIG, as the launcher's stage is started (launch.Launcher); a child past its
// execve holds none, because the group is opened FAN_CLOEXEC, and that is what matters for the agent's
// processes, which outlive a killed launcher (§6 E38). The helper holds one exec in its decision for good,
// with a decision deadline of an hour, keeps a second child running, and is killed; the mount must answer at
// once, with the second child still alive.
func TestKilledListenerReleasesTheMount(t *testing.T) {
	mnt, _ := freezeMount(t)
	cmd, out, stderr := startFreezeHelper(t, "hold", mnt, 0)
	var survivor int
	for {
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("the helper stopped before it held an exec (%v):\n%s", err, stderr.String())
		}
		line = strings.TrimSpace(line)
		if v, ok := strings.CutPrefix(line, "survivor "); ok {
			survivor, _ = strconv.Atoi(v)
		}
		if line == "holding" {
			break
		}
	}
	if survivor == 0 {
		t.Fatal("the helper named no surviving child")
	}
	t.Cleanup(func() { _ = unix.Kill(survivor, unix.SIGKILL) })
	// The mark is live and the listener answers everything but the held exec: the deny_read entry refuses
	// this process, which shares the helper's cgroup.
	if ok, err := openWithin(filepath.Join(mnt, "secret"), 5*time.Second); !ok || !errors.Is(err, unix.EPERM) {
		t.Fatalf("an open under the helper's deny_read entry finished %v with %v, want EPERM from its listener", ok, err)
	}

	_ = cmd.Process.Kill()
	_ = cmd.Wait()
	if ok, err := openWithin(filepath.Join(mnt, "plain"), 10*time.Second); !ok || err != nil {
		t.Fatalf("the mount of a killed listener still blocks opens (finished %v, %v); the surviving child %d, "+
			"which must not hold the group:\n%s", ok, err, survivor, taskStacks(survivor))
	}
	if err := unix.Kill(survivor, 0); err != nil {
		t.Fatalf("the surviving child %d died with the helper (%v): the release proved nothing about a "+
			"process that outlives its launcher", survivor, err)
	}
}

// TestStoppedListenerHoldsItsMountUntilContinued is enforce-cgroup-observe.md §6 E40, the hazard a stopped launcher is at tier cgroup: a
// listener whose process is stopped (SIGSTOP here; a terminal's SIGTSTP when the launcher leaves it at its
// default, a debugger, or the cgroup freezer stop it the same way) keeps its marks and reads nothing, so an
// open on its marked mount waits for as long as the process stays stopped, however long its deadline (E16),
// which only runs once an event is read. It also pins what continuing does for an open made after the stop,
// which waits in the group's queue: it gets the answer the contract gives it, the deny_read refusal, not an
// allow nobody decided (I8). An open the listener had already read and was still deciding when it stopped is
// not covered by this: its deadline kept running through the stop and has usually passed on SIGCONT, so it is
// allowed with gap why=fanotify-timeout (E40). The helper's group marks a
// tmpfs of its own, so the wait holds nothing else in the guest. The helper runs its listener and sleeps, with
// no thread in a vfork wait, since a thread there does not take part in the stop (the "hold" helper's does).
func TestStoppedListenerHoldsItsMountUntilContinued(t *testing.T) {
	mnt, _ := freezeMount(t)
	cmd, out, stderr := startFreezeHelper(t, "stop", mnt, 0)
	for {
		line, err := out.ReadString('\n')
		if err != nil {
			t.Fatalf("the helper stopped before it listened (%v):\n%s", err, stderr.String())
		}
		if strings.TrimSpace(line) == "listening" {
			break
		}
	}
	secret := filepath.Join(mnt, "secret")
	if ok, err := openWithin(secret, 5*time.Second); !ok || !errors.Is(err, unix.EPERM) {
		t.Fatalf("an open under the helper's deny_read entry finished %v with %v, want EPERM from its listener", ok, err)
	}
	pid := cmd.Process.Pid
	if err := unix.Kill(pid, unix.SIGSTOP); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGCONT) })
	waitAllStopped(t, pid)

	done := make(chan error, 1)
	go func() {
		f, err := os.Open(secret)
		if err == nil {
			_ = f.Close()
		}
		done <- err
	}()
	select {
	case err := <-done:
		t.Fatalf("an open on a stopped listener's marked mount finished (%v): E40 says it waits, and is stale", err)
	case <-time.After(3 * time.Second):
	}
	if err := unix.Kill(pid, unix.SIGCONT); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("the open held while the listener was stopped ended with %v once it continued, want the "+
				"deny_read refusal (EPERM) its listener decides", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the open still waits 10 s after the listener continued:\n%s", taskStacks(pid))
	}
}

// waitAllStopped waits until every thread of pid is in the stopped state, which is when a group stop has
// taken the whole process and not only the thread the signal chose.
func waitAllStopped(t *testing.T, pid int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		tasks, _ := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/stat", pid))
		stopped := len(tasks) > 0
		for _, task := range tasks {
			data, err := os.ReadFile(task)
			if err != nil {
				stopped = false
				break
			}
			// The state follows the command name, which is in parentheses and may itself hold any byte.
			i := bytes.LastIndexByte(data, ')')
			if i < 0 || i+2 >= len(data) || data[i+2] != 'T' {
				stopped = false
				break
			}
		}
		if stopped {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("process %d did not stop within 10 s:\n%s", pid, taskStacks(pid))
}

// TestFreezeHelper is the helper half of the tests above. It does nothing in a normal run.
func TestFreezeHelper(t *testing.T) {
	mode, mnt := os.Getenv(freezeModeEnv), os.Getenv(freezeMountEnv)
	if mode == "" || mnt == "" {
		t.Skip("helper process only")
	}
	stage, secret := filepath.Join(mnt, "tego"), filepath.Join(mnt, "secret")
	cg, err := cgroupPathOfPID(os.Getpid())
	if err != nil {
		t.Fatalf("no cgroup v2 path: %v", err)
	}
	deadline := DefaultFanotifyDeadline
	// stop: the open queued while the listener is stopped is decided after SIGCONT, and a slow runner's first decision
	// after the resume can take longer than the 500 ms default, which allows it (E40's timeout) and is not what that
	// test is about (GitHub's arm64 runner, 2026-11-02). With an hour, an allow there could only be a real bug.
	if mode == "hold" || mode == "stop" {
		deadline = time.Hour
	}
	// A deny_read entry marks the helper's tmpfs and nothing else. No exec: section, so no exec is refused
	// and all that is left to test is whether the stage's execve waits.
	table := &agent.RuleTable{
		FS:       []agent.FSRule{{Kind: agent.FSDenyRead, Path: secret, Raw: "deny_read: " + secret}},
		Contract: &agent.Contract{},
		Tier:     backend.TierCgroup, Record: agent.RecordFull,
	}
	h := &Handle{
		opts:   Options{Events: &sink{}, FanotifyDeadline: deadline, Now: time.Now},
		run:    Run{ID: "freeze", Agent: "a", CgroupPath: cg, StageExe: stage},
		policy: newPolicy(table, cg),
	}
	if len(h.policy.mounts) != 1 {
		t.Fatalf("marks %v, want the helper's tmpfs alone", h.policy.mounts)
	}
	if err := h.startFanotify(); err != nil {
		t.Fatalf("startFanotify: %v", err)
	}
	defer h.fan.Close()
	// The marks Arm places (the helper has no kernel objects, so it places them itself).
	markPolicy := func() {
		for _, m := range h.policy.mounts {
			if err := h.fan.markFor(m, h.policy.masks[m]); err != nil {
				t.Fatalf("mark %s: %v", m, err)
			}
		}
	}
	if mode != "stage" {
		markPolicy()
	}

	held := make(chan struct{})
	decide := h.fan.decide
	other := filepath.Join(mnt, "other")
	// Every event goes to the wrapped decide below, the ones the loop would answer from the path alone
	// included (settleByPath): the slow decision is what these helpers are about.
	h.fan.settle = nil
	h.fan.decide = func(ev fanEvent) (verdict, error) {
		// The table has no exec: section, so the mark asks for no exec event (markMasks), and what the
		// execve of other raises is the open permission event of the file it executes.
		if mode == "hold" {
			if p, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(ev.FD))); err == nil && p == other {
				os.Stdout.WriteString("holding\n")
				<-held // never closed: the exec stays in its decision until the helper dies
			}
		}
		time.Sleep(5 * time.Millisecond)
		return decide(ev)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = h.RunListener(ctx) }()

	switch mode {
	case "stage":
		stop := make(chan struct{})
		defer close(stop)
		go func() {
			for {
				select {
				case <-stop:
					return
				default:
					runtime.GC()
				}
			}
		}()
		n := 0
		repeat, _ := strconv.Atoi(os.Getenv(freezeRepeatEnv))
		for range repeat {
			if err := armedStage(stage, mnt, markPolicy); err != nil {
				t.Fatalf("stage %d: %v", n+1, err)
			}
			if err := h.fan.unmarkAll(); err != nil {
				t.Fatalf("stage %d: unmark: %v", n+1, err)
			}
			if proc.Armed() {
				t.Fatalf("stage %d: the process is still armed with every mark removed", n+1)
			}
			n++
		}
		fmt.Fprintf(os.Stderr, "stage execs: %d\n", n)
	case "stop":
		os.Stdout.WriteString("listening\n")
		time.Sleep(time.Hour)
	case "hold":
		// A child that is past its execve and outlives the helper, as an agent's processes outlive a killed
		// launcher: it must not hold the group. Its binary is this one, off the marked tmpfs.
		self, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		survivor := exec.Command(self, "-test.run=^TestFreezeSleeper$")
		survivor.Env = append(os.Environ(), freezeModeEnv+"=sleep")
		if err := survivor.Start(); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(os.Stdout, "survivor %d\n", survivor.Process.Pid)
		// A child in its vfork window: its execve of a file the group was not told to ignore waits in the
		// decision above for as long as the helper lives, and it holds a copy of the group's descriptor
		// meanwhile. It dies with the helper, as the launcher's stage does.
		c := exec.Command(filepath.Join(mnt, "other"))
		c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
		_ = c.Run()
		t.Fatal("the held exec returned")
	}
}

// armedStage is one run's start in the launcher's order (ADR 0021 (2)): the stage binary is started through
// proc.Start with no mark of the group anywhere, the way launch.Launcher starts it (the stage killed if its
// parent dies); once it reports on its stdout, which it does only after its execve has returned, the group is
// armed (arm); a process start is then refused (ADR 0021 (3)); and only then is the stage acked, when it opens
// the deny_read file as the agent would and must be refused by the group.
func armedStage(stage, mnt string, arm func()) error {
	c := proc.Command(stage, "-test.run=^TestFreezeStageChild$")
	c.Env = []string{freezeModeEnv + "=stage-child", freezeMountEnv + "=" + mnt}
	c.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	ack, err := c.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := c.StdoutPipe()
	if err != nil {
		return err
	}
	if _, err := proc.Start(c); err != nil {
		return fmt.Errorf("start the stage: %w", err)
	}
	defer func() { _ = c.Process.Kill(); _ = c.Wait() }()
	lines := bufio.NewReader(stdout)
	next := func(prefix string) (string, error) {
		for {
			line, err := lines.ReadString('\n')
			if err != nil {
				return "", fmt.Errorf("the stage ended before %q: %w", prefix, err)
			}
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), prefix); ok {
				return v, nil
			}
		}
	}
	if _, err := next("stage-ready"); err != nil {
		return err
	}
	arm()
	if _, err := proc.Start(proc.Command("/bin/true")); !errors.Is(err, proc.ErrArmed) {
		return fmt.Errorf("a process start while the group holds marks = %v, want proc.ErrArmed", err)
	}
	if _, err := ack.Write([]byte{1}); err != nil {
		return err
	}
	got, err := next("agent-open ")
	if err != nil {
		return err
	}
	if got != "refused" {
		return fmt.Errorf("the acked stage's open of the deny_read file: %s, want refused by the armed group", got)
	}
	return nil
}

// TestFreezeStageChild is armedStage's stage: it says it has exec'd, waits for its ack, then opens the helper's
// deny_read file as an agent would and says how that went. It does nothing in a normal run.
func TestFreezeStageChild(t *testing.T) {
	if os.Getenv(freezeModeEnv) != "stage-child" {
		t.Skip("helper process only")
	}
	os.Stdout.WriteString("stage-ready\n")
	var b [1]byte
	if _, err := os.Stdin.Read(b[:]); err != nil {
		t.Fatalf("read the ack: %v", err)
	}
	f, err := os.Open(filepath.Join(os.Getenv(freezeMountEnv), "secret"))
	switch {
	case err == nil:
		_ = f.Close()
		os.Stdout.WriteString("agent-open allowed\n")
	case errors.Is(err, unix.EPERM):
		os.Stdout.WriteString("agent-open refused\n")
	default:
		fmt.Fprintf(os.Stdout, "agent-open %v\n", err)
	}
}

// TestFreezeSleeper is the surviving child of TestKilledListenerReleasesTheMount: it sleeps, and does nothing
// in a normal run.
func TestFreezeSleeper(t *testing.T) {
	if os.Getenv(freezeModeEnv) != "sleep" {
		t.Skip("helper process only")
	}
	time.Sleep(10 * time.Minute)
}
