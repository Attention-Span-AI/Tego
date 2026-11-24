// SPDX-License-Identifier: Apache-2.0

//go:build linux && amd64

package contracts

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger/runstart"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/registry"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func init() {
	lifecycleTestCommand = func() (int, bool) {
		if len(os.Args) == 5 && os.Args[1] == "--contracts-lifecycle-child" {
			return lifecycleChild(os.Args[2], os.Args[3], os.Args[4]), true
		}
		return 0, false
	}
}

func lifecycleOptions(base, cwd string) Options {
	m := config.Builtin()
	m.Home = filepath.Join(base, "home")
	m.LedgerRoot.Value = filepath.Join(base, "ledger")
	m.Registry.Value = filepath.Join(base, "registry")
	return Options{Machine: m, Places: registry.Places{Dir: cwd, UID: os.Getuid()},
		Snapshot: &runstart.Snapshot{}, PATH: "/usr/bin:/bin",
		CompileContext: CompileContext{MountInfo: new(string)}}
}

// refusedForWantOfASlot makes a check while all four synthetic helper slots are held, with a one-second start-up budget
// (the production one is StartTimeout): it must end, measured from this call and not from the process's start, as a
// start-up refusal that names the slots and says only that they are alive (their holders are another process's:
// nothing here knows whether they are busy or stuck), and does not say the location did not answer, because the
// location was never asked. It returns 0, or the exit code of what went wrong (40, 41, 42).
func refusedForWantOfASlot(path string) int {
	startTimeout = time.Second * raceScale
	began := time.Now()
	_, err := PlacePath(context.Background(), path)
	waited := time.Since(began)
	switch {
	case err == nil || !strings.Contains(err.Error(), "4 filesystem helpers"):
		fmt.Printf("slot refusal: %v\n", err)
		return 40
	case !IsStartFailure(err) || IsLocationUnavailable(err) || strings.Contains(err.Error(), UnavailableLocation) ||
		strings.Contains(err.Error(), "very busy") || !strings.Contains(err.Error(), "cannot tell whether they are busy or stuck"):
		fmt.Printf("slot refusal in the wrong words: %v\n", err)
		return 41
	case waited > CheckTimeout:
		fmt.Printf("slot refusal took %v\n", waited)
		return 42
	}
	return 0
}

func lifecycleChild(stage, base, blocked string) int {
	// Exercise exhaustion with four traced workers instead of thirty-two. Both
	// caller processes use the same smaller synthetic budget; production uses 32.
	if stage == "limit" || stage == "cross-limit" {
		processWorkers, governedWorkers = helperPools(4)
		// A real command or another test may own production reservations. Both
		// lifecycle callers share this fixture's pool, including after caller exit.
		helperReservationPool = fmt.Sprintf("tego.contracts-test.%x", sha256.Sum256([]byte(base)))
	}
	if tracedWithoutALocationBound(stage) {
		locationTimeout = hangGuard // the worker's own marker file says the same (traceRecordedPath)
	}
	// No caller deadline in any stage: "place" exercises the transport's own bounds (the helper's start-up budget,
	// then CheckTimeout from its ready frame), and the others end when the tracer says their worker is held.
	ctx := context.Background()
	o := lifecycleOptions(base, base)
	path := filepath.Join(base, "agent.yaml")
	if stage == "place" || stage == "limit" || stage == "cross-limit" {
		// Keep the '..': placing an already clean absolute path needs no I/O.
		path = blocked + "/../agent.yaml"
		if stage == "cross-limit" {
			if code := refusedForWantOfASlot(path); code != 0 {
				return code
			}
			fmt.Println("RESULT incomplete cross-limit=4")
			return 125
		}
		if stage == "limit" {
			// The four callers give up only when the tracer has seen all four workers held in their pathname
			// calls and says so on stdin: a worker still starting when its caller left would end and free its
			// slot, and how long four helpers take to start is the machine's. The transport's own bounds
			// (StartTimeout, then CheckTimeout from the ready frame) still end a call that is never answered.
			var gaveUp context.CancelFunc
			ctx, gaveUp = context.WithCancel(context.Background())
			defer gaveUp()
			go func() {
				var signal [1]byte
				_, _ = os.Stdin.Read(signal[:])
				gaveUp()
			}()
			var wg sync.WaitGroup
			errs := make(chan error, 4)
			for range 4 {
				wg.Add(1)
				go func() { defer wg.Done(); _, err := PlacePath(ctx, path); errs <- err }()
			}
			wg.Wait()
			close(errs)
			for err := range errs {
				if !errors.Is(err, context.Canceled) && !errors.Is(err, context.DeadlineExceeded) {
					fmt.Printf("non-deadline helper result: %v\n", err)
					return 20
				}
			}
			if code := refusedForWantOfASlot(path); code != 0 {
				return code
			}
			fmt.Println("RESULT incomplete limit=4")
			return 125
		}
		_, err := PlacePath(ctx, path)
		if !errors.Is(err, context.DeadlineExceeded) {
			return 22
		}
		fmt.Println("RESULT incomplete")
		return 125
	}
	switch stage {
	case "registry":
		o.Places.Dir = blocked
	case "source", "late":
		path = filepath.Join(blocked, "agent.yaml")
	case "cwd":
		o.Places.Dir = blocked
	}
	// The caller gives up only when the tracer has seen the worker held in its pathname call and says so on stdin,
	// as the four callers of "limit" do. A fixed caller deadline would end the call, on a machine too busy to start
	// the helper in it, before any worker reached the path, and the test would measure the machine. The transport's
	// own bounds (StartTimeout, then CheckTimeout from the ready frame) still end a call that is never answered.
	var gaveUp context.CancelFunc
	ctx, gaveUp = context.WithCancel(context.Background())
	defer gaveUp()
	go func() {
		var signal [1]byte
		_, _ = os.Stdin.Read(signal[:])
		gaveUp()
	}()
	var c Catalog
	if stage == "registry" {
		c = Discover(ctx, o)
	} else {
		c = Inspect(ctx, path, o)
	}
	if !c.Incomplete || c.ExitCode() != 125 {
		return 23
	}
	before, err := json.Marshal(c)
	if err != nil {
		return 24
	}
	fmt.Printf("RESULT %s\n", before)
	if stage == "late" {
		// The tracer releases the real syscall only after observing this result.
		var signal [1]byte
		if _, err := os.Stdin.Read(signal[:]); err != nil {
			return 25
		}
		timer := time.NewTimer(3 * time.Second)
		defer timer.Stop()
		for range cap(processWorkers) {
			select {
			case processWorkers <- struct{}{}:
			case <-timer.C:
				return 26
			}
		}
		for range cap(processWorkers) {
			<-processWorkers
		}
		after, err := json.Marshal(c)
		if err != nil || !bytes.Equal(before, after) {
			return 27
		}
		fresh := Inspect(context.Background(), path, o)
		if fresh.Incomplete {
			return 28
		}
		fmt.Println("LATE discarded; fresh check recovered")
	}
	return 125
}

// A ptrace syscall-entry stop holds a genuine pathname operation indefinitely,
// without changing the product or replacing its filesystem calls. It exposes a
// waiting parent or a worker thread retained in the command. It is not an
// uninterruptible kernel wait: the dead-FUSE recipe remains owed in a guest.
func TestRecordedPathProcessExit(t *testing.T) {
	for _, stage := range []string{"place", "registry", "source", "cwd", "compile", "limit", "late"} {
		t.Run(stage, func(t *testing.T) { traceRecordedPath(t, stage) })
	}
}

// hangGuard ends a traced command or worker that never exits (see traceRecordedPath).
const hangGuard = 60 * time.Second

// tracedWithoutALocationBound says a stage ends when the tracer says its worker is held, never at the helper's
// location budget: the tracer steps the worker through every system call it makes before the held one, and on a
// busy machine that alone can outlast five seconds of the worker's own clock, which would end the call before any
// path was held. "place" and the limit stages reach their held call at once and keep the transport's own bounds.
func tracedWithoutALocationBound(stage string) bool {
	return stage != "place" && stage != "limit" && stage != "cross-limit"
}

func traceRecordedPath(t *testing.T, stage string) {
	t.Helper()
	if tracedWithoutALocationBound(stage) {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(executable+".traced", nil, 0o600); err != nil {
			t.Fatal(err)
		}
		defer os.Remove(executable + ".traced")
	}
	base := t.TempDir()
	blocked := filepath.Join(base, "blocked")
	if err := os.Mkdir(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	body := "version: 0\nname: fixture\ncommand: [/bin/true]\nenv:\n  pass: [PATH]\nnet:\n  allow: []\n"
	if stage == "compile" {
		body = strings.Replace(body, "/bin/true", filepath.Join(blocked, "program"), 1)
		write(t, filepath.Join(blocked, "program"), "#!/bin/sh\nexit 0\n")
		if err := os.Chmod(filepath.Join(blocked, "program"), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	write(t, filepath.Join(base, "agent.yaml"), body)
	write(t, filepath.Join(blocked, "agent.yaml"), body)
	output, err := os.Create(filepath.Join(base, "output"))
	if err != nil {
		t.Fatal(err)
	}
	defer output.Close()
	input, signal, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	defer signal.Close()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	cmd := exec.Command(os.Args[0], "--contracts-lifecycle-child", stage, base, blocked)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = input, output, output
	cmd.SysProcAttr = &syscall.SysProcAttr{Ptrace: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start traced command: %v", err)
	}
	leader := cmd.Process.Pid
	live := map[int]bool{leader: true}
	lastTask := 0
	held := map[int]bool{}
	completed := map[int]bool{}
	released := false
	allHeld := false
	defer func() {
		// Kill only tasks this test traced. Drain their exits on every failure.
		for pid := range live {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			_ = syscall.PtraceCont(pid, int(syscall.SIGKILL))
		}
		deadline := time.Now().Add(3 * time.Second)
		for len(live) > 0 && time.Now().Before(deadline) {
			var status syscall.WaitStatus
			pid, err := syscall.Wait4(-1, &status, syscall.WALL|syscall.WNOHANG, nil)
			if err != nil {
				break
			}
			if pid == 0 {
				time.Sleep(time.Millisecond)
				continue
			}
			if status.Exited() || status.Signaled() {
				delete(live, pid)
			} else {
				_ = syscall.PtraceCont(pid, int(syscall.SIGKILL))
			}
		}
		// Wait4 above owns reaping; Release only releases the Go handle.
		_ = cmd.Process.Release()
	}()
	var initial syscall.WaitStatus
	if _, err := syscall.Wait4(leader, &initial, 0, nil); err != nil {
		t.Fatal(err)
	}
	if !initial.Stopped() {
		t.Fatalf("initial wait: %v", initial)
	}
	options := syscall.PTRACE_O_TRACESYSGOOD | syscall.PTRACE_O_TRACEFORK | syscall.PTRACE_O_TRACEVFORK | syscall.PTRACE_O_TRACECLONE | syscall.PTRACE_O_TRACEEXEC
	if err := syscall.PtraceSetOptions(leader, options); err != nil {
		t.Fatalf("ptrace options for command %d: %v", leader, err)
	}
	if err := syscall.PtraceSyscall(leader, 0); err != nil {
		t.Fatalf("ptrace start command %d: %v", leader, err)
	}
	// A guard against a hang, not a claim about speed: the traced workers are released only after the command has
	// exited, so a command that waited for them would never exit at all, however long this waits. What a busy
	// machine needs to start four helpers is its own.
	bound := hangGuard
	deadline := time.Now().Add(bound)
	commandExited := false
	observed := 0
	for len(live) > 0 {
		if time.Now().After(deadline) {
			t.Fatalf("command or recovered helper did not exit in bound; stage=%s held=%v live=%v output=%s", stage, held, live, readLifecycleOutput(output.Name()))
		}
		pid, status, err := waitLifecycleTask(live, &lastTask)
		if err != nil {
			t.Fatalf("wait traced task: %v; exited=%v observed=%d held=%v live=%v output=%s", err, commandExited, observed, held, live, readLifecycleOutput(output.Name()))
		}
		if pid == 0 {
			if stage != "limit" && stage != "place" && stage != "cross-limit" && !released && !allHeld && observed == 1 {
				// The worker is held in its pathname call: the caller may give up now (lifecycleChild).
				allHeld = true
				if _, err := signal.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "limit" && !released && !allHeld && observed == 4 {
				allHeld = true
				if _, err := signal.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "late" && !released && len(held) == 1 && strings.Contains(readLifecycleOutput(output.Name()), "RESULT ") {
				for tid := range held {
					if err := syscall.PtraceCont(tid, 0); err != nil {
						t.Fatalf("ptrace recover held worker %d: %v", tid, err)
					}
				}
				released = true
				if _, err := signal.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			}
			runtime.Gosched()
			continue
		}
		if status.Exited() || status.Signaled() {
			completed[pid] = true
			delete(live, pid)
			if pid == leader {
				commandExited = true
				if !status.Exited() || status.ExitStatus() != 125 {
					t.Fatalf("command exit %v output=%s", status, readLifecycleOutput(output.Name()))
				}
				want := 1
				if stage == "limit" {
					want = 4
				}
				if observed != want {
					t.Fatalf("held %d real pathname calls, want %d; output=%s", observed, want, readLifecycleOutput(output.Name()))
				}
				if !strings.Contains(readLifecycleOutput(output.Name()), "RESULT ") {
					t.Fatal("command exited without printing its result")
				}
				if stage != "late" {
					if stage == "limit" {
						// The original caller is gone, but its four workers still
						// own the bound. A fresh invocation must also refuse.
						assertFreshCommandLimit(t, base, blocked)
					}
					for tid := range held {
						if !live[tid] {
							t.Fatalf("blocked task %d exited before recovery", tid)
						}
						if err := syscall.PtraceCont(tid, 0); err != nil {
							t.Fatalf("ptrace recover held worker %d: %v", tid, err)
						}
					}
					released = true
					// The command met its exit bound. Give recovery its own
					// bound, and stop tracing irrelevant compiler syscalls.
					deadline = time.Now().Add(hangGuard)
				}
			}
			continue
		}
		live[pid] = true
		if status.TrapCause() == syscall.PTRACE_EVENT_EXEC {
			// A nonleader thread that execs adopts its group's leader tid.
			// Its old tid has no separate exit event and must leave the set.
			previous, err := syscall.PtraceGetEventMsg(pid)
			if exitedDuringTraceRead(t, "exec event", pid, held[pid], err) {
				continue
			}
			if int(previous) != pid {
				completed[int(previous)] = true
				delete(live, int(previous))
			}
		}
		if status.TrapCause() == syscall.PTRACE_EVENT_FORK || status.TrapCause() == syscall.PTRACE_EVENT_VFORK || status.TrapCause() == syscall.PTRACE_EVENT_CLONE {
			child, err := syscall.PtraceGetEventMsg(pid)
			if exitedDuringTraceRead(t, "fork event", pid, held[pid], err) {
				continue
			}
			// Wait4(-1) can deliver a child's exit before the parent's
			// fork event. Do not resurrect an already reaped launcher.
			if !completed[int(child)] {
				live[int(child)] = true
			}
		}
		if status.StopSignal() == syscall.Signal(int(syscall.SIGTRAP)|0x80) && !released {
			var regs syscall.PtraceRegs
			if err := syscall.PtraceGetRegs(pid, &regs); exitedDuringTraceRead(t, "syscall registers", pid, held[pid], err) {
				continue
			}
			if int64(regs.Rax) == -int64(syscall.ENOSYS) && lifecyclePath(pid, regs, blocked) {
				statusBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
				if err != nil {
					t.Fatal(err)
				}
				statusFields := map[string]string{}
				for _, line := range strings.Split(string(statusBytes), "\n") {
					if key, value, ok := strings.Cut(line, ":"); ok {
						statusFields[key] = strings.TrimSpace(value)
					}
				}
				if statusFields["Tgid"] == fmt.Sprint(leader) || statusFields["PPid"] == fmt.Sprint(leader) {
					t.Fatalf("pathname syscall remains in caller or its waiting child: tid=%d tgid=%s ppid=%s caller=%d", pid, statusFields["Tgid"], statusFields["PPid"], leader)
				}
				callerStatus, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", leader))
				if err != nil {
					t.Fatal(err)
				}
				for _, line := range strings.Split(string(callerStatus), "\n") {
					key, value, ok := strings.Cut(line, ":")
					if !ok {
						continue
					}
					switch key {
					case "Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb":
						if strings.Join(strings.Fields(value), " ") != strings.Join(strings.Fields(statusFields[key]), " ") {
							t.Fatalf("helper %s credentials %q differ from caller %q", key, statusFields[key], value)
						}
					}
				}
				caller, err := sys.ReadTaskCreds(leader)
				if err != nil {
					t.Fatal(err)
				}
				worker, err := sys.ReadTaskCreds(pid)
				if err != nil {
					t.Fatal(err)
				}
				if !caller.Equal(worker) {
					t.Fatalf("helper credentials %+v differ from caller %+v", worker, caller)
				}
				held[pid] = true
				observed++
				continue
			}
		}
		sig := 0
		if status.StopSignal() != syscall.SIGTRAP && status.StopSignal() != syscall.SIGSTOP && status.StopSignal() != syscall.Signal(int(syscall.SIGTRAP)|0x80) {
			sig = int(status.StopSignal())
		}
		var resumeErr error
		if released {
			resumeErr = syscall.PtraceCont(pid, sig)
		} else {
			resumeErr = syscall.PtraceSyscall(pid, sig)
		}
		if resumeErr != nil && !errors.Is(resumeErr, syscall.ESRCH) {
			t.Fatalf("ptrace resume task %d: %v", pid, resumeErr)
		}
	}
	if !commandExited {
		t.Fatal("never observed command process exit")
	}
	if stage == "late" && !strings.Contains(readLifecycleOutput(output.Name()), "LATE discarded") {
		t.Fatal("late response was not checked")
	}
	t.Logf("%s: command printed and exited with %d pathname syscall(s) held; matching credentials; all traced helper tasks exited after recovery", stage, observed)
}

// exit_group can remove an unheld runtime thread after Wait4 reported its stop
// and before a ptrace read. Its final wait event still owns removal from live.
func exitedDuringTraceRead(t *testing.T, operation string, pid int, held bool, err error) bool {
	t.Helper()
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ESRCH) && !held {
		return true
	}
	t.Fatalf("ptrace %s for task %d (held=%t): %v", operation, pid, held, err)
	return false
}

func assertFreshCommandLimit(t *testing.T, base, blocked string) {
	t.Helper()
	// A hang guard, not a speed claim: the child measures its own refusal from its call (refusedForWantOfASlot), so a
	// busy machine that is slow to start the child process cannot fail this.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	outputFile, err := os.Create(filepath.Join(base, "cross-output"))
	if err != nil {
		t.Fatal(err)
	}
	defer outputFile.Close()
	cmd := exec.CommandContext(ctx, os.Args[0], "--contracts-lifecycle-child", "cross-limit", base, blocked)
	cmd.Stdout, cmd.Stderr = outputFile, outputFile
	err = cmd.Run()
	output := readLifecycleOutput(outputFile.Name())
	if ctx.Err() != nil {
		t.Fatalf("fresh invocation waited on exhausted helper bound: %v; output=%s", ctx.Err(), output)
	}
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 125 || !strings.Contains(output, "RESULT incomplete cross-limit=4") {
		t.Fatalf("fresh invocation bypassed existing four workers: error=%v output=%s", err, output)
	}
	t.Log("fresh command refused while the exited caller's four helpers remained blocked")
}

func readLifecycleOutput(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return err.Error()
	}
	return string(b)
}

func lifecyclePath(pid int, r syscall.PtraceRegs, blocked string) bool {
	var address uint64
	var dirfd int64 = -100 // AT_FDCWD
	switch r.Orig_rax {
	case syscall.SYS_OPENAT, syscall.SYS_NEWFSTATAT, syscall.SYS_READLINKAT, 437, 332: // openat2, statx
		address, dirfd = r.Rsi, int64(r.Rdi)
	case syscall.SYS_OPEN, syscall.SYS_STAT, syscall.SYS_LSTAT, syscall.SYS_READLINK:
		address = r.Rdi
	default:
		return false
	}
	name := make([]byte, 0, 4096)
	for len(name) < 4096 {
		var chunk [8]byte
		n, err := syscall.PtracePeekData(pid, uintptr(address)+uintptr(len(name)), chunk[:])
		if err != nil {
			return false
		}
		if end := bytes.IndexByte(chunk[:n], 0); end >= 0 {
			name = append(name, chunk[:end]...)
			break
		}
		name = append(name, chunk[:n]...)
	}
	path := string(name)
	if !filepath.IsAbs(path) {
		anchor := fmt.Sprintf("/proc/%d/cwd", pid)
		if dirfd != -100 {
			anchor = fmt.Sprintf("/proc/%d/fd/%d", pid, dirfd)
		}
		dir, err := os.Readlink(anchor)
		if err != nil {
			return false
		}
		path = filepath.Join(dir, path)
	}
	return path == blocked || strings.HasPrefix(path, blocked+"/")
}

// waitLifecycleTask polls known tracees in rotation. Wait4(-1) can repeatedly
// select a hot sched_yield thread while leaving other tasks in ptrace stops,
// preventing their launchers and even the caller's deadline timer from running.
func waitLifecycleTask(live map[int]bool, after *int) (int, syscall.WaitStatus, error) {
	tasks := make([]int, 0, len(live))
	for pid := range live {
		tasks = append(tasks, pid)
	}
	slices.Sort(tasks)
	start := 0
	for start < len(tasks) && tasks[start] <= *after {
		start++
	}
	for offset := range tasks {
		tid := tasks[(start+offset)%len(tasks)]
		var status syscall.WaitStatus
		pid, err := syscall.Wait4(tid, &status, syscall.WALL|syscall.WNOHANG, nil)
		if errors.Is(err, syscall.ECHILD) {
			// A nonleader exec can retire its old tid before its leader's
			// exec event removes that tid from live. Poll the leader too.
			continue
		}
		if err != nil || pid != 0 {
			*after = tid
			return pid, status, err
		}
	}
	return 0, 0, nil
}
