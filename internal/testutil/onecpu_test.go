// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// oneCPUEnv makes this test binary, re-executed by a test of the own time, play one part in TestOneCPUChild: "spin"
// works until it is killed (another process wanting the CPU), "handoff" measures a wait for another goroutine's work.
// The parent starts it from a thread held to one CPU (onOneCPU), and a child's threads all inherit that CPU.
const oneCPUEnv = "TEGO_TESTUTIL_ONE_CPU_CHILD"

// TestOneCPUChild is the re-executed binary's test (oneCPUEnv); run plainly it skips.
func TestOneCPUChild(t *testing.T) {
	switch part := os.Getenv(oneCPUEnv); part {
	case "":
		t.Skip("run as a child of TestOwnTimeLeavesOutRunQueueWaits or TestAHandOffShowsInTheOwnTime")
	case "spin":
		fmt.Println("spinning")
		x := uint64(1)
		for deadline := time.Now().Add(time.Minute); time.Now().Before(deadline); {
			for range 1 << 16 {
				x = x*6364136223846793005 + 1
			}
		}
		spinSink = x
	case "handoff":
		handOffOnOneCPU(t)
	default:
		t.Fatalf("%s=%q: want spin or handoff", oneCPUEnv, part)
	}
}

// TestAHandOffShowsInTheOwnTime: a wait for work the code hands to another goroutine counts in the own time, also
// where the waiting thread never blocks. That is so wherever the process has fewer CPUs than runnable threads, even
// on an idle machine: the helper's wake-up takes the CPU from the waiting thread before it parks, the thread waits in
// the run queue for the helper's whole run, and its later futex sleep returns at once, so the wait is all run-queue
// delay and never a voluntary switch. Before the own time held the process's other threads' CPU time against the
// run-queue delay (2026-10-17), the fastest of 400 such samples read 3.7 µs of own time for a 500 µs hand-off and
// passed a 12 µs Limit's 120 µs ceiling (a review's probe under taskset, 3 runs of 3). The child process runs on one
// CPU, with one P and with four.
func TestAHandOffShowsInTheOwnTime(t *testing.T) {
	requireRunQueue(t)
	onOneCPU(t, func(cpu int) {
		for _, procs := range []string{"1", "4"} {
			cmd := oneCPUChild(t, "handoff", "GOMAXPROCS="+procs)
			cmd.Args = append(cmd.Args, "-test.v")
			out, err := cmd.CombinedOutput()
			t.Logf("GOMAXPROCS=%s, held to CPU %d:\n%s", procs, cpu, out)
			if err != nil || !strings.Contains(string(out), "--- PASS: TestOneCPUChild") {
				t.Errorf("the hand-off child, GOMAXPROCS=%s on CPU %d: %v", procs, cpu, err)
			}
		}
	})
}

// handOffOnOneCPU is the "handoff" child: on its one CPU, a sample that waits for 500 µs of another goroutine's work
// must fail a 12 µs Limit's unit-gate ceiling on its own time.
func handOffOnOneCPU(t *testing.T) {
	m, err := threadAffinity()
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, w := range m {
		for ; w != 0; w &= w - 1 {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("the child may run on %d CPUs, want 1: %v", n, m)
	}
	const work = 500 * time.Microsecond
	handOff := func() {
		ch := make(chan struct{})
		go func() {
			spinCPU(work)
			close(ch)
		}()
		<-ch
	}
	fs := Mode{}.Measure(400, handOff, func() {})
	f := fs[0].Sub(fs[1])
	t.Logf("a wait for %v of another goroutine's work, the process held to one CPU: %v", work, f)
	r := &judgeTB{TB: t}
	Mode{}.Judge(r, Budget{Name: "hand-off", Limit: 12 * time.Microsecond, Spec: "test", Added: true}, f)
	if !slices.ContainsFunc(r.errs, func(e string) bool {
		return strings.Contains(e, "of the thread's own time, over the unit gate's +120µs ceiling")
	}) {
		t.Errorf("a %v hand-off measured %v: errors %q, want a failure of its own time against the +120µs ceiling",
			work, f, r.errs)
	}
}

// requireRunQueue skips a test of the run-queue delay where the kernel does not report it.
func requireRunQueue(t *testing.T) {
	t.Helper()
	q := openRunQueue()
	if !q.ok() {
		t.Skip("no readable /proc/thread-self/schedstat (CONFIG_SCHED_INFO): the unit gate holds the wall clock")
	}
	q.close()
}

// onOneCPU runs fn on the calling goroutine, locked to its thread and that thread held to the first CPU of its mask,
// and restores the mask after. A thread whose mask cannot be restored ends with the goroutine (it stays locked), so
// a one-CPU mask never reaches the runtime's pool.
func onOneCPU(t *testing.T, fn func(cpu int)) {
	t.Helper()
	runtime.LockOSThread()
	was, err := threadAffinity()
	if err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	cpu := -1
	for i := range len(was) * 64 {
		if was[i/64]&(1<<(i%64)) != 0 {
			cpu = i
			break
		}
	}
	if cpu < 0 {
		runtime.UnlockOSThread()
		t.Fatalf("an empty CPU mask: %v", was)
	}
	var one cpuMask
	one[cpu/64] = 1 << (cpu % 64)
	if err := setThreadAffinity(one); err != nil {
		runtime.UnlockOSThread()
		t.Fatal(err)
	}
	defer func() {
		if err := setThreadAffinity(was); err != nil {
			t.Errorf("restoring the thread's CPUs: %v", err)
			return
		}
		runtime.UnlockOSThread()
	}()
	fn(cpu)
}

// oneCPUChild is this test binary re-executed to play part in TestOneCPUChild, with env added. Started from onOneCPU's
// fn, it runs on that one CPU: a fork copies the forking thread's mask, which the goroutine's lock makes that thread.
func oneCPUChild(t *testing.T, part string, env ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOneCPUChild$", "-test.count=1")
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, oneCPUEnv+"=") && !strings.HasPrefix(kv, "GOMAXPROCS=") {
			cmd.Env = append(cmd.Env, kv)
		}
	}
	cmd.Env = append(cmd.Env, oneCPUEnv+"="+part)
	cmd.Env = append(cmd.Env, env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	return cmd
}

// startSpinner starts the "spin" child on onOneCPU's CPU and returns once it works, with the function that stops it:
// another process that wants the CPU, whose work no figure of this process counts.
func startSpinner(t *testing.T) (stop func()) {
	t.Helper()
	cmd := oneCPUChild(t, "spin")
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	stop = func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "spinning\n" {
		stop()
		t.Fatalf("the spinning child said %q: %v", line, err)
	}
	return stop
}

// cpuMask is a sched_setaffinity mask of 1024 CPUs.
type cpuMask [16]uint64

// threadAffinity is the calling thread's CPU mask.
func threadAffinity() (cpuMask, error) {
	var m cpuMask
	_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_GETAFFINITY, 0, unsafe.Sizeof(m), uintptr(unsafe.Pointer(&m)))
	if errno != 0 {
		return m, fmt.Errorf("sched_getaffinity: %w", errno)
	}
	return m, nil
}

// setThreadAffinity holds the calling thread to the CPUs in m.
func setThreadAffinity(m cpuMask) error {
	_, _, errno := syscall.RawSyscall(syscall.SYS_SCHED_SETAFFINITY, 0, unsafe.Sizeof(m), uintptr(unsafe.Pointer(&m)))
	if errno != 0 {
		return fmt.Errorf("sched_setaffinity: %w", errno)
	}
	return nil
}
