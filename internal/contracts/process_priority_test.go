// SPDX-License-Identifier: Apache-2.0

package contracts

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/proc"
)

// taskSchedules is the nice value and scheduling policy of every thread of process pid (stat fields 19 and 41).
func taskSchedules(t *testing.T, pid int) (nice, policy []int) {
	t.Helper()
	tasks, err := filepath.Glob(fmt.Sprintf("/proc/%d/task/*/stat", pid))
	if err != nil || len(tasks) == 0 {
		t.Fatalf("threads of %d: %v (%d)", pid, err, len(tasks))
	}
	for _, path := range tasks {
		b, err := os.ReadFile(path)
		if err != nil {
			continue // the thread ended meanwhile
		}
		s := string(b)
		fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
		n, errN := strconv.Atoi(fields[16])
		p, errP := strconv.Atoi(fields[38])
		if errN != nil || errP != nil {
			t.Fatalf("%s: unreadable schedule", path)
		}
		nice, policy = append(nice, n), append(policy, p)
	}
	return nice, policy
}

// workerOf is the pid of the worker a started helper's launcher started, as the worker itself says it in its first
// frame (helperCredentials.Pid), the one the product's own record of an abandoned worker is made from. It is not found
// through /proc/<pid>/fd: the worker is undumpable, so no other process of the user may read its descriptors.
func workerOf(t *testing.T, w *helperWorker) int {
	t.Helper()
	encoded, err := readFrame(w.receive, 1<<20)
	if err != nil {
		t.Fatalf("the helper's first frame: %v", err)
	}
	var header helperCredentials
	if err := json.Unmarshal(encoded, &header); err != nil || header.Pid == 0 {
		t.Fatalf("the helper's first frame %q: pid %d, %v", encoded, header.Pid, err)
	}
	return header.Pid
}

// startedWorker starts a helper for ctx as a request does, waits out its launcher and returns its worker's pid.
func startedWorker(t *testing.T, ctx context.Context) int {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	as, err := readHelperCredentials()
	if err != nil {
		t.Fatal(err)
	}
	w, err := startHelper(ctx, as)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(w.close)
	if err := w.cmd.Wait(); err != nil {
		t.Fatalf("launcher: %v", err)
	}
	return workerOf(t, w)
}

// A governed request's helper worker, and every thread of it, runs at the lowest CPU priority an unprivileged
// process may take (nice 19 and the idle policy where the kernel allows it), so a governed program's checks can
// never win the CPU from a person's own check; the person's worker keeps the priority of the dashboard's thread that
// started it, whatever that is. Both are read back from the kernel, from every thread of the worker.
func TestGovernedHelperWorkerRunsAtTheLowestPriority(t *testing.T) {
	standsAt(t, false, nil)
	prev := helperReservationPool
	helperReservationPool = fmt.Sprintf("tego.contracts-test.%x", sha256.Sum256([]byte(t.Name()+fmt.Sprint(os.Getpid()))))
	t.Cleanup(func() { helperReservationPool = prev })

	// Whether this kernel gives the idle policy to an unprivileged thread: probed on a thread that retires after.
	probe := make(chan bool)
	go func() {
		runtime.LockOSThread() // never unlocked: the lowered thread is retired with this goroutine
		idle, err := proc.LowerPriority()
		probe <- idle && err == nil
	}()
	idle := <-probe

	var ownNice, ownPolicy int
	func() {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		// The thread that starts the helper in the person's case is this one: its own schedule is the expectation.
		b, err := os.ReadFile("/proc/thread-self/stat")
		if err != nil {
			t.Fatal(err)
		}
		s := string(b)
		fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:])
		ownNice, _ = strconv.Atoi(fields[16])
		ownPolicy, _ = strconv.Atoi(fields[38])
	}()

	person := startedWorker(t, WithGovernedCaller(context.Background(), func() bool { return false }))
	governed := startedWorker(t, WithGovernedCaller(context.Background(), func() bool { return true }))

	pn, pp := taskSchedules(t, person)
	for i := range pn {
		if pn[i] != ownNice || pp[i] != ownPolicy {
			t.Errorf("a person's worker thread has nice %d policy %d, want its starter's (%d, %d)", pn[i], pp[i], ownNice, ownPolicy)
		}
	}
	gn, gp := taskSchedules(t, governed)
	for i := range gn {
		if gn[i] != 19 || idle && gp[i] != unix.SCHED_IDLE {
			t.Errorf("a governed worker thread has nice %d policy %d, want nice 19 and policy %d (idle available: %v)", gn[i], gp[i], unix.SCHED_IDLE, idle)
		}
	}
	if ownNice == 19 && (!idle || ownPolicy == unix.SCHED_IDLE) {
		t.Skip("this test process already runs at the lowest priority: the person's worker cannot be told from a governed one")
	}
	if pn[0] == 19 && pp[0] == unix.SCHED_IDLE {
		t.Error("a person's worker runs at the lowest priority")
	}
}
