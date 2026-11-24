// SPDX-License-Identifier: Apache-2.0

//go:build linux

package proc

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// threadSchedule reads one thread's nice value and scheduling policy from its /proc stat (fields 19 and 41).
func threadSchedule(t *testing.T, path string) (nice, policy int) {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	fields := strings.Fields(s[strings.LastIndexByte(s, ')')+1:]) // field 3 is the first after the name
	if len(fields) < 39 {
		t.Fatalf("%s has %d fields after its name", path, len(fields))
	}
	nice, err = strconv.Atoi(fields[16])
	if err != nil {
		t.Fatal(err)
	}
	policy, err = strconv.Atoi(fields[38])
	if err != nil {
		t.Fatal(err)
	}
	return nice, policy
}

// LowerPriority lowers only the calling thread, to nice 19 and the idle policy where the kernel allows it; another
// thread of the process keeps its priority. The lowered thread ends with its goroutine, which exits locked.
func TestLowerPriorityLowersOnlyTheCallingThread(t *testing.T) {
	// A bystander holds its own OS thread, so the lowering goroutine's thread is another one.
	read, quit := make(chan [2]int), make(chan struct{})
	ask := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		for {
			select {
			case <-ask:
				n, p := threadSchedule(t, "/proc/thread-self/stat")
				read <- [2]int{n, p}
			case <-quit:
				return
			}
		}
	}()
	defer close(quit)
	ask <- struct{}{}
	before := <-read
	type seen struct {
		idle         bool
		err          error
		nice, policy int
	}
	done := make(chan seen)
	go func() {
		runtime.LockOSThread() // never unlocked: the lowered thread is retired with this goroutine
		var s seen
		s.idle, s.err = LowerPriority()
		s.nice, s.policy = threadSchedule(t, "/proc/thread-self/stat")
		done <- s
	}()
	s := <-done
	if s.err != nil {
		t.Fatalf("LowerPriority: %v", s.err)
	}
	if s.nice != 19 {
		t.Errorf("nice after LowerPriority = %d, want 19", s.nice)
	}
	if s.idle != (s.policy == unix.SCHED_IDLE) {
		t.Errorf("LowerPriority said idle=%v, the thread's policy is %d", s.idle, s.policy)
	}
	if !s.idle {
		t.Logf("this kernel refused SCHED_IDLE here: nice alone (policy %d)", s.policy)
	}
	ask <- struct{}{}
	if after := <-read; after != before {
		t.Errorf("another thread's schedule moved: nice %d policy %d, was %d and %d", after[0], after[1], before[0], before[1])
	}
}
