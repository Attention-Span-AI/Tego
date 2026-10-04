// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func TestFanotifyRequestsThreadIDs(t *testing.T) {
	saved, roots := fanotifyInit, threadRoots
	t.Cleanup(func() { fanotifyInit, threadRoots = saved, roots })
	host := fakeHost{cgroup: "/run", self: 12, threadsMax: 16384, threads: 400, pids: map[string][2]int64{"/run": {1200, 180}}}
	threadRoots.proc, threadRoots.cgroup = host.build(t)
	called := false
	fanotifyInit = func(flags uint, _ uint) (int, error) {
		called = true
		if flags&unix.FAN_REPORT_TID == 0 {
			t.Error("fanotify cannot distinguish sibling opens")
		}
		return -1, unix.EPERM
	}
	_, _ = newFanotifyListener(nil, Run{}, nil, 0)
	if !called {
		t.Fatal("fanotify_init was not reached")
	}
}

func TestFanotifyThreadAttribution(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if pid := threadGroupOf(unix.Gettid()); pid != os.Getpid() {
		t.Fatalf("thread resolves to %d, want %d", pid, os.Getpid())
	}
	if pid := threadGroupOf(-1); pid != 0 {
		t.Fatalf("absent thread resolves to %d", pid)
	}
}

// The process lookup must precede FAN_DENY: answering releases the thread, which can exit and be reused.
func TestFanotifyAttributionPrecedesResponse(t *testing.T) {
	s := &sink{}
	l, response := testListener(t, s, func(fanEvent) (verdict, error) { return verdict{reason: record.ReasonReadDenied}, nil }, time.Second)
	var answered atomic.Bool
	l.threadGroup = func(int) int {
		if answered.Load() {
			t.Error("read process identity after releasing the opener")
		}
		return 4200
	}
	l.write = func(fd int, b []byte) (int, error) { answered.Store(true); return unix.Write(fd, b) }
	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 4201})
	_, _ = readResponse(t, response)
	events := s.all()
	if len(events) != 1 || events[0].PID != 4200 || events[0].TID != 4201 {
		t.Fatalf("event identity: %+v", events)
	}
}
