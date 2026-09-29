// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestALateRefusalReadsNoDescriptorTheDeadlineClosed: a decision answered at the deadline goes on running, and the
// descriptor it came with is closed and its number free for the kernel to hand to another event. The exec-line
// question read the image's identity through that number once the late refusal came, so it could consume the
// supervisor's entry for another file. The identity is read before the decision, by the worker that owns the
// descriptor, and the late question asks the supervisor with that.
func TestALateRefusalReadsNoDescriptorTheDeadlineClosed(t *testing.T) {
	t.Parallel()
	refused := verdict{path: "/work/secrets/tool", rule: "fs.deny_read[./secrets/]", reason: record.ReasonReadDenied}
	release := make(chan struct{})
	s := &sink{}
	l, r := testListener(t, s, func(fanEvent) (verdict, error) {
		<-release
		return refused, nil
	}, 20*time.Millisecond)
	var answered atomic.Bool
	lateRead := make(chan bool, 4)
	l.fileID = func(int) (uint64, uint64, bool) {
		lateRead <- answered.Load()
		return 7, 11, true
	}
	asked := make(chan [3]uint64, 1)
	fn := func(pid int, dev, ino uint64) bool {
		asked <- [3]uint64{uint64(pid), dev, ino}
		return true
	}
	l.execLine.Store(&fn)
	fd := openFD(t)
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 4242})
	answered.Store(true)
	if _, resp := readResponse(t, r); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x, want FAN_ALLOW at the deadline", resp)
	}
	close(release)
	select {
	case got := <-asked:
		if got != [3]uint64{4242, 7, 11} {
			t.Errorf("the supervisor was asked about %v, want the image read before the deadline", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the late refusal never asked the supervisor")
	}
	for len(lateRead) > 0 {
		if <-lateRead {
			t.Error("the event's descriptor was read after the deadline had answered and closed it")
		}
	}
}

// TestListenerLeavesAnExecsRefusedOpenToTheSupervisor is supervisor R7a for an exec whose image's open this
// listener refuses: the supervisor continued the exec and wrote its line, refused under the deny_read, so the
// refused FAN_OPEN_PERM of that image by that process gets no line here (it is still refused), and the action
// has one. Any other refused open, and a refused FAN_OPEN_EXEC_PERM, keeps this listener's line, and so does
// every refusal while no supervisor answers.
func TestListenerLeavesAnExecsRefusedOpenToTheSupervisor(t *testing.T) {
	t.Parallel()
	refused := verdict{path: "/work/secrets/tool", rule: "fs.deny_read[./secrets/]", reason: record.ReasonReadDenied}
	const dev, ino = 7, 11
	for _, tc := range []struct {
		name   string
		mask   uint64
		pid    int32
		hook   bool
		ino    uint64
		lines  int
		asked  int
		denied bool
	}{
		{name: "the exec's open", mask: unix.FAN_OPEN_PERM, pid: 4242, hook: true, ino: ino, lines: 0, asked: 1},
		{name: "another process's open of the image", mask: unix.FAN_OPEN_PERM, pid: 4243, hook: true, ino: ino, lines: 1, asked: 1},
		{name: "another file", mask: unix.FAN_OPEN_PERM, pid: 4242, hook: true, ino: ino + 1, lines: 1, asked: 1},
		{name: "a refused exec permission", mask: unix.FAN_OPEN_EXEC_PERM, pid: 4242, hook: true, ino: ino, lines: 1},
		{name: "no supervisor", mask: unix.FAN_OPEN_PERM, pid: 4242, ino: ino, lines: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &sink{}
			l, r := testListener(t, s, func(fanEvent) (verdict, error) { return refused, nil }, time.Second)
			asked := 0
			if tc.hook {
				fn := func(pid int, d, i uint64) bool {
					asked++
					return pid == 4242 && d == dev && i == ino
				}
				l.execLine.Store(&fn)
			}
			l.fileID = func(int) (uint64, uint64, bool) { return dev, tc.ino, true }
			fd := openFD(t)
			l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: tc.mask, FD: fd, PID: tc.pid})
			if _, resp := readResponse(t, r); resp != unix.FAN_DENY {
				t.Fatalf("response %#x, want FAN_DENY: the open is refused whoever writes its line", resp)
			}
			if got := len(s.all()); got != tc.lines || asked != tc.asked {
				t.Errorf("%d lines, supervisor asked %d times; want %d, %d", got, asked, tc.lines, tc.asked)
			}
		})
	}
}

// TestAStalledIdentityReadHoldsNoWorker is §6 E34/E35 for the exec-line identity read: it goes through the
// event's descriptor, and on NFS or FUSE a server that stopped answering holds it in the kernel. It ran on the
// worker before the deadline's timer started, so each such read took a worker for good and 16 stalled the read
// loop. It now runs under the deadline: handle answers FAN_ALLOW and returns, leaves the descriptor open while
// the read still goes through it, and the read, once it returns, closes it and asks the supervisor nothing.
func TestAStalledIdentityReadHoldsNoWorker(t *testing.T) {
	t.Parallel()
	refused := verdict{path: "/nfs/secrets/key", rule: "fs.deny_read[./secrets/]", reason: record.ReasonReadDenied}
	decided := make(chan struct{}, 1)
	s := &sink{}
	l, r := testListener(t, s, func(fanEvent) (verdict, error) {
		decided <- struct{}{}
		return refused, nil
	}, 20*time.Millisecond)
	release := make(chan struct{})
	l.fileID = func(int) (uint64, uint64, bool) {
		<-release
		return 7, 11, true
	}
	fn := func(int, uint64, uint64) bool {
		t.Error("the supervisor was asked about an event the deadline had answered before its identity was read")
		return true
	}
	l.execLine.Store(&fn)
	closed := make(chan int, 2)
	l.closeSettled = func(fd int) error {
		closed <- fd
		return unix.Close(fd)
	}
	l.closer = newFDCloser(l.closeSettled, 8) // not run: a close handed to it stays counted in its backlog
	fd := openFD(t)
	returned := make(chan struct{})
	go func() {
		l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 4242})
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("handle waited on the identity read past the deadline: the worker is held by the filesystem")
	}
	if _, resp := readResponse(t, r); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x, want FAN_ALLOW at the deadline", resp)
	}
	if n := l.closer.backlog(); n != 0 {
		t.Fatalf("the deadline branch closed the descriptor (%d queued) while the identity read still went through it", n)
	}
	if got := l.overdue.Load(); got != 1 {
		t.Errorf("overdue %d while the identity read is stalled, want 1", got)
	}
	close(release)
	select {
	case got := <-closed:
		if got != int(fd) {
			t.Errorf("closed descriptor %d, want %d", got, fd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the descriptor was never closed once the identity read returned")
	}
	deadline := time.Now().Add(5 * time.Second)
	for l.overdue.Load() != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := l.overdue.Load(); got != 0 {
		t.Errorf("overdue %d after the late read returned, want 0", got)
	}
	select {
	case <-decided:
		t.Error("an event the deadline answered was decided after its identity read")
	default:
	}
	if n := l.closer.backlog(); n != 0 {
		t.Errorf("the descriptor was also handed to the closer (%d queued): a double close", n)
	}
}

// TestFstatIDMatchesFstat: the supervisor compares the image's identity with fstat's st_dev and st_ino, so the
// statx fstatID reads must encode the device the same way.
func TestFstatIDMatchesFstat(t *testing.T) {
	t.Parallel()
	for _, path := range []string{os.DevNull, t.TempDir(), "/proc/self/stat"} {
		f, err := os.Open(path)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		var st unix.Stat_t
		if err := unix.Fstat(int(f.Fd()), &st); err != nil {
			t.Fatalf("fstat %s: %v", path, err)
		}
		dev, ino, ok := fstatID(int(f.Fd()))
		f.Close()
		if !ok || dev != st.Dev || ino != st.Ino {
			t.Errorf("%s: fstatID = %d, %d, %v; fstat says %d, %d", path, dev, ino, ok, st.Dev, st.Ino)
		}
	}
}
