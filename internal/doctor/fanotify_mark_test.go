// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"golang.org/x/sys/unix"
)

// fanotifyMarkProbeTimeout bounds the two waits below. Each is a local open on a local file, so a
// kernel that is going to deliver the event has delivered it long before this elapses; the bound
// only stops a broken kernel from hanging `go test`.
const fanotifyMarkProbeTimeout = 500 * time.Millisecond

// unprivilegedFanotify opens the one fanotify group an ordinary uid may create: FAN_CLASS_NOTIF
// with FAN_REPORT_FID (Linux 5.13+). It cannot carry permission events — FANOTIFY_ADMIN_INIT_FLAGS
// needs CAP_SYS_ADMIN in the initial user namespace — but mark placement and event *generation* are
// the same fsnotify machinery D8 depends on, so it settles which object a mark covers without root.
func unprivilegedFanotify(t *testing.T) int {
	t.Helper()
	fd, err := unix.FanotifyInit(unix.FAN_CLASS_NOTIF|unix.FAN_REPORT_FID|unix.FAN_CLOEXEC,
		unix.O_RDONLY|unix.O_CLOEXEC)
	if err != nil {
		t.Skipf("unprivileged fanotify group (5.13+): %v", err)
	}
	t.Cleanup(func() { _ = unix.Close(fd) })
	return fd
}

// pendingEvents reports how many events are queued on the group, waiting up to the bound above. A signal that lands
// while it waits resumes the wait (testutil.PollReadable): the race job's integration step failed
// TestFanotifyProbeMarksTheObjectItOpens after 0.00 s with "poll: interrupted system call", a single poll's first
// wait, for an event that must not come, ended by a signal.
func pendingEvents(t *testing.T, fd int) int {
	t.Helper()
	n, err := testutil.PollReadable(fd, fanotifyMarkProbeTimeout)
	if err != nil {
		t.Fatalf("poll: %v", err)
	}
	return n
}

// TestFanotifyProbeMarksTheObjectItOpens is the regression test for D8's silent timeout: the probe
// used to mark the temporary *directory* and open a file inside it, and a plain FAN_MARK_INODE mark
// covers only the object named — fanotify_mark(2), "events for the immediate children of marked
// directories" need FAN_EVENT_ON_CHILD in the mask. No event was ever generated, readFanotifyEvent
// waited out fanotifyProbeTimeout on every kernel, and D8 never reached the reply at all. D8 now
// fails when its FAN_DENY round trip cannot be completed, so the same mistake would fail tier cgroup
// on every kernel instead of passing unnoticed.
//
// It drives markProbeTarget — the production helper that decides what D8 marks — and asserts the
// kernel actually delivers an event for the object it returns. Marking the parent directory instead
// makes the second half report 0 queued events and the test fail.
func TestFanotifyProbeMarksTheObjectItOpens(t *testing.T) {
	dir := t.TempDir()

	// Half one, the kernel fact the old code got wrong: a directory inode mark, no
	// FAN_EVENT_ON_CHILD, does not see a child being opened.
	fd := unprivilegedFanotify(t)
	child := filepath.Join(dir, "child")
	if err := os.WriteFile(child, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_ADD, unix.FAN_OPEN, unix.AT_FDCWD, dir); err != nil {
		t.Skipf("mark the temporary directory: %v", err)
	}
	openAndClose(t, child)
	if n := pendingEvents(t, fd); n != 0 {
		t.Errorf("a directory mark without FAN_EVENT_ON_CHILD reported %d events for a child open; "+
			"fanotify_mark(2) says a plain inode mark covers only the object named", n)
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE, unix.FAN_OPEN, unix.AT_FDCWD, dir); err != nil {
		t.Fatalf("remove the directory mark: %v", err)
	}

	// Half two, what D8 now does: markProbeTarget marks the object the probe opens, and the event
	// arrives. It arrives in the marking process itself, which is what lets D8 answer its own
	// opener from another goroutine.
	target, err := markProbeTarget(fd, unix.FAN_OPEN, dir)
	if err != nil {
		t.Fatalf("markProbeTarget: %v", err)
	}
	if want := filepath.Join(dir, fanotifyProbeFile); target != want {
		t.Fatalf("markProbeTarget returned %q, want %q", target, want)
	}
	openAndClose(t, target)
	if n := pendingEvents(t, fd); n == 0 {
		t.Fatalf("no event within %s for an open of the marked object %s: D8 would wait out its whole "+
			"%s timeout and never test a FAN_DENY reply on any kernel", fanotifyMarkProbeTimeout, target,
			fanotifyProbeTimeout)
	}
	buf := make([]byte, 4096)
	n, err := unix.Read(fd, buf)
	if err != nil {
		t.Fatalf("read the event: %v", err)
	}
	meta, err := ParseFanotifyMetadata(buf[:n])
	if err != nil {
		t.Fatalf("decode the event: %v", err)
	}
	if meta.mask&unix.FAN_OPEN == 0 {
		t.Errorf("event mask %#x carries no FAN_OPEN", meta.mask)
	}
	if int(meta.pid) != os.Getpid() {
		t.Errorf("event pid %d, want this process %d", meta.pid, os.Getpid())
	}
	if err := unix.FanotifyMark(fd, unix.FAN_MARK_REMOVE, unix.FAN_OPEN, unix.AT_FDCWD, target); err != nil {
		t.Errorf("remove the target mark: %v", err)
	}
}

func openAndClose(t *testing.T, path string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close %s: %v", path, err)
	}
}
