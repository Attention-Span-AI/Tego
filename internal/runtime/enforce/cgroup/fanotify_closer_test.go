// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// closerRig is a loop() over a socket pair whose closer holds the first descriptor it is given, as a FUSE daemon
// or an NFS server that stopped answering would hold its close (fdCloser, §6 E35).
type closerRig struct {
	l          *fanotifyListener
	kernelSide int
	events     *sink
	dir        string
	held       chan struct{}
	release    func()
	loopErr    chan error
	unmarked   atomic.Int32
}

func newCloserRig(t *testing.T) *closerRig {
	t.Helper()
	r := &closerRig{events: &sink{}, dir: t.TempDir(), held: make(chan struct{}), loopErr: make(chan error, 1)}
	r.l, r.kernelSide = socketpairListener(t, r.events, nil)
	r.l.policy = newPolicy(policyTable([]agent.FSRule{
		fsRule(agent.FSDenyRead, filepath.Join(r.dir, "secret"), "", "secret"),
	}, nil), "/run.scope")
	r.l.settle = r.l.settleByPath
	r.l.decide = r.l.decideEvent
	// The opener of every refused event is the run's, so a worker answers it with a refusal.
	r.l.run.CgroupPath = "/run.scope"
	r.l.cgroupOfPID = func(int) (string, error) { return "/run.scope", nil }
	gate := make(chan struct{})
	r.release = sync.OnceFunc(func() { close(gate) })
	t.Cleanup(r.release)
	var first atomic.Bool
	r.l.closeSettled = func(fd int) error {
		if first.CompareAndSwap(false, true) {
			close(r.held)
			<-gate
		}
		return unix.Close(fd)
	}
	r.l.marks["/m"] = unix.FAN_OPEN_PERM
	r.l.unmarkMounts = func() error { r.unmarked.Add(1); return nil }
	if err := unix.SetsockoptTimeval(r.kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}
	return r
}

func (r *closerRig) start(ctx context.Context) {
	go func() { r.loopErr <- r.l.loop(ctx) }()
}

// file creates a file in the rig's directory and returns a descriptor on it, standing in for the one fanotify
// hands over; the listener closes it.
func (r *closerRig) file(t *testing.T, name string) int32 {
	t.Helper()
	p := filepath.Join(r.dir, name)
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	return int32(fd)
}

// ask writes one open event for fd and returns the response the loop gave it.
func (r *closerRig) ask(t *testing.T, fd int32) uint32 {
	t.Helper()
	if _, err := unix.Write(r.kernelSide, metadata(unix.FAN_OPEN_PERM, fd, 777, fanMetadataVersion, 0)); err != nil {
		t.Fatalf("write synthetic event: %v", err)
	}
	var resp [8]byte
	if n, err := readRetrying(r.kernelSide, resp[:]); err != nil || n != 8 {
		t.Fatalf("no response to descriptor %d (%d bytes, %v)", fd, n, err)
	}
	if got := int32(binary.NativeEndian.Uint32(resp[0:4])); got != fd {
		t.Fatalf("response names descriptor %d, want %d", got, fd)
	}
	return binary.NativeEndian.Uint32(resp[4:8])
}

// TestFatalLoopReturnsWhileACloseIsHeld: a listener that meets a fatal error returns it at once, whatever the
// closer is waiting on. RunListener's caller cancels the run and kills its cgroup only once loop returns (§6
// E15), and the marks come down first, so a loop that waited for its closer, held in one close by a filesystem
// that stopped answering, left the run going with nothing asking about its opens and no line saying so. Here
// the overdue ceiling is passed while the first answered descriptor's close is held: loop must return
// ErrListenerDied, and the group and the held descriptor are closed once the close is let go.
func TestFatalLoopReturnsWhileACloseIsHeld(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	r.l.overdueCeiling = 1
	r.start(context.Background())
	if resp := r.ask(t, r.file(t, "first")); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x to an open the path allows", resp)
	}
	select {
	case <-r.held:
	case <-time.After(5 * time.Second):
		t.Fatal("the answered descriptor never reached the closer")
	}
	r.l.overdue.Store(5)
	select {
	case err := <-r.loopErr:
		if !errors.Is(err, ErrListenerDied) {
			t.Fatalf("loop() = %v, want ErrListenerDied", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatalf("loop() has not returned 3 s after it passed the overdue ceiling, with one close held (marks "+
			"removed %d time(s)): the run is never told its listener died, and runs unmarked", r.unmarked.Load())
	}
	if r.unmarked.Load() == 0 {
		t.Fatal("loop() returned with its mark still in place")
	}
	r.release()
	deadline := time.Now().Add(5 * time.Second)
	for !r.l.closed.Load() || r.l.closer.backlog() != 0 {
		if time.Now().After(deadline) {
			t.Fatalf("after the held close was let go: group closed %v, %d descriptors still to close",
				r.l.closed.Load(), r.l.closer.backlog())
		}
		time.Sleep(time.Millisecond)
	}
}

// TestCancelledLoopReturnsWhileACloseIsHeld: a cancelled listener waits for its closer only so long. Its run
// is already ending, and it joins its workers and closes its group before it returns, but a close held by a
// filesystem that never answers held its return with it, and with that the run's errgroup, run_end, Detach and
// the build lock, for as long as the filesystem did not answer (§6 E35). Here the first answered descriptor's
// close is held and the wait is bounded at 50 ms: loop must return nil with its group closed, leave the held
// close to the closer, and the closer must end once the close is let go.
func TestCancelledLoopReturnsWhileACloseIsHeld(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	r.l.closerJoin = 50 * time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	r.start(ctx)
	if resp := r.ask(t, r.file(t, "first")); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x to an open the path allows", resp)
	}
	select {
	case <-r.held:
	case <-time.After(5 * time.Second):
		t.Fatal("the answered descriptor never reached the closer")
	}
	cancel()
	select {
	case err := <-r.loopErr:
		if err != nil {
			t.Fatalf("loop() after cancellation = %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("a cancelled loop() has not returned 3 s after its cancellation, its closer bounded at 50 ms and " +
			"one close held: the run's end waits on a filesystem that never answers")
	}
	if !r.l.closed.Load() {
		t.Fatal("a cancelled loop() returned with its group still open")
	}
	if n := r.l.closer.backlog(); n != 1 {
		t.Fatalf("%d descriptors still to close when the cancelled loop returned, want the held one", n)
	}
	r.release()
	select {
	case <-r.l.closer.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the closer left behind never ended after its held close was let go")
	}
	if n := r.l.closer.backlog(); n != 0 {
		t.Fatalf("%d descriptors never closed", n)
	}
}

// TestNoRefusalIsRecordedForADenyNeverWritten: a refusal reaches the ledger only once its FAN_DENY was
// written. On a fatal path loop returns before its workers finish (§6 E35), and Detach can close the group
// before a worker answers; that answer is then not written (groupMu), and the close lets the open through.
// A refused event for it recorded a refusal that never happened. Here the group is closed before handle
// answers a refusal, plain and with its membership unread: there must be no refused event and no
// membership gap, and the failed response must be the gap that says what happened.
func TestNoRefusalIsRecordedForADenyNeverWritten(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"refused", nil},
		{"membership unread", fmt.Errorf("%w: %w", errMembershipUnread, unix.EMFILE)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := &sink{}
			refusal := verdict{rule: "secret", reason: record.ReasonReadDenied}
			l, _ := socketpairListener(t, s, func(fanEvent) (verdict, error) { return refusal, tc.err })
			if err := l.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: openFD(t), PID: 4242})
			for _, e := range s.all() {
				if e.Verdict == record.VerdictRefused {
					t.Fatalf("a refused event for an open whose FAN_DENY was never written: %+v", s.all())
				}
			}
			if hasGap(s.all(), GapFanotifyMembership) {
				t.Fatalf("a %s gap says the refusal stood, and it was never written: %+v", GapFanotifyMembership, s.all())
			}
			if !hasGap(s.all(), GapFanotifyResponse) {
				t.Fatalf("no %s gap for the refusal the closed group never got: %+v", GapFanotifyResponse, s.all())
			}
		})
	}
}

// TestLoopGivesUpAtTheCloseBacklogCap: the closer's backlog is capped, and the listener ends at the cap with a
// line saying why. Uncapped, every open answered behind one held close kept its descriptor, until the process
// reached its descriptor limit: there a refusal's membership read failed with EMFILE and was answered allow (§6
// E35), and the group's own read failed with it. Here the cap is 4 and the first close is held: the loop must
// answer the opens it read, wait one decision deadline (100 ms here) for the closer to catch up (catchUp), then
// return ErrListenerDied with GapFanotifyCloseBacklog, and never read on.
func TestLoopGivesUpAtTheCloseBacklogCap(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	r.l.closeBacklogCap = 4
	r.l.deadline = 100 * time.Millisecond
	r.start(context.Background())
	for i := range 4 {
		if resp := r.ask(t, r.file(t, fmt.Sprintf("plain-%d", i))); resp != unix.FAN_ALLOW {
			t.Fatalf("open %d: response %#x to an open the path allows", i, resp)
		}
		if i == 0 {
			<-r.held
		}
	}
	select {
	case err := <-r.loopErr:
		if !errors.Is(err, ErrListenerDied) {
			t.Fatalf("loop() = %v, want ErrListenerDied", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loop() has not returned with its descriptors waiting on one held close and a cap of 4: the " +
			"backlog grows until the process runs out of descriptors")
	}
	if !hasGap(r.events.all(), GapFanotifyCloseBacklog) {
		t.Fatalf("no %s gap: the ledger would show the run killed for no stated reason: %+v",
			GapFanotifyCloseBacklog, r.events.all())
	}
	if r.unmarked.Load() == 0 {
		t.Fatal("loop() returned with its mark still in place")
	}
}

// TestLoopWaitsAtTheCapForItsCloser: a backlog at the cap is not by itself a held close. The loop answers the
// allowed opens on its own goroutine and blocks nowhere while they keep coming, so where every processor is busy
// the closer it wakes is not run, and the backlog reached the cap in about a thousand opens with nothing held:
// as root with GOMAXPROCS 2, the allowed opens of BenchmarkFanotifyRoundTrip ended the listener every time (§6
// E35). At the cap the loop must stop reading and wait for the closer (catchUp), which gives it a processor, and
// read on once it has caught up. Here the cap is 4 and the first close is held, standing in for a closer that has
// not run, until the loop is waiting; then the close is let go, and the next open must be answered with no gap
// and the loop still running. It fails with the loop giving the group up at the cap at once, as it did.
func TestLoopWaitsAtTheCapForItsCloser(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	r.l.closeBacklogCap = 4
	r.l.deadline = time.Minute // the wait's bound is TestLoopGivesUpAtTheCloseBacklogCap's; here it must not pass
	ctx, cancel := context.WithCancel(context.Background())
	r.start(ctx)
	for i := range 4 {
		if resp := r.ask(t, r.file(t, fmt.Sprintf("plain-%d", i))); resp != unix.FAN_ALLOW {
			t.Fatalf("open %d: response %#x to an open the path allows", i, resp)
		}
		if i == 0 {
			<-r.held
		}
	}
	// The closer was started before the first close was held, so reading it here is ordered after loop() set it.
	deadline := time.Now().Add(5 * time.Second)
	for r.l.closer.target.Load() < 0 {
		select {
		case err := <-r.loopErr:
			t.Fatalf("loop() = %v at its cap, before its closer had caught up or its deadline passed: a closer "+
				"that has not run is taken for a held close", err)
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("loop() is not waiting for its closer 5 s after reaching its cap (backlog %d)", r.l.closer.backlog())
		}
		time.Sleep(time.Millisecond)
	}
	r.release()
	if resp := r.ask(t, r.file(t, "plain-after")); resp != unix.FAN_ALLOW {
		t.Fatalf("response %#x to the open after the closer caught up", resp)
	}
	select {
	case err := <-r.loopErr:
		t.Fatalf("loop() = %v after its closer caught up", err)
	default:
	}
	if hasGap(r.events.all(), GapFanotifyCloseBacklog) {
		t.Fatalf("a %s gap for a closer that caught up: %+v", GapFanotifyCloseBacklog, r.events.all())
	}
	cancel()
	if err := <-r.loopErr; err != nil {
		t.Fatalf("loop() after cancellation = %v", err)
	}
}

// TestWorkersCloseThroughTheCloser: a descriptor a worker answered is closed by the closer too, not by the
// worker. A worker that closed its own was held in that close like the read loop was (§6 E35), one fewer
// deciding for each, and once the pool was held the loop's hand-off blocked and every opener on the marked
// mounts waited; and the closer's cap counted none of them. The refused open here goes to a worker; its
// descriptor must reach closeSettled, and a second refused open must still be answered while that close is held.
func TestWorkersCloseThroughTheCloser(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	ctx, cancel := context.WithCancel(context.Background())
	r.start(ctx)
	if resp := r.ask(t, r.file(t, "secret/one")); resp != unix.FAN_DENY {
		t.Fatalf("response %#x to the run's open under a deny_read entry, want FAN_DENY", resp)
	}
	select {
	case <-r.held:
	case <-time.After(3 * time.Second):
		t.Fatal("the descriptor a worker answered never reached the closer: the worker closed it itself")
	}
	if resp := r.ask(t, r.file(t, "secret/two")); resp != unix.FAN_DENY {
		t.Fatalf("response %#x to the second refused open, want FAN_DENY", resp)
	}
	r.release()
	cancel()
	if err := <-r.loopErr; err != nil {
		t.Fatalf("loop() after cancellation = %v", err)
	}
	if n := r.l.closer.backlog(); n != 0 {
		t.Fatalf("%d descriptors still to close after a cancelled loop returned", n)
	}
}

// TestNoResponseIsWrittenToAClosedGroup: once the group is closed, a late answer writes nothing. On a fatal
// path loop returns before its workers finish, and Detach can close the group while one is still answering;
// the closed number can then name any file this process opens next, and the eight response bytes went into it.
// Here the number is given to a pipe right after the close, and the pipe must stay empty. dup3 onto that number
// would take it from whatever another test opened there meanwhile, so this one cannot run in parallel.
func TestNoResponseIsWrittenToAClosedGroup(t *testing.T) {
	l, _ := socketpairListener(t, &sink{}, func(fanEvent) (verdict, error) { return allowed, nil })
	number := l.fd
	// The pipe is made while the group still holds its number, so neither end can be given that number.
	var p [2]int
	if err := unix.Pipe2(p[:], unix.O_CLOEXEC|unix.O_NONBLOCK); err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer unix.Close(p[0])
	defer unix.Close(p[1])
	if err := l.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := unix.Dup3(p[1], number, unix.O_CLOEXEC); err != nil {
		t.Fatalf("dup3 onto the group's old number %d: %v", number, err)
	}
	defer unix.Close(number)
	l.respond(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: 42, PID: 7}, allowed)
	var buf [8]byte
	if n, err := unix.Read(p[0], buf[:]); err == nil || n > 0 {
		t.Fatalf("a response after Close wrote %d bytes into the file that took the group's number", n)
	}
}

// TestCloseBacklogFor pins the cap: fdCloserCap, or a quarter of the soft descriptor limit where that is less.
func TestCloseBacklogFor(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		soft uint64
		want int
	}{{1 << 20, fdCloserCap}, {4096, fdCloserCap}, {1024, 256}, {512, 128}, {3, 0}} {
		if got := closeBacklogFor(tc.soft); got != tc.want {
			t.Errorf("closeBacklogFor(%d) = %d, want %d", tc.soft, got, tc.want)
		}
	}
	if c := newFDCloser(nil, closeBacklogFor(3)); c.limit != 1 {
		t.Errorf("a closer under a tiny limit gives up at %d, want 1", c.limit)
	}
}

// TestDecideEventKeepsTheRefusalWhenMembershipIsUnread: an opener whose cgroup cannot be read is not known to
// be outside the run, so the path's refusal stands and a gap says why. Allowing it gave the run's own refusal
// away whenever a membership read failed, and the read fails first for a process out of descriptors (EMFILE,
// §6 E35). An opener that has exited is still allowed: there is nothing left to refuse (enforce-cgroup-observe.md §6 E10).
func TestDecideEventKeepsTheRefusalWhenMembershipIsUnread(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s := &sink{}
	l, pipe := testListener(t, s, nil, time.Second)
	l.run.CgroupPath = "/run.scope"
	l.policy = newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, secret, "", "secret")}, nil), "/run.scope")
	l.decide = l.decideEvent
	readErr := fmt.Errorf("cgroup: read /proc/4242/cgroup: %w", unix.EMFILE)
	l.cgroupOfPID = func(int) (string, error) { return "", readErr }

	v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, secret), PID: 4242})
	if v.allow || v.reason != record.ReasonReadDenied || !errors.Is(err, errMembershipUnread) || !errors.Is(err, unix.EMFILE) {
		t.Fatalf("decideEvent with the membership read failing = %+v, %v; want the path's refusal and "+
			"errMembershipUnread wrapping EMFILE", v, err)
	}

	fd, ferr := unix.Open(secret, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if ferr != nil {
		t.Fatal(ferr)
	}
	l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(fd), PID: 4242})
	if _, resp := readResponse(t, pipe); resp != unix.FAN_DENY {
		t.Fatalf("response %#x, want FAN_DENY: the refusal was given away because membership went unread", resp)
	}
	var refusals int
	for _, e := range s.all() {
		if e.Kind == record.KindFS && e.Verdict == record.VerdictRefused {
			refusals++
		}
	}
	if refusals != 1 || !hasGap(s.all(), GapFanotifyMembership) {
		t.Fatalf("events = %+v, want one refusal and a %s gap", s.all(), GapFanotifyMembership)
	}

	l.cgroupOfPID = func(int) (string, error) { return "", fmt.Errorf("%w: pid 4242", ErrProcGone) }
	if v, err := l.decideEvent(fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, secret), PID: 4242}); !v.allow || err != nil {
		t.Fatalf("decideEvent for an opener that has exited = %+v, %v; want an allow", v, err)
	}
}

// TestDecideEventKeepsTheRefusalAtTheDescriptorLimit is the case above with the kernel's own EMFILE: the run
// is this test's own cgroup, the policy refuses the file, and the descriptor table is full when the decision
// is made, so the pidfd and /proc/<pid>/cgroup both fail. That was an allow with only a gap. It fills this
// process's descriptor table, so it cannot run in parallel.
func TestDecideEventKeepsTheRefusalAtTheDescriptorLimit(t *testing.T) {
	raw, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		t.Skipf("no /proc/self/cgroup: %v", err)
	}
	own, err := parseCgroupFile(raw)
	if err != nil {
		t.Skipf("no unified cgroup line: %v", err)
	}
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	if err := os.WriteFile(secret, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	run := Run{ID: "run-1", Agent: "a", CgroupPath: own}
	l := &fanotifyListener{
		run: run, policy: newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, secret, "", "secret")}, nil), own),
		now: time.Now, deadline: time.Second, marks: map[string]uint64{}, cgroupOfPID: cgroupPathOfPID,
		members: newRunMembers(run),
	}
	t.Cleanup(l.members.close)
	ev := fanEvent{Mask: unix.FAN_OPEN_PERM, FD: openForEvent(t, secret), PID: int32(os.Getpid())}
	if v, err := l.decideEvent(ev); v.allow || err != nil {
		t.Fatalf("precondition: the run's own open of the refused file = %+v, %v; want a refusal", v, err)
	}

	var saved unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	lowered := saved
	lowered.Cur = uint64(len(entries) + 64)
	if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &lowered); err != nil {
		t.Skipf("cannot lower RLIMIT_NOFILE: %v", err)
	}
	var dups []int
	defer func() {
		for _, fd := range dups {
			_ = unix.Close(fd)
		}
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &saved); err != nil {
			t.Errorf("restore RLIMIT_NOFILE: %v", err)
		}
	}()
	// A descriptor closed on another goroutine (an earlier test's file reaching its finalizer) frees a slot between
	// the fill and the decision, and the read then succeeds: the run's refusal with no error, right, but not this
	// case. So the table is filled again and the decision repeated, a few times. Each of them must refuse.
	for range 20 {
		for {
			fd, err := unix.Dup(int(ev.FD))
			if errors.Is(err, unix.EMFILE) {
				break
			}
			if err != nil {
				t.Fatalf("dup: %v", err)
			}
			dups = append(dups, fd)
		}
		v, err := l.decideEvent(ev)
		if v.allow {
			t.Fatalf("decideEvent with this process out of descriptors = %+v, %v: the run's refusal was answered allow",
				v, err)
		}
		if errors.Is(err, errMembershipUnread) {
			return
		}
		if err != nil {
			t.Fatalf("decideEvent = %+v, %v; want errMembershipUnread", v, err)
		}
	}
	t.Fatal("decideEvent read the opener's cgroup on every try with the descriptor table full")
}

// TestLoopRemovesItsMarksWithoutNamingAPath: a listener's marks come down by one fanotify_mark call that names
// no path, FAN_MARK_FLUSH of the mount marks, on every way out of loop. FAN_MARK_REMOVE names each mount's root,
// and the kernel walks that path and checks read permission on it before it removes anything
// (fanotify_find_path): on an NFS mount whose server stopped answering, which is how a close comes to be held
// and the close backlog to fill (§6 E35), or a FUSE mount with default_permissions whose daemon did, that check
// is a GETATTR that waits as long as the server does. A failed loop then never returned, and its run was never
// killed; a cancelled one held run_end. Here every call that names a path for removal is held, as that GETATTR
// would be: loop must return within 3 s either way, having flushed the mount marks once, and only those, with
// no such call. It swaps fanotifyInit and fanotifyMark, so it cannot run in parallel.
func TestLoopRemovesItsMarksWithoutNamingAPath(t *testing.T) {
	for _, fatal := range []bool{true, false} {
		name := "cancelled"
		if fatal {
			name = "fatal"
		}
		t.Run(name, func(t *testing.T) {
			fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatalf("socketpair: %v", err)
			}
			t.Cleanup(func() { _ = unix.Close(fds[0]) })
			savedInit, savedMark := fanotifyInit, fanotifyMark
			t.Cleanup(func() { fanotifyInit, fanotifyMark = savedInit, savedMark })
			handed := false
			fanotifyInit = func(uint, uint) (int, error) {
				handed = true
				return fds[1], nil
			}
			defer func() {
				if !handed {
					_ = unix.Close(fds[1])
				}
			}()
			server := make(chan struct{})
			t.Cleanup(sync.OnceFunc(func() { close(server) }))
			var flushes, walks atomic.Int32
			var flushFlags atomic.Uint64
			// The kernel takes a flush before any path lookup, and a removal only after one.
			fanotifyMark = func(_ int, flags uint, _ uint64, _ int, _ string) error {
				switch {
				case flags&unix.FAN_MARK_FLUSH != 0:
					flushFlags.Store(uint64(flags))
					flushes.Add(1)
				case flags&unix.FAN_MARK_REMOVE != 0:
					walks.Add(1)
					<-server // the marked filesystem's server stopped answering
				}
				return nil
			}
			p := newPolicy(policyTable([]agent.FSRule{fsRule(agent.FSDenyRead, "/m/secret", "", "secret")}, nil), "/run.scope")
			l, err := newFanotifyListener(p, Run{ID: "run-1", Agent: "a", CgroupID: 99}, &sink{}, time.Second)
			if errors.Is(err, errThreadBudget) {
				t.Skipf("this host's thread budget refuses a listener before fanotify_init: %v", err)
			}
			if err != nil {
				t.Fatalf("newFanotifyListener: %v", err)
			}
			if err := l.markFor("/m", unix.FAN_OPEN_PERM); err != nil {
				t.Fatalf("mark: %v", err)
			}
			if fatal {
				l.overdueCeiling = 1
				l.overdue.Store(5)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			loopErr := make(chan error, 1)
			go func() { loopErr <- l.loop(ctx) }()
			if !fatal {
				cancel()
			}
			select {
			case err := <-loopErr:
				if fatal && !errors.Is(err, ErrListenerDied) {
					t.Fatalf("loop() = %v, want ErrListenerDied", err)
				}
				if !fatal && err != nil {
					t.Fatalf("loop() after cancellation = %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatalf("loop() has not returned 3 s after it began to stop, with %d call(s) naming a marked path "+
					"waiting on that filesystem: its run is never killed, or never ends", walks.Load())
			}
			if n := walks.Load(); n != 0 {
				t.Fatalf("removing the marks named a path %d time(s), and so waited on the marked filesystem", n)
			}
			if n := flushes.Load(); n != 1 {
				t.Fatalf("the mount marks were flushed %d time(s), want once", n)
			}
			if got, want := flushFlags.Load(), uint64(unix.FAN_MARK_FLUSH|unix.FAN_MARK_MOUNT); got != want {
				t.Fatalf("flush flags %#x, want %#x: without FAN_MARK_MOUNT the flush takes the stage's inode "+
					"ignore mark too", got, want)
			}
			if m := l.marked(); len(m) != 0 {
				t.Fatalf("marks %v remain after loop returned", m)
			}
		})
	}
}

// holdDecisions has the rig's workers take n refused opens of the run's and hold each in its membership read,
// with a deadline long enough that none is answered at it while the test runs, and returns what lets them go.
func (r *closerRig) holdDecisions(t *testing.T, n int) (release func()) {
	t.Helper()
	r.l.deadline = time.Minute
	gate := make(chan struct{})
	release = sync.OnceFunc(func() { close(gate) })
	t.Cleanup(release)
	var asked atomic.Int32
	r.l.cgroupOfPID = func(int) (string, error) {
		asked.Add(1)
		<-gate
		return "/run.scope", nil
	}
	for i := range n {
		fd := r.file(t, fmt.Sprintf("secret/held-%d", i))
		if _, err := unix.Write(r.kernelSide, metadata(unix.FAN_OPEN_PERM, fd, 777, fanMetadataVersion, 0)); err != nil {
			t.Fatalf("write synthetic event: %v", err)
		}
	}
	deadline := time.Now().Add(5 * time.Second)
	for asked.Load() < int32(n) {
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d refused opens reached a worker", asked.Load(), n)
		}
		time.Sleep(time.Millisecond)
	}
	return release
}

// gapCount is the count of the first gap with the given reason, and whether there is one.
func gapCount(events []*record.Event, why string) (int, bool) {
	for _, e := range events {
		var p record.GapPayload
		if e.Kind != record.KindGap || e.DecodePayload(&p) != nil || !strings.HasPrefix(p.Why, why) {
			continue
		}
		return p.Count, true
	}
	return 0, false
}

// TestFailedLoopCountsWhatItsWorkersHold: a loop that fails returns before its workers, and a line one of them
// records after that can reach the run's queue after internal/runtime's final drain, which is never written (§6
// E35). The loop counts those events before it returns, so the ledger says how many lines it can be missing
// rather than nothing. Here two refused opens are held in their membership reads when the overdue ceiling is
// passed: when loop returns, the fanotify-listener-abandoned gap must already be there with a count of 2, and
// no refusal yet; the refusals are still answered FAN_DENY once the reads return.
func TestFailedLoopCountsWhatItsWorkersHold(t *testing.T) {
	t.Parallel()
	r := newCloserRig(t)
	r.l.overdueCeiling = 1
	r.start(context.Background())
	release := r.holdDecisions(t, 2)
	r.l.overdue.Store(5)
	select {
	case err := <-r.loopErr:
		if !errors.Is(err, ErrListenerDied) {
			t.Fatalf("loop() = %v, want ErrListenerDied", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loop() has not returned 3 s after it passed the overdue ceiling, with two decisions held")
	}
	got, ok := gapCount(r.events.all(), GapFanotifyAbandoned)
	if !ok || got != 2 {
		t.Fatalf("when loop returned: %s gap %v with count %d, want one counting the 2 events its workers held: "+
			"%+v", GapFanotifyAbandoned, ok, got, r.events.all())
	}
	for _, e := range r.events.all() {
		if e.Verdict == record.VerdictRefused {
			t.Fatalf("a refusal was recorded while its decision was still held: %+v", e)
		}
	}
	release()
	for range 2 {
		var resp [8]byte
		if n, err := readRetrying(r.kernelSide, resp[:]); err != nil || n != 8 {
			t.Fatalf("a held refusal was never answered (%d bytes, %v)", n, err)
		}
		if got := binary.NativeEndian.Uint32(resp[4:8]); got != unix.FAN_DENY {
			t.Fatalf("a held refusal was answered %#x, want FAN_DENY", got)
		}
	}
}

// TestWaitListenerWaitsForAFailedListenersWorkers: WaitListener is what lets internal/runtime write the lines a
// failed listener's workers record, by waiting for them before its final drain (§6 E35). It must not return
// while a worker still holds an event, and once it returns every line those workers record must already have
// been handed on. A handle with no listener, or whose listener never ran, has nothing to wait for.
func TestWaitListenerWaitsForAFailedListenersWorkers(t *testing.T) {
	t.Parallel()
	if err := (&Handle{}).WaitListener(context.Background()); err != nil {
		t.Fatalf("WaitListener with no listener = %v", err)
	}
	r := newCloserRig(t)
	h := &Handle{fan: r.l}
	if err := h.WaitListener(context.Background()); err != nil {
		t.Fatalf("WaitListener before the listener ran = %v", err)
	}
	r.l.overdueCeiling = 1
	r.start(context.Background())
	release := r.holdDecisions(t, 1)
	r.l.overdue.Store(5)
	select {
	case err := <-r.loopErr:
		if !errors.Is(err, ErrListenerDied) {
			t.Fatalf("loop() = %v, want ErrListenerDied", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("loop() has not returned 3 s after it passed the overdue ceiling")
	}
	short, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if err := h.WaitListener(short); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("WaitListener with a worker still deciding = %v, want the context's deadline", err)
	}
	release()
	long, cancelLong := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelLong()
	if err := h.WaitListener(long); err != nil {
		t.Fatalf("WaitListener once the worker's decision returned = %v", err)
	}
	var refused int
	for _, e := range r.events.all() {
		if e.Verdict == record.VerdictRefused {
			refused++
		}
	}
	if refused != 1 {
		t.Fatalf("WaitListener returned with %d refusal(s) recorded, want the held one: %+v", refused, r.events.all())
	}
}
