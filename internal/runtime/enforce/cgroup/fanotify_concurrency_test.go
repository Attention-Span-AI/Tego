// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHandleRespondsBeforeClosingTheEventDescriptor pins the order the fanotify response protocol depends on,
// on both of handle's branches: the decision that returns in time and the one answered at E16's deadline.
//
// A response is matched to its pending event by the descriptor *number*: the kernel keeps the event on the
// group's access list and looks the number up when the response is written, and it hands the lowest free
// number to the next event it delivers. fanotify(7)'s own example therefore writes the response first
// (`response.fd = metadata->fd; write(fd, &response, ...)`) and closes `metadata->fd` only afterwards.
// Closing first frees the number while the response naming it is still unwritten, so with more than one
// decision in flight — which the worker pool in loop() makes ordinary — a response can be delivered to
// whichever pending event inherited the number, answering the wrong process's open. The deadline branch
// closes the descriptor there and then rather than leaving it to the stalled decision (§6 E34), so it is
// held to the same order.
//
// The test makes the window observable rather than racing it: the pipe standing in for the group is filled
// first, so the eight-byte response blocks in write(2). respond() bumps `answered` as its first statement and
// then blocks, so `answered == 1` is exactly the instant between the decision and the response reaching the
// kernel, and at that instant the event descriptor must still be open.
func TestHandleRespondsBeforeClosingTheEventDescriptor(t *testing.T) {
	cases := []struct {
		name     string
		deadline time.Duration
		// stall says whether the decision waits for the test instead of returning at once.
		stall bool
	}{
		// A deadline far beyond the test keeps this one on handle's in-time branch.
		{name: "decided in time", deadline: time.Minute},
		// A decision that never returns while the test runs, and a deadline that fires almost at once.
		{name: "answered at the deadline", deadline: time.Millisecond, stall: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatalf("pipe: %v", err)
			}
			t.Cleanup(func() { _ = r.Close(); _ = w.Close() })

			// The listener owns and closes its own descriptor, exactly as it owns a real group's.
			group, err := unix.Dup(int(w.Fd()))
			if err != nil {
				t.Fatalf("dup: %v", err)
			}
			fillPipe(t, group)

			l := &fanotifyListener{
				fd: group, run: Run{ID: "run-1", Agent: "a", CgroupID: 99}, out: &sink{},
				deadline: tc.deadline, now: time.Now, marks: map[string]uint64{},
				markMount: func(string, uint64) error { return nil }, unmarkMounts: func() error { return nil },
			}
			release := make(chan struct{})
			t.Cleanup(func() { close(release) })
			l.decide = func(fanEvent) (verdict, error) {
				if tc.stall {
					<-release
				}
				return allowed, nil
			}
			t.Cleanup(func() { _ = l.Close() })

			// A uniquely named file, so a descriptor number handed straight back to something else in this
			// process is still detected: the check is what /proc/self/fd/<n> points at, not merely that it
			// points somewhere.
			target := filepath.Join(t.TempDir(), "event-target")
			if err := os.WriteFile(target, nil, 0o600); err != nil {
				t.Fatalf("write %s: %v", target, err)
			}
			fd, err := unix.Open(target, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatalf("open %s: %v", target, err)
			}
			if !fdPointsAt(int32(fd), target) {
				t.Fatalf("precondition: descriptor %d does not point at %s", fd, target)
			}

			answered := make(chan struct{})
			go func() {
				defer close(answered)
				l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: int32(fd), PID: 4242})
			}()

			deadline := time.Now().Add(5 * time.Second)
			for l.answered.Load() == 0 {
				if time.Now().After(deadline) {
					t.Fatal("handle() never reached respond(); the response was never attempted")
				}
				time.Sleep(time.Millisecond)
			}

			if !fdPointsAt(int32(fd), target) {
				t.Fatalf("the event descriptor %d was closed before its response was written; the kernel may "+
					"already have reissued that number to another pending event (fanotify(7))", fd)
			}

			// Drain so the blocked write completes and handle() can finish.
			go func() { _, _ = io.Copy(io.Discard, r) }()
			select {
			case <-answered:
			case <-time.After(5 * time.Second):
				t.Fatal("handle() did not return once its response could be written")
			}
			if _, _, timeouts, _ := l.stats(); (timeouts == 1) != tc.stall {
				t.Fatalf("timeouts = %d: the case did not take the branch it names", timeouts)
			}
		})
	}
}

// fdPointsAt reports whether descriptor fd of this process is open on path. A closed descriptor, or a number
// already reissued to another file, both read as false.
func fdPointsAt(fd int32, path string) bool {
	got, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(int(fd)))
	return err == nil && got == path
}

// fillPipe writes until the pipe has no free byte left, so the next write blocks. The 4096-byte chunks fill
// it quickly; the single bytes that follow close the remainder a chunk cannot, since an eight-byte response
// would otherwise still fit in the gap and never block.
func fillPipe(t *testing.T, fd int) {
	t.Helper()
	if err := unix.SetNonblock(fd, true); err != nil {
		t.Fatalf("set O_NONBLOCK: %v", err)
	}
	for _, size := range []int{4096, 1} {
		junk := make([]byte, size)
		for {
			if _, err := unix.Write(fd, junk); err != nil {
				if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK) {
					break
				}
				t.Fatalf("fill the pipe: %v", err)
			}
		}
	}
	if err := unix.SetNonblock(fd, false); err != nil {
		t.Fatalf("clear O_NONBLOCK: %v", err)
	}
}

// TestListenerLoopAnswersPastASlowDecision is §6 E35: one slow decision must not hold up the next opener.
//
// A mount mark puts every open on the filesystem through this one listener, and the kernel blocks each
// opener in fanotify_get_response until a response arrives — TASK_KILLABLE, with nothing timing it out on
// the kernel side. When the read loop also answered, handle()'s per-event deadline bounded a single decision
// and nothing bounded the queue behind it: the opener at position N waited N deadlines. One process stuck in
// D state (an unreachable NFS mount, a frozen container) therefore stopped every open on the machine, which
// is the system lockup ClamAV refuses to let its users configure.
//
// Here the first event's decision never returns until the test releases it, with a deadline far beyond the
// test so the timeout path cannot rescue the result. The second event must still be answered.
func TestListenerLoopAnswersPastASlowDecision(t *testing.T) {
	release := make(chan struct{})
	l, kernelSide := socketpairListener(t, &sink{}, func(ev fanEvent) (verdict, error) {
		if ev.PID == 1 {
			<-release
		}
		return allowed, nil
	})
	l.deadline = time.Minute
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})

	if err := unix.SetsockoptTimeval(kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatalf("SO_RCVTIMEO: %v", err)
	}

	slowFD, fastFD := openFD(t), openFD(t)
	for _, ev := range [][]byte{
		metadata(unix.FAN_OPEN_PERM, slowFD, 1, fanMetadataVersion, 0),
		metadata(unix.FAN_OPEN_PERM, fastFD, 2, fanMetadataVersion, 0),
	} {
		if _, err := unix.Write(kernelSide, ev); err != nil {
			t.Fatalf("write synthetic event: %v", err)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	loopErr := make(chan error, 1)
	go func() { loopErr <- l.loop(ctx) }()

	var resp [8]byte
	n, err := readRetrying(kernelSide, resp[:])
	if err != nil {
		t.Fatalf("no opener was answered while one decision was in flight: %v; a listener that answers from "+
			"its own read loop blocks every other open on the marked mount behind the slowest decision", err)
	}
	if n != 8 {
		t.Fatalf("response is %d bytes, want 8", n)
	}
	if got := int32(binary.NativeEndian.Uint32(resp[0:4])); got != fastFD {
		t.Fatalf("the first response was for descriptor %d, want %d: the second opener must not wait behind "+
			"the first one's decision", got, fastFD)
	}

	close(release)
	if _, err := readRetrying(kernelSide, resp[:]); err != nil {
		t.Fatalf("the slow decision was never answered once it completed: %v", err)
	}
	if got := int32(binary.NativeEndian.Uint32(resp[0:4])); got != slowFD {
		t.Fatalf("the second response was for descriptor %d, want %d", got, slowFD)
	}

	cancel()
	select {
	case err := <-loopErr:
		if err != nil {
			t.Fatalf("loop() after cancellation = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("loop() did not return after its context was cancelled")
	}
}

// TestListenerLoopQueuesOpensBehindExecsStalledOnMembership is §6 E34's stalled procfs read inside E35's pool.
//
// An execve of a binary the contract did not name reaches the /proc/<pid>/cgroup read whichever process ran
// it (TestDecideEventExecReadsProcUnlessTheBinaryIsNamed). Kernels before 6.8 serve that file under the global
// cgroup_mutex (proc_cgroup_show), so one held mutex stalls every such read at the same moment, not one of
// them; the lookup here models that with one gate every call waits on. E34 and E35 promise this much and no
// more. Below fanotifyWorkers stalled execs an open the policy allows is answered at once. At fanotifyWorkers
// it waits for a worker, which E16's deadline frees by allowing a stalled exec with a gap, so the open is
// answered without any stalled read returning but never ahead of that deadline. Those two bounds are the pool's,
// pinned with every event sent to it. The read loop answers an open its path allows itself (settleByPath), so
// in production such an open waits for no worker, and only once the pool and its queue are full does the
// loop's own hand-off block, holding the open behind a deadline again. An exec answered at its
// deadline has its event descriptor closed right after the answer, since its stalled read goes through a
// descriptor of its own, and stays counted as overdue until that read returns. And once more decisions are
// overdue than the ceiling allows, loop() gives the group up with ErrListenerDied instead of letting them
// pile up toward the Go runtime's thread limit. A listener that answered the open ahead of the deadline would
// either be deciding past its pool, which E34 and E35 would then have to say, or answering on backpressure
// without a decision, which E35 forbids.
func TestListenerLoopQueuesOpensBehindExecsStalledOnMembership(t *testing.T) {
	t.Parallel()
	const (
		runCgroup  = "/tego.slice/run-1.scope"
		hostCgroup = "/system.slice/cron.service"
	)
	dir := t.TempDir()
	named := filepath.Join(dir, "python3")
	unnamed := filepath.Join(dir, "curl")
	ordinary := filepath.Join(dir, "ordinary.txt")
	for _, p := range []string{named, unnamed, ordinary} {
		if err := os.WriteFile(p, nil, 0o700); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	type rig struct {
		l          *fanotifyListener
		kernelSide int
		events     *sink
		lookups    *atomic.Int64
		release    func()
		loopErr    chan error
		// exited records that the test has taken loop()'s return itself, so the cleanup does not wait for
		// a second one.
		exited bool
	}
	// start runs loop() over the real decideEvent with every membership lookup held on one gate; a ceiling
	// of 0 leaves fanotifyOverdueCeiling in force. The cleanup opens the gate before cancelling, because
	// loop() drains its workers before it returns and a worker with no deadline to rescue it returns only
	// once its lookup does. settle puts the path verdict on the read loop, as newFanotifyListener does;
	// without it every event goes to the pool, which is what the pool's own bounds are pinned against.
	start := func(t *testing.T, deadline time.Duration, ceiling int64, settle bool) *rig {
		t.Helper()
		r := &rig{events: &sink{}, lookups: new(atomic.Int64), loopErr: make(chan error, 1)}
		r.l, r.kernelSide = socketpairListener(t, r.events, nil)
		gate := make(chan struct{})
		var once sync.Once
		r.release = func() { once.Do(func() { close(gate) }) }
		r.l.run = Run{ID: "run-1", Agent: "a", CgroupPath: runCgroup, CgroupID: 99}
		r.l.policy = &policy{runCgroup: runCgroup, execAllow: newPathSet([]fsEntry{{path: named, rule: "exec[python3]"}})}
		r.l.deadline = deadline
		r.l.overdueCeiling = ceiling
		r.l.cgroupOfPID = func(int) (string, error) {
			r.lookups.Add(1)
			<-gate
			return hostCgroup, nil
		}
		r.l.decide = r.l.decideEvent
		if settle {
			r.l.settle = r.l.settleByPath
		}
		if err := unix.SetsockoptTimeval(r.kernelSide, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 5}); err != nil {
			t.Fatalf("SO_RCVTIMEO: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { r.loopErr <- r.l.loop(ctx) }()
		t.Cleanup(func() {
			r.release()
			cancel()
			if r.exited {
				return
			}
			select {
			case err := <-r.loopErr:
				if err != nil {
					t.Errorf("loop() after cancellation = %v, want nil", err)
				}
			case <-time.After(10 * time.Second):
				t.Error("loop() did not return after its context was cancelled")
			}
		})
		return r
	}
	// send hands loop() one event the way the kernel would, on a descriptor of its own that the listener
	// closes; the test never closes it, so a number the listener frees early is never closed twice.
	send := func(t *testing.T, r *rig, mask uint64, path string, pid int32) int32 {
		t.Helper()
		fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatalf("open %s: %v", path, err)
		}
		if _, err := unix.Write(r.kernelSide, metadata(mask, int32(fd), pid, fanMetadataVersion, 0)); err != nil {
			t.Fatalf("write synthetic event: %v", err)
		}
		return int32(fd)
	}
	next := func(t *testing.T, r *rig) (int32, uint32) {
		t.Helper()
		var resp [8]byte
		if n, err := readRetrying(r.kernelSide, resp[:]); err != nil || n != 8 {
			t.Fatalf("no response (%d bytes, %v)", n, err)
		}
		return int32(binary.NativeEndian.Uint32(resp[0:4])), binary.NativeEndian.Uint32(resp[4:8])
	}

	t.Run("below the pool's width an allowed open is answered at once", func(t *testing.T) {
		// A deadline far beyond the test: nothing but a free worker can answer the open first.
		r := start(t, time.Minute, 0, false)
		execs := map[int32]bool{}
		for i := range fanotifyWorkers - 1 {
			execs[send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, int32(100+i))] = true
		}
		open := send(t, r, unix.FAN_OPEN_PERM, ordinary, 1)

		if fd, resp := next(t, r); fd != open || resp != unix.FAN_ALLOW {
			t.Fatalf("first response = descriptor %d, %#x; want the open's %d, FAN_ALLOW, while %d execs are "+
				"stalled on membership: one worker is still free (§6 E35)", fd, resp, open, fanotifyWorkers-1)
		}
		r.release()
		for range fanotifyWorkers - 1 {
			fd, resp := next(t, r)
			if !execs[fd] || resp != unix.FAN_ALLOW {
				t.Fatalf("response = descriptor %d, %#x; want a host exec's FAN_ALLOW", fd, resp)
			}
			delete(execs, fd)
		}
		if got := r.lookups.Load(); got != fanotifyWorkers-1 {
			t.Fatalf("%d membership lookups, want %d: one per unnamed exec and none for the allowed open (§6 E34)",
				got, fanotifyWorkers-1)
		}
		if _, _, timeouts, _ := r.l.stats(); timeouts != 0 {
			t.Fatalf("timeouts = %d, want 0", timeouts)
		}
	})

	t.Run("at the pool's width the open waits for a deadline to free a worker", func(t *testing.T) {
		const deadline = 200 * time.Millisecond
		r := start(t, deadline, 0, false)
		sent := time.Now()
		execs := map[int32]bool{}
		stalled := make([]int32, 0, fanotifyWorkers)
		for i := range fanotifyWorkers {
			fd := send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, int32(100+i))
			execs[fd] = true
			stalled = append(stalled, fd)
		}
		open := send(t, r, unix.FAN_OPEN_PERM, ordinary, 1)

		// The gate stays shut throughout: every answer below comes from a deadline, none from a lookup.
		execsFirst := 0
		for {
			fd, resp := next(t, r)
			if resp != unix.FAN_ALLOW {
				t.Fatalf("response for descriptor %d = %#x, want FAN_ALLOW (§6 E16)", fd, resp)
			}
			if fd == open {
				break
			}
			if !execs[fd] {
				t.Fatalf("a response named descriptor %d, which no event carried or which was already answered", fd)
			}
			delete(execs, fd)
			execsFirst++
		}
		waited := time.Since(sent)
		if execsFirst == 0 || waited < deadline {
			t.Fatalf("the open was answered after %v with %d stalled execs answered ahead of it; want it behind "+
				"at least one of them and no sooner than the %v deadline: with %d execs stalled every worker is "+
				"held, and only E16's deadline frees one (§6 E34, E35)", waited, execsFirst, deadline, fanotifyWorkers)
		}
		for len(execs) > 0 {
			fd, resp := next(t, r)
			if !execs[fd] || resp != unix.FAN_ALLOW {
				t.Fatalf("response = descriptor %d, %#x; want a stalled exec's FAN_ALLOW", fd, resp)
			}
			delete(execs, fd)
		}
		if _, _, timeouts, _ := r.l.stats(); timeouts != fanotifyWorkers {
			t.Fatalf("timeouts = %d, want %d: each stalled exec is allowed at its deadline (§6 E16)",
				timeouts, fanotifyWorkers)
		}
		if got := r.lookups.Load(); got != fanotifyWorkers {
			t.Fatalf("%d membership lookups, want %d: one per unnamed exec and none for the allowed open", got,
				fanotifyWorkers)
		}
		// handle() emits the gap after it writes the response, so the last response can be read before the
		// last gap exists; wait for the count rather than sample it.
		timeoutGaps := func() int {
			n := 0
			for _, e := range r.events.all() {
				var p record.GapPayload
				if e.Kind == record.KindGap && e.DecodePayload(&p) == nil && strings.HasPrefix(p.Why, GapFanotifyTimeout) {
					n++
				}
			}
			return n
		}
		for until := time.Now().Add(5 * time.Second); timeoutGaps() < fanotifyWorkers && time.Now().Before(until); {
			time.Sleep(time.Millisecond)
		}
		if gaps := timeoutGaps(); gaps != fanotifyWorkers {
			t.Fatalf("%d %s gaps, want %d, one per stalled exec", gaps, GapFanotifyTimeout, fanotifyWorkers)
		}

		// With the gate still shut, every exec's event descriptor goes right after its deadline answer. The
		// stalled read never needed it: decideEvent reads through the event descriptor only before the
		// membership read (its readlink, and for an exec the fstat beside it), the membership read goes
		// through a procfs descriptor of its own, and whatever the
		// decision concludes now is discarded. What the stalled decisions do still hold is counted as
		// overdue until their reads return (§6 E34).
		until := time.Now().Add(5 * time.Second)
		for _, fd := range stalled {
			for fdPointsAt(fd, unnamed) {
				if time.Now().After(until) {
					t.Fatalf("descriptor %d still open after its deadline answer, with its membership read still "+
						"stalled: a decision answered at its deadline must not keep the event descriptor (§6 E34)", fd)
				}
				time.Sleep(time.Millisecond)
			}
		}
		if got := r.l.overdue.Load(); got != fanotifyWorkers {
			t.Fatalf("overdue = %d with every read still stalled, want %d, one per exec answered at its deadline "+
				"(§6 E34)", got, fanotifyWorkers)
		}
		r.release()
		for until := time.Now().Add(5 * time.Second); r.l.overdue.Load() != 0; {
			if time.Now().After(until) {
				t.Fatalf("overdue = %d after every stalled read returned, want 0: a decision that returns must "+
					"leave the count, or a run's scattered timeouts add up to the ceiling and end it (§6 E34)",
					r.l.overdue.Load())
			}
			time.Sleep(time.Millisecond)
		}
	})

	t.Run("with the path verdict on the read loop a held pool does not hold an allowed open", func(t *testing.T) {
		// As production runs it (settleByPath): every worker is held on a membership read, and the open,
		// which its path allows, is still answered at once, by the loop, with no deadline and no worker.
		r := start(t, time.Minute, 0, true)
		execs := map[int32]bool{}
		for i := range fanotifyWorkers {
			execs[send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, int32(100+i))] = true
		}
		open := send(t, r, unix.FAN_OPEN_PERM, ordinary, 1)
		if fd, resp := next(t, r); fd != open || resp != unix.FAN_ALLOW {
			t.Fatalf("first response = descriptor %d, %#x; want the open's %d, FAN_ALLOW, answered by the read "+
				"loop while all %d workers are held", fd, resp, open, fanotifyWorkers)
		}
		r.release()
		for range fanotifyWorkers {
			fd, resp := next(t, r)
			if !execs[fd] || resp != unix.FAN_ALLOW {
				t.Fatalf("response = descriptor %d, %#x; want a host exec's FAN_ALLOW", fd, resp)
			}
			delete(execs, fd)
		}
		if got := r.lookups.Load(); got != fanotifyWorkers {
			t.Fatalf("%d membership lookups, want %d: one per unnamed exec and none for the allowed open",
				got, fanotifyWorkers)
		}
		if _, _, timeouts, _ := r.l.stats(); timeouts != 0 {
			t.Fatalf("timeouts = %d, want 0", timeouts)
		}
	})

	t.Run("with the path verdict on the read loop the open still waits once the hand-off blocks", func(t *testing.T) {
		// E35's bound survives the loop answering: past the pool and its queue the loop blocks handing off the
		// next held exec, reads nothing more, and an allowed open behind it waits for a deadline to free a
		// worker. Answering it anyway would mean reading past a blocked hand-off, and the hand-off must block
		// rather than allow on backpressure (§6 E35).
		const deadline = 200 * time.Millisecond
		r := start(t, deadline, 0, true)
		sent := time.Now()
		execs := map[int32]bool{}
		for i := range 2*fanotifyWorkers + 1 {
			execs[send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, int32(100+i))] = true
		}
		open := send(t, r, unix.FAN_OPEN_PERM, ordinary, 1)
		execsFirst := 0
		for {
			fd, resp := next(t, r)
			if resp != unix.FAN_ALLOW {
				t.Fatalf("response for descriptor %d = %#x, want FAN_ALLOW (§6 E16)", fd, resp)
			}
			if fd == open {
				break
			}
			if !execs[fd] {
				t.Fatalf("a response named descriptor %d, which no event carried or which was already answered", fd)
			}
			delete(execs, fd)
			execsFirst++
		}
		if waited := time.Since(sent); execsFirst == 0 || waited < deadline {
			t.Fatalf("the open was answered after %v with %d stalled execs answered ahead of it; want it behind at "+
				"least one of them and no sooner than the %v deadline", waited, execsFirst, deadline)
		}
		r.release()
		for len(execs) > 0 {
			fd, resp := next(t, r)
			if !execs[fd] || resp != unix.FAN_ALLOW {
				t.Fatalf("response = descriptor %d, %#x; want a stalled exec's FAN_ALLOW", fd, resp)
			}
			delete(execs, fd)
		}
	})

	t.Run("past the overdue ceiling the listener gives the group up", func(t *testing.T) {
		// A small ceiling stands in for fanotifyOverdueCeiling, so three rounds of the pool pass it rather
		// than sixty-five, and the deadline above leaves each exec ample time to reach its stalled lookup
		// before it is answered.
		const (
			deadline = 200 * time.Millisecond
			ceiling  = 2 * fanotifyWorkers
		)
		r := start(t, deadline, ceiling, false)

		// Every descriptor is open before the first deadline closes any, so each number names one event.
		execs := map[int32]bool{}
		for i := range ceiling {
			execs[send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, int32(100+i))] = true
		}
		for range ceiling {
			fd, resp := next(t, r)
			if !execs[fd] || resp != unix.FAN_ALLOW {
				t.Fatalf("response = descriptor %d, %#x; want a stalled exec's FAN_ALLOW (§6 E16)", fd, resp)
			}
			delete(execs, fd)
		}
		// handle() counts a decision as overdue before it writes the answer, so every count is in by now.
		if got, lookups := r.l.overdue.Load(), r.lookups.Load(); got != ceiling || lookups != ceiling {
			t.Fatalf("overdue = %d, lookups = %d; want %d of each: every exec answered at its deadline with its "+
				"membership read still stalled", got, lookups, ceiling)
		}

		// At the ceiling, not past it, the listener is still the listener: it decides and answers.
		open := send(t, r, unix.FAN_OPEN_PERM, ordinary, 1)
		if fd, resp := next(t, r); fd != open || resp != unix.FAN_ALLOW {
			t.Fatalf("response = descriptor %d, %#x; want the open's %d, FAN_ALLOW, with %d decisions overdue "+
				"against a ceiling of %d", fd, resp, open, ceiling, ceiling)
		}
		select {
		case err := <-r.loopErr:
			r.exited = true
			t.Fatalf("loop() = %v with %d decisions overdue, at its ceiling of %d rather than past it", err,
				ceiling, ceiling)
		case <-time.After(3 * fanPollTimeoutMS * time.Millisecond):
		}

		last := send(t, r, unix.FAN_OPEN_EXEC_PERM, unnamed, 1000)
		if fd, resp := next(t, r); fd != last || resp != unix.FAN_ALLOW {
			t.Fatalf("response = descriptor %d, %#x; want the last exec's %d, FAN_ALLOW at its deadline", fd,
				resp, last)
		}
		select {
		case err := <-r.loopErr:
			r.exited = true
			if !errors.Is(err, ErrListenerDied) {
				t.Fatalf("loop() = %v with %d decisions overdue against a ceiling of %d, want ErrListenerDied, "+
					"which takes §7's path for a dead listener (§6 E34)", err, ceiling+1, ceiling)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("loop() still running 5s after %d decisions were overdue against a ceiling of %d: stalled "+
				"reads would pile up toward the Go runtime's thread limit, whose abort runs no teardown (§6 E34)",
				r.l.overdue.Load(), ceiling)
		}
		if _, _, timeouts, _ := r.l.stats(); timeouts != ceiling+1 {
			t.Fatalf("timeouts = %d, want %d", timeouts, ceiling+1)
		}
		if got := r.lookups.Load(); got != ceiling+1 {
			t.Fatalf("%d membership lookups, want %d: the ceiling ends the listener, it decides nothing itself",
				got, ceiling+1)
		}
		// The error reaches no ledger by itself: the run is cancelled and its cgroup killed. The gap is the
		// ledger's record of why, with the count that passed the ceiling (§6 E34).
		var overdue []record.GapPayload
		for _, e := range r.events.all() {
			var p record.GapPayload
			if e.Kind == record.KindGap && e.DecodePayload(&p) == nil && strings.HasPrefix(p.Why, GapFanotifyOverdue) {
				overdue = append(overdue, p)
			}
		}
		if len(overdue) != 1 || overdue[0].Count != ceiling+1 || overdue[0].What != record.GapEnforce ||
			!strings.Contains(overdue[0].Why, fmt.Sprintf("more than the %d", ceiling)) {
			t.Fatalf("%s gaps = %+v; want exactly one, what=%s, count %d, naming the ceiling of %d",
				GapFanotifyOverdue, overdue, record.GapEnforce, ceiling+1, ceiling)
		}
	})
}

// TestOverdueCeilingLeavesTheThreadLimitClear pins the arithmetic behind fanotifyOverdueCeiling against the
// Go runtime's own limit (§6 E34). Each decision answered at its deadline and still blocked in its read holds
// an OS thread; loop() checks the count between reads, so the most it can reach is the ceiling plus
// fanOverdueOvershoot. Even at the cap, with no smaller limit measured, that has to leave the rest of the
// launcher at least half of the runtime's limit, since passing it aborts the process with no teardown. The
// smaller limits a real host has are TestOverdueCeilingFitsTheMeasuredBudget's.
func TestOverdueCeilingLeavesTheThreadLimitClear(t *testing.T) {
	t.Parallel()
	limit := goMaxThreads()

	worst := fanotifyOverdueCeiling + fanOverdueOvershoot
	if fanOverdueOvershoot != fanReadBuffer/fanMetadataLen+2*fanotifyWorkers {
		t.Fatalf("fanOverdueOvershoot = %d, want one read's %d records plus the %d queued or deciding",
			fanOverdueOvershoot, fanReadBuffer/fanMetadataLen, 2*fanotifyWorkers)
	}
	if 2*worst > limit {
		t.Fatalf("worst-case overdue decisions = %d of a %d-thread limit, more than half of it", worst, limit)
	}
}

// TestConcurrentRefusalsAreEachOneBareFanDeny is §6 E2 and §8 I8 under the worker pool: every refusal gets
// exactly one response, and that response is the bare FAN_DENY, however many are decided at once and
// whichever of them is first.
//
// The bare FAN_DENY is the only refusal this listener writes. The group has no FAN_ENABLE_AUDIT, so the
// kernel would refuse FAN_AUDIT, and the listener sends no info record, so it never sets FAN_INFO — which
// the kernel would accept with a well-formed audit-rule record even from this group, because
// process_access_response checks FAN_ENABLE_AUDIT for the FAN_AUDIT bit alone. FAN_DENY_ERRNO bits it would
// not accept: process_access_response answers EINVAL to them from any group but a FAN_CLASS_PRE_CONTENT one
// (6.14+; every errno bit, from every group, before that), and to EACCES from every group. A listener that
// phrases a refusal with those bits hands the kernel a response it rejects and needs a second write to say
// what the first could not; this pipe rejects nothing, so here such a listener shows up as a response word
// carrying more than FAN_DENY. The run's first refusals are where a probe for those bits kept its state, so
// they are the ones released together here.
func TestConcurrentRefusalsAreEachOneBareFanDeny(t *testing.T) {
	t.Parallel()
	refusal := verdict{path: "/home/u/.ssh/id_ed25519", rule: "fs.deny_read[~/.ssh]", reason: record.ReasonReadDenied}
	l, r := testListener(t, &sink{}, func(fanEvent) (verdict, error) { return refusal, nil }, time.Minute)

	// Every descriptor is open before any handle() runs, and handle() is what closes each one, so no two
	// events can share a number and a response is attributable to exactly one of them.
	pending := map[int32]bool{}
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range fanotifyWorkers {
		fd := openFD(t)
		pending[fd] = true
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			l.handle(fanEvent{Len: fanMetadataLen, Vers: fanMetadataVersion, Mask: unix.FAN_OPEN_PERM, FD: fd, PID: 4242})
		}()
	}
	close(start)
	wg.Wait()

	// Counted before anything is read: every handle() has returned, so every write it made is in the pipe.
	if got := unreadBytes(t, r); got != 8*fanotifyWorkers {
		t.Fatalf("%d bytes written for %d refusals, want one eight-byte response each (§8 I8)", got, fanotifyWorkers)
	}
	for range fanotifyWorkers {
		fd, resp := readResponse(t, r)
		if !pending[fd] {
			t.Fatalf("a response named descriptor %d, which no event carried or which was already answered", fd)
		}
		delete(pending, fd)
		if resp != unix.FAN_DENY {
			t.Fatalf("the refusal of descriptor %d was answered %#x, want the bare FAN_DENY %#x, the only refusal "+
				"this listener writes: no kernel takes errno bits from a FAN_CLASS_CONTENT group, and the "+
				"listener sends no audit or info record (§6 E2)", fd, resp, unix.FAN_DENY)
		}
	}
	if _, refused, _, _ := l.stats(); refused != fanotifyWorkers {
		t.Fatalf("refused counter = %d, want %d", refused, fanotifyWorkers)
	}
}

// unreadBytes reports how many bytes sit in a pipe's buffer: TIOCINQ is FIONREAD's Linux name, and x/sys
// spells it per architecture. It goes through SyscallConn rather than Fd because Fd switches the file to
// blocking mode, which would take readResponse's read deadline away.
func unreadBytes(t *testing.T, r *os.File) int {
	t.Helper()
	rc, err := r.SyscallConn()
	if err != nil {
		t.Fatalf("SyscallConn: %v", err)
	}
	var n int
	var ioctlErr error
	if err := rc.Control(func(fd uintptr) { n, ioctlErr = unix.IoctlGetInt(int(fd), unix.TIOCINQ) }); err != nil {
		t.Fatalf("Control: %v", err)
	}
	if ioctlErr != nil {
		t.Fatalf("TIOCINQ: %v", ioctlErr)
	}
	return n
}
