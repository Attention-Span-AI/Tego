// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// callLog is a ProcessHook that records its calls, and can be held on its first call.
type callLog struct {
	mu    sync.Mutex
	calls []string
	hold  chan struct{} // closed to let the first call return; nil holds nothing
	held  sync.Once
	// entered is closed when the first call is held (a test that must know the follower has taken it); nil is unused.
	entered chan struct{}
}

func (c *callLog) note(s string) {
	if c.hold != nil {
		c.held.Do(func() {
			if c.entered != nil {
				close(c.entered)
			}
			<-c.hold
		})
	}
	c.mu.Lock()
	c.calls = append(c.calls, s)
	c.mu.Unlock()
}
func (c *callLog) OnExec(pid int, _ uint64, path string) {
	c.note(fmt.Sprintf("exec %d %s", pid, path))
}
func (c *callLog) OnOpen(pid int, _ uint64, path string) {
	c.note(fmt.Sprintf("open %d %s", pid, path))
}
func (c *callLog) OnExit(pid int) { c.note(fmt.Sprintf("exit %d", pid)) }

// TestHookQueueKeepsOrderAndFreesTheCaller: the uprobe source's hooks read files a traced process names and
// ran on the recorder's drain goroutine, so a hook that waited held the kernel record, and the run's Stop
// behind it. They run on a queue's own goroutine now: the caller returns while the follower is held, and the
// follower still sees the calls in the recorder's order, an exit after the exec it ends.
func TestHookQueueKeepsOrderAndFreesTheCaller(t *testing.T) {
	f := &callLog{hold: make(chan struct{})}
	q := newHookQueue(f)
	returned := make(chan struct{})
	go func() {
		q.OnExec(7, 41, "/usr/bin/python3")
		q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
		q.OnExit(7)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the caller waited for a held follower")
	}
	close(f.hold)
	if !q.close(5 * time.Second) {
		t.Fatal("the queue did not finish the calls it held")
	}
	want := []string{"exec 7 /usr/bin/python3", "open 7 /usr/lib/libssl.so.3", "exit 7"}
	f.mu.Lock()
	defer f.mu.Unlock()
	if fmt.Sprint(f.calls) != fmt.Sprint(want) {
		t.Fatalf("follower saw %q, want %q", f.calls, want)
	}
}

// TestHookQueueCloseIsBounded: a follower held in a call does not hold shutdown past the queue's wait, and a
// call made after close is dropped rather than waiting for a goroutine that has gone.
func TestHookQueueCloseIsBounded(t *testing.T) {
	f := &callLog{hold: make(chan struct{})}
	q := newHookQueue(f)
	q.OnExec(1, 0, "/bin/true")
	start := time.Now()
	if q.close(50 * time.Millisecond) {
		t.Fatal("close reported a held call finished")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Fatalf("close waited %v for a held follower", waited)
	}
	q.OnExit(1) // after close: dropped, never blocks
	close(f.hold)
	<-q.done
}

// blockingSource is a source whose Stop waits until release is closed.
type blockingSource struct {
	plainSource
	release chan struct{}
}

func (s *blockingSource) Stop() error { <-s.release; return nil }

// TestAStopThatHangsIsBoundedAndRecorded: a source's Stop had no deadline, so one that never returned held
// run_end and the release of the run's cgroup, pins and lock. It is waited for sourceStopWait now, and the
// record says which source it left behind.
func TestAStopThatHangsIsBoundedAndRecorded(t *testing.T) {
	stuck := &blockingSource{plainSource: plainSource{name: "uprobe"}, release: make(chan struct{})}
	t.Cleanup(func() { close(stuck.release) })
	r := &runner{log: slog.New(slog.DiscardHandler), queue: NewQueue(8), stopWait: 50 * time.Millisecond,
		sources: []source.Source{&plainSource{name: "observe"}, stuck}}
	start := time.Now()
	r.stopSources()
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("shutdown waited %v on a source that never stopped", waited)
	}
	select {
	case ev := <-r.queue.C():
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil || p.Why != GapSourceStopTimeout || p.Binary != "uprobe" {
			t.Fatalf("gap %+v (%v), want why=%s binary=uprobe", p, err, GapSourceStopTimeout)
		}
	default:
		t.Fatal("no gap names the source that did not stop")
	}
}

// TestHookQueueNeverWaitsAndCountsWhatItDrops: put waited for room, so a follower slow in one OnExec behind a
// burst of libssl opens stalled the recorder's drain, and Stop's final drain behind it, again. Past its
// capacity a call is dropped and counted.
//
// A dropped exec or libssl open is a process the uprobe source never attached at, whose model traffic is
// unmetered, and the only trace was a gap written at shutdown. The first drop is now recorded at once and
// reported as unmetered spend, which ends a run with a token budget; closeHookQueues records the rest.
func TestHookQueueNeverWaitsAndCountsWhatItDrops(t *testing.T) {
	r, cgroups, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
	f := &callLog{hold: make(chan struct{})}
	q := newHookQueue(f)
	r.watchHookQueue(q, "uprobe")
	returned := make(chan struct{})
	go func() {
		q.OnExec(7, 41, "/usr/bin/python3") // held in the follower
		for range hookQueueSize + 100 {
			q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
		}
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("put waited for room behind a held follower")
	}
	gap := func(want int64) {
		t.Helper()
		select {
		case ev := <-r.queue.C():
			var p record.GapPayload
			if err := ev.DecodePayload(&p); err != nil || p.Why != GapHookQueueFull || p.What != record.GapCapture ||
				p.Binary != "uprobe" || int64(p.Count) != want {
				t.Fatalf("gap %+v (%v), want what=capture why=%s binary=uprobe count=%d", p, err, GapHookQueueFull, want)
			}
		default:
			t.Fatal("no gap records the calls the queue dropped")
		}
	}
	// Before shutdown: the first drop is already in the record, and the budgeted run is ending.
	gap(1)
	if r.terminal != identity.ReasonError || cgroups.killed != 1 {
		t.Fatalf("a budgeted run whose follower missed an exec is %q after %d kills, want error and one kill",
			r.terminal, cgroups.killed)
	}
	if !strings.Contains(r.detail, "hook queue full") {
		t.Errorf("detail %q does not name the cause", r.detail)
	}
	close(f.hold)
	r.hookQueues = []*hookQueue{q}
	r.closeHookQueues()
	n := q.dropped.Load()
	if n < 99 || n > 101 {
		t.Errorf("dropped %d calls, want the ~100 past capacity", n)
	}
	gap(n - 1)

	// A run with no token or cost budget keeps running; its record still says so at once.
	r2, cgroups2, _, _ := budgetRunner(t, agent.ResolvedLimits{Wall: time.Hour})
	q2 := newHookQueue(&callLog{})
	r2.watchHookQueue(q2, "uprobe")
	q2.lost()
	if r2.terminal != "" || cgroups2.killed != 0 {
		t.Fatalf("a run with no budget was ended (%q, %d kills)", r2.terminal, cgroups2.killed)
	}
	q2.close(5 * time.Second)
}

// TestHookQueueQueuesOnlyTheOpensAFollowerActsOn: the uprobe source attaches only at a libssl (capture-derive
// R4), so only those opens are queued; every other open filled the queue while the source was slow.
func TestHookQueueQueuesOnlyTheOpensAFollowerActsOn(t *testing.T) {
	for path, want := range map[string]bool{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3": true,
		"/usr/lib/libssl.so":                    true,
		"/opt/lib/libssl.so.1.1":                true,
		"libssl.so.3":                           false, // relative: names no file the source can open
		"/usr/lib/libssl.so.3x":                 false,
		"/usr/lib/libssl.so.":                   false,
		"/usr/lib/libssl.so..3":                 false,
		"/usr/lib/libcrypto.so.3":               false,
		"/home/u/project/main.py":               false,
	} {
		if got := followedOpen(path); got != want {
			t.Errorf("followedOpen(%q) = %v, want %v", path, got, want)
		}
	}
	f := &callLog{}
	q := newHookQueue(f)
	q.OnOpen(7, 41, "/etc/passwd")
	q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
	if !q.close(5 * time.Second) {
		t.Fatal("close")
	}
	if fmt.Sprint(f.calls) != fmt.Sprint([]string{"open 7 /usr/lib/libssl.so.3"}) {
		t.Errorf("follower saw %q", f.calls)
	}
}

// TestHookQueueNeverDropsAnExit: an exit put found no room for was dropped, so the follower kept a dead pid
// until Stop, which a reused pid could then be taken for, and the queue's promise that an exit follows the
// exec it ends was broken. An exit is always queued now, behind whatever the queue holds; only execs and
// libssl opens are bounded and dropped.
func TestHookQueueNeverDropsAnExit(t *testing.T) {
	f := &callLog{hold: make(chan struct{})}
	q := newHookQueue(f)
	q.OnExec(7, 41, "/usr/bin/python3") // held in the follower
	for pid := range 50 {
		q.OnExec(1000+pid, 41, "/usr/bin/python3")
	}
	for range hookQueueSize + 100 {
		q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
	}
	for pid := range 50 {
		q.OnExit(1000 + pid)
	}
	close(f.hold)
	if !q.close(5 * time.Second) {
		t.Fatal("the queue did not finish the calls it held")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	exits := 0
	for _, c := range f.calls {
		var pid int
		if _, err := fmt.Sscanf(c, "exit %d", &pid); err == nil {
			exits++
		}
	}
	if exits != 50 {
		t.Fatalf("follower saw %d of 50 exits; an exit was dropped", exits)
	}
	if last := f.calls[len(f.calls)-1]; last != "exit 1049" {
		t.Errorf("last call %q, want the last exit: the queue's order was broken", last)
	}
	if n := q.dropped.Load(); n < 149 || n > 151 {
		t.Errorf("dropped %d calls, want the ~100 opens past capacity and no exit", n)
	}
}

// readingSource is a source whose Stop is still reading the kernel state the handle owns when shutdown gives up
// on it: it reports whether the handle was closed under it.
type readingSource struct {
	plainSource
	release chan struct{}
	handle  *raceHandle
	mu      sync.Mutex
	raced   bool
}

func (s *readingSource) Stop() error {
	<-s.release
	if s.handle.isClosed() {
		s.mu.Lock()
		s.raced = true
		s.mu.Unlock()
	}
	return nil
}

// raceHandle is a handle whose releases can be read from another goroutine.
type raceHandle struct {
	fakeHandle
	mu     sync.Mutex
	closed bool
}

func (h *raceHandle) Detach() error { return nil }
func (h *raceHandle) Close() error {
	h.mu.Lock()
	h.closed = true
	h.mu.Unlock()
	return nil
}
func (h *raceHandle) isClosed() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.closed
}

// TestReleaseWaitsForAStopStillRunning: a source whose Stop outlasted sourceStopWait was left running, and
// releaseKernelState then closed the ring and pins that Stop may still read. The handle is released only once
// every Stop shutdown gave up on has returned; the launcher does not wait for it.
func TestReleaseWaitsForAStopStillRunning(t *testing.T) {
	h := &raceHandle{}
	stuck := &readingSource{plainSource: plainSource{name: "observe"}, release: make(chan struct{}), handle: h}
	r := &runner{log: slog.New(slog.DiscardHandler), queue: NewQueue(8), stopWait: 20 * time.Millisecond,
		sources: []source.Source{stuck}, handle: h}
	r.stopSources()
	start := time.Now()
	r.releaseKernelState(context.Background(), nil)
	if waited := time.Since(start); waited > 5*time.Second {
		t.Fatalf("release waited %v on a Stop that never returned", waited)
	}
	if h.isClosed() {
		t.Fatal("the handle was closed while a source's Stop was still running")
	}
	close(stuck.release)
	deadline := time.Now().Add(5 * time.Second)
	for !h.isClosed() {
		if time.Now().After(deadline) {
			t.Fatal("the handle was never released after the Stop returned")
		}
		time.Sleep(5 * time.Millisecond)
	}
	stuck.mu.Lock()
	defer stuck.mu.Unlock()
	if stuck.raced {
		t.Fatal("the handle was closed under a Stop still reading it")
	}
}

// TestHookQueueDoesNotGrowOnExitsItHoldsNoStateFor: an exit was queued past the bound for every process, so a
// fork-and-exit loop grew the queue without limit while the follower was slow in one call. Only a pid the
// follower was given an exec or open of has an exit queued.
func TestHookQueueDoesNotGrowOnExitsItHoldsNoStateFor(t *testing.T) {
	f := &callLog{hold: make(chan struct{}), entered: make(chan struct{})}
	q := newHookQueue(f)
	q.OnExec(7, 41, "/usr/bin/python3") // held in the follower
	select {
	case <-f.entered: // the follower has taken the exec off the queue, so only exits count below
	case <-time.After(10 * time.Second):
		t.Fatal("the follower never took the exec")
	}
	for pid := range 100000 {
		q.OnExit(5000 + pid)
	}
	q.OnExit(7)
	q.mu.Lock()
	n := len(q.pending)
	q.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d calls queued behind a held follower, want only the exit of the pid it was given", n)
	}
	close(f.hold)
	if !q.close(5 * time.Second) {
		t.Fatal("the queue did not finish")
	}
}

// TestHookQueueFirstDropIsRecordedOnce: the first drop was counted, and only then marked as reported,
// so a close between the two let closeHookQueues record it again (a gap of count 1 besides lost's own).
// What closeHookQueues reads right after close must never show a drop lost has not been told about.
func TestHookQueueFirstDropIsRecordedOnce(t *testing.T) {
	for round := 0; round < 2000; round++ {
		f := &callLog{hold: make(chan struct{})}
		q := newHookQueue(f)
		q.lost = func() {}
		q.OnExec(7, 41, "/usr/bin/python3")
		// Fill to exactly capacity, so the next open is the queue's first drop.
		for {
			q.mu.Lock()
			full := q.bounded >= hookQueueSize
			q.mu.Unlock()
			if full {
				break
			}
			q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
		}
		done := make(chan struct{})
		go func() {
			q.OnOpen(7, 41, "/usr/lib/libssl.so.3")
			close(done)
		}()
		q.close(0)
		if n := q.dropped.Load() - q.reported.Load(); n > 0 {
			t.Fatalf("round %d: close saw %d drops that lost was not told of", round, n)
		}
		<-done
		close(f.hold)
	}
}
