// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/derive"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// followKernelRecord connects every capture source that follows the kernel record to the recorder
// startKernelRecord has just built. It runs before any source starts, which is what AddProcessHook needs.
//
// A follower is told the build only when a recorder is there to drive it. One that is never told has no
// exec to attach at, and says so when it starts with a mechanism-unavailable gap rather than draining a
// ring buffer nothing will fill; the run has already recorded kernel-record-unavailable for the recorder
// itself.
//
// Each follower is fed through stageFilter, so the launcher's own child stage never reaches it as a process
// of the agent.
func (r *runner) followKernelRecord(bpfHash string, rec source.Source) {
	stream, ok := rec.(source.ProcessStream)
	if !ok {
		return
	}
	for _, s := range r.deps.Capture {
		f, ok := s.(source.KernelFollower)
		if !ok {
			continue
		}
		q := newHookQueue(f)
		r.watchHookQueue(q, s.Name())
		if err := stream.AddProcessHook(stageFilter{ProcessHook: q, r: r}); err != nil {
			q.close(0)
			r.log.Warn("runtime: capture source cannot follow the kernel record", "source", s.Name(), "err", err)
			continue
		}
		r.hookQueues = append(r.hookQueues, q)
		f.FollowKernel(bpfHash)
	}
}

// followExits hands the kernel record's process exits to the run's attribute stage, which retires the
// threads of an exited process (derive.Steps.Exit). A run's model traffic can come from far more threads
// than are ever alive at once, one per short-lived process at tier 2 and 3 where the uprobe source reports
// the real tid, and the stage used to keep every one of them for the rest of the run (P8). It runs when
// attributeStage builds the stage, which is after startKernelRecord and before any source starts, as
// AddProcessHook requires. With no recorder (tier 1, whose forwarder events all carry the launcher's own
// tid, or a tier whose record could not be built) nothing reports an exit, and the stage keeps every thread:
// memory, not time per event.
func (r *runner) followExits(s *derive.Steps) {
	stream, ok := r.kernelRecord.(source.ProcessStream)
	if !ok {
		return
	}
	if err := stream.AddProcessHook(exitsTo{steps: s}); err != nil {
		r.log.Warn("runtime: the attribute stage cannot follow process exits", "err", err)
	}
}

// exitsTo is the attribute stage as a ProcessHook: only an exit concerns it.
type exitsTo struct{ steps *derive.Steps }

func (exitsTo) OnExec(int, uint64, string) {}
func (exitsTo) OnOpen(int, uint64, string) {}
func (h exitsTo) OnExit(pid int)           { h.steps.Exit(pid) }

// recorderFirst is the kernel recorder as the run starts it: before any capture source (runner.allSources), and
// with every follower withdrawn when the recorder's Start leaves it reading nothing.
//
// The recorder and a follower each decide at their own Start, from their own walk of the build's run set,
// whether this run may read (enforce-cgroup-observe.md §2 "Run scope", capture-derive.md edge case #26), and
// the walks are not one instant: another run's row can appear between them, or one walk alone can fail. A
// follower that decided to read beside a recorder that did not would capture nothing, because nothing feeds
// it an exec or an open, while run_start named it as the run's capture. Withdrawn, the follower starts with
// no build and records its own mechanism-unavailable gap, which is what run_start reads (startedCapture). The
// other split, a recorder that reads beside a follower that found another run's row, needs no help: the
// follower's gap already says it is not capturing, and the recorder's record is complete.
type recorderFirst struct {
	source.Source
	r *runner
}

// Start starts the recorder and withdraws the followers when it reads nothing (kernelRecordInert).
func (s recorderFirst) Start(ctx context.Context, run source.RunRef, sink source.Sink) error {
	if err := s.Source.Start(ctx, run, sink); err != nil {
		return err
	}
	if kernelRecordInert(s.Source) {
		for _, c := range s.r.deps.Capture {
			if f, ok := c.(source.KernelFollower); ok {
				f.FollowKernel("")
			}
		}
	}
	return nil
}

// stageFilter keeps the launcher's child stage from a follower. The run's first process is this launcher's
// clone, which execs the launcher's own binary (launch.Launcher.Exe, /proc/self/exe by default) as `tego
// __child` inside the run's cgroup and only then execs the agent in place (docs/p0/runtime-launch.md §4.1
// steps 5-7). Since ADR 0021 the tier's run-set row is inserted after that exec (arm), so the kernel record
// no longer sees it; the filter stays as the second line, for a record that ever does. When the record saw it
// like any other, a follower handed it took the launcher's binary for an agent process: the uprobe source held a static-tls-no-symbols verdict for it and
// settled it into the ledger when the agent's exec replaced the image, a gap line naming tego in every
// tier-2 capture run and naming nothing the agent ran.
//
// An exec is the stage's when its pid is the child's and its path is the one the launcher execs the stage
// by. Nothing else in the run has the child's pid until the agent itself runs under it, and the agent's own
// exec names its resolved command, never that path. Should the agent later re-exec itself through the same
// path, the file is the image it already runs, whose verdict and attach reference the follower already
// holds under that pid, so holding the exec back loses nothing.
//
// r.child and r.launcher are set by startChild, before startWorkers starts the recorder whose drain calls
// this, and never written again, so the drain reads them without a lock.
type stageFilter struct {
	source.ProcessHook
	r *runner
}

// OnExec passes every exec but the child stage's to the follower.
func (s stageFilter) OnExec(pid int, cgroupID uint64, path string) {
	if s.r.isChildStage(pid, path) {
		return
	}
	s.ProcessHook.OnExec(pid, cgroupID, path)
}

// isChildStage reports whether an exec record is this run's child stage (see stageFilter).
func (r *runner) isChildStage(pid int, path string) bool {
	if r.child == nil || r.launcher == nil || pid != r.child.PID {
		return false
	}
	exe := r.launcher.Exe
	if exe == "" {
		exe = childStageExe
	}
	return path == exe
}

// childStageExe is what launch.Launcher execs its child stage by when its Exe is empty.
const childStageExe = "/proc/self/exe"

// hookQueueSize bounds the execs and libssl opens waiting for one follower. Past it one is dropped and counted
// (GapHookQueueFull), never waited for: the recorder's drain, and Stop's final drain behind it, used to wait for
// room, so a follower slow in one OnExec behind a burst of opens stalled the kernel record again. Exits are not
// bounded by it (hookQueue).
const hookQueueSize = 4096

// GapHookQueueFull is gap what=capture: the hook calls a capture source that follows the kernel record never
// received because its queue was full (hookQueue.put). A dropped exec is a process the source never attached
// at, a dropped open a libssl it may not have attached: that process's model traffic is unmetered. The first
// drop is recorded when it happens, count 1, and reported as unmetered spend (runner.hookCallsLost); the rest,
// if any, when the queue closes. binary names the source.
const GapHookQueueFull = "hook-queue-full"

// hookQueueStopWait bounds how long shutdown waits for a follower to finish the hook calls already queued.
const hookQueueStopWait = 5 * time.Second

// hookCall is one process-lifecycle call a hookQueue holds.
type hookCall struct {
	kind   hookKind
	pid    int
	cgroup uint64
	path   string
}

type hookKind uint8

const (
	hookExec hookKind = iota
	hookOpen
	hookExit
)

// hookQueue calls a follower's process hooks on a goroutine of its own, in the order the recorder made them.
// The uprobe source's OnExec and OnOpen read the files a traced process names and
// attach probes to them, and ran on the recorder's drain goroutine: while one of them waited, the kernel
// record, and the run's Stop behind it, waited too. The order is kept because an exit must follow the exec it
// ends. close stops the goroutine once the calls already queued are made, or after its wait.
//
// It never makes its caller wait. Past hookQueueSize an exec or a libssl open is dropped and counted; the
// first drop is reported to lost at once, and the rest are recorded when the queue closes (closeHookQueues).
// An exit is never dropped for a pid the follower was given an exec or open of: a follower that missed one
// kept a dead pid until Stop, which a reused pid could be taken for. Such exits are queued past the bound, in
// order, one per pid queued and not yet exited, so what they hold is bounded by the execs and opens the queue
// took. An exit for a pid the follower was never given (a fork that exits without an exec, or whose exec was
// dropped and counted) is not queued: the follower kept no state for it, and a fork-and-exit flood otherwise
// grew the queue without bound while the follower was slow. Only the opens a follower acts on are queued at
// all (followedOpen).
type hookQueue struct {
	next source.ProcessHook
	name string // the follower's source name, for the gap
	// lost is called once, on the recorder's goroutine, at the first exec or open the queue drops; nil in a
	// test that reads the count alone.
	lost func()

	mu         sync.Mutex
	pending    []hookCall
	bounded    int              // execs and opens in pending
	known      map[int]struct{} // pids with an exec or open queued and no exit queued since: the only ones an exit is queued for
	lostCalled bool             // the first drop has been handed to lost
	closed     bool             // close has run: put drops what it is given, uncounted
	wake       chan struct{}

	quit chan struct{}
	done chan struct{}
	once sync.Once
	// dropped counts the calls put found no room for; reported is how many of them lost has recorded.
	dropped  atomic.Int64
	reported atomic.Int64
}

// NewHookQueue is the queue a follower is fed through, for a test outside this package that drives a real
// recorder against it (observe's stop-drain tests): the calls it is given are made on its own goroutine, close
// ends it as closeHookQueues does, and dropped is what it had no room for.
func NewHookQueue(next source.ProcessHook) (hook source.ProcessHook, close func(wait time.Duration) bool, dropped func() int64) {
	q := newHookQueue(next)
	return q, q.close, q.dropped.Load
}

func newHookQueue(next source.ProcessHook) *hookQueue {
	q := &hookQueue{next: next, wake: make(chan struct{}, 1), quit: make(chan struct{}), done: make(chan struct{})}
	go q.run()
	return q
}

func (q *hookQueue) OnExec(pid int, cgroupID uint64, path string) {
	q.put(hookCall{kind: hookExec, pid: pid, cgroup: cgroupID, path: path})
}

// OnOpen queues only an open the follower acts on (followedOpen); the follower checks again itself.
func (q *hookQueue) OnOpen(pid int, cgroupID uint64, path string) {
	if !followedOpen(path) {
		return
	}
	q.put(hookCall{kind: hookOpen, pid: pid, cgroup: cgroupID, path: path})
}
func (q *hookQueue) OnExit(pid int) { q.put(hookCall{kind: hookExit, pid: pid}) }

// put queues c without waiting: an exec or open with no room is dropped and counted, an exit queued when the
// follower was given its pid, and after close c is dropped uncounted, since nothing will make the call.
func (q *hookQueue) put(c hookCall) {
	q.mu.Lock()
	if q.closed {
		q.mu.Unlock()
		return
	}
	if c.kind == hookExit {
		if _, ok := q.known[c.pid]; !ok {
			q.mu.Unlock()
			return
		}
		delete(q.known, c.pid)
	} else if q.bounded >= hookQueueSize {
		// The drop and the decision to report it are one step under mu, so closeHookQueues (which takes mu
		// in close) never sees a drop that lost has not been told about yet and records it a second time.
		q.dropped.Add(1)
		first := q.lost != nil && !q.lostCalled
		if first {
			q.lostCalled = true
			q.reported.Store(1)
		}
		q.mu.Unlock()
		if first {
			q.lost()
		}
		return
	}
	q.pending = append(q.pending, c)
	if c.kind != hookExit {
		q.bounded++
		if q.known == nil {
			q.known = make(map[int]struct{})
		}
		q.known[c.pid] = struct{}{}
	}
	q.mu.Unlock()
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// take removes the oldest queued call.
func (q *hookQueue) take() (hookCall, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.pending) == 0 {
		return hookCall{}, false
	}
	c := q.pending[0]
	q.pending[0] = hookCall{}
	q.pending = q.pending[1:]
	if len(q.pending) == 0 {
		q.pending = nil
	}
	if c.kind != hookExit {
		q.bounded--
	}
	return c, true
}

// followedOpen reports whether a follower acts on an open of path: the uprobe source, the one there is, attaches
// only at an absolute path whose final component is named like a libssl (capture-derive R4's
// libssl\.so(\.\d+)*, uprobe.OnOpen). Every other open was queued behind it too, and a burst of them filled
// the queue while the source was slow in one call.
func followedOpen(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	base := filepath.Base(path)
	rest, ok := strings.CutPrefix(base, "libssl.so")
	if !ok {
		return false
	}
	for rest != "" {
		if rest[0] != '.' || len(rest) == 1 {
			return false
		}
		i := 1
		for i < len(rest) && rest[i] >= '0' && rest[i] <= '9' {
			i++
		}
		if i == 1 {
			return false
		}
		rest = rest[i:]
	}
	return true
}

// run makes the queued calls in order until close, then the ones queued before it.
func (q *hookQueue) run() {
	defer close(q.done)
	for {
		var closing bool
		select {
		case <-q.wake:
		case <-q.quit:
			closing = true
		}
		for {
			c, ok := q.take()
			if !ok {
				break
			}
			q.call(c)
		}
		if closing {
			return // put queues nothing once closed is set, which close did before quit
		}
	}
}

func (q *hookQueue) call(c hookCall) {
	switch c.kind {
	case hookExec:
		q.next.OnExec(c.pid, c.cgroup, c.path)
	case hookOpen:
		q.next.OnOpen(c.pid, c.cgroup, c.path)
	case hookExit:
		q.next.OnExit(c.pid)
	}
}

// close ends the queue: the calls already queued are made, and close waits for them up to wait. It reports
// whether the goroutine finished in time; one that did not ends when the call it is in returns.
func (q *hookQueue) close(wait time.Duration) bool {
	q.once.Do(func() {
		q.mu.Lock()
		q.closed = true
		q.mu.Unlock()
		close(q.quit)
	})
	if wait <= 0 {
		return false
	}
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case <-q.done:
		return true
	case <-t.C:
		return false
	}
}

// closeHookQueues ends every follower's hook queue, once the recorder that feeds them has stopped, so a
// follower's Stop runs after the hook calls of its own run — within hookQueueStopWait. A call still running
// past that wait (an OnOpen reading a file the agent chose, an attach the kernel is slow to answer) is not
// stopped: it runs on beside the follower's Stop, which must tolerate it (the uprobe source takes its own lock
// and ignores a hook after its sweep), and the warning below is the only trace it leaves.
//
// The calls a queue had no room for, past the first that hookCallsLost already recorded, are recorded as gap
// what=capture why=hook-queue-full with their count and the source's name.
func (r *runner) closeHookQueues() {
	for _, q := range r.hookQueues {
		if !q.close(hookQueueStopWait) {
			r.log.Warn("run: a capture source's process hooks did not finish in time; stopping it anyway",
				"wait", hookQueueStopWait)
		}
		if n := q.dropped.Load() - q.reported.Load(); n > 0 {
			r.emitGap(source.Gap{What: record.GapCapture, Why: GapHookQueueFull, Binary: q.name, Count: n})
		}
	}
	r.hookQueues = nil
}

// watchHookQueue names q's follower and has the runner told at its first drop (hookCallsLost).
func (r *runner) watchHookQueue(q *hookQueue, source string) {
	q.name = source
	q.lost = func() { r.hookCallsLost(source) }
}

// hookCallsLost is a follower's first dropped exec or libssl open (R1 (j)). The source
// never attached at that process, so its model traffic is unmetered: a run with a token or cost budget ends
// here, as for any spend capture could not count (captureUnmetered), and the gap is written now rather than at
// shutdown. It runs on the recorder's drain goroutine, and neither step waits: emitGap drops on a full lane,
// and captureUnmetered's kill is one write to cgroup.kill.
func (r *runner) hookCallsLost(name string) {
	r.emitGap(source.Gap{What: record.GapCapture, Why: GapHookQueueFull, Binary: name, Count: 1})
	r.captureUnmetered(1, name+" hook queue full: a process exec or libssl open was never attached at, "+
		"so its model traffic is unmetered")
}
