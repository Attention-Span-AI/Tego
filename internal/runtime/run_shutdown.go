// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/internal/runtime/supervisor"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// awaitExit is §4.1 step 12: wait for the agent's main process, then for the whole cgroup to empty,
// so a daemonized descendant the subreaper adopted is waited on too (case 24, R19).
func (r *runner) awaitExit(ctx context.Context) {
	res, err := r.child.Wait(ctx)
	killed := false
	if err != nil {
		// ctx ended (a worker failed, or the caller cancelled): end the tree and reap it. A worker that
		// failed is tego's own failure, and the run_end must say so rather than read the SIGKILL below as
		// the agent's own exit.
		if r.group != nil {
			if gerr := r.group.Err(); gerr != nil {
				r.fail(identity.ReasonError, gerr.Error())
			}
		}
		r.quiesced.Store(true)
		if kerr := r.cgm.Kill(r.cg); kerr != nil {
			r.log.Warn("run: kill after cancel", "err", kerr)
		}
		killed = true
		kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), killTimeout)
		defer cancel()
		if res, err = r.child.Wait(kctx); err != nil {
			r.log.Error("run: wait", "err", err)
			r.noteDetail("wait: " + err.Error())
		}
	}
	r.wait = res
	if !killed && r.endWithMain(ctx) {
		killed = true
	}
	// The open deputy is a process of the run cgroup (ADR 0041 D2) that lives as long as its control socket, so the
	// cgroup would never empty around it: it is ended once it is the run's last process, the agent's descendants
	// served to the end, and reaped before the wait for the empty cgroup.
	if !killed {
		r.awaitOnlyDeputy(ctx)
	}
	r.closeDeputy()
	r.awaitEmpty(ctx, killed)
}

// endWithMain is the rule for a main process that has exited while processes it started still run (runtime-launch.md
// case 24 as amended 2026-10-26): they get stop_grace to exit on their own, and what is left then
// is killed with cgroup.kill, run_end's detail naming each process the kill ended. The run's reason and exit code
// stay the main process's own, so a supervisor sees the agent's exit (a crash a unit restarts) and not a run that
// never ends because a `setsid` or `&`-started child lives on. It reports whether it killed the tree. A contract
// with keep_descendants: true keeps the earlier rule, a run that lasts as long as any process of its tree, and so
// does a run with no cgroup to read. A ctx that ends first leaves the tree to awaitEmpty's cancelled path.
func (r *runner) endWithMain(ctx context.Context) bool {
	if r.cg.Path == "" || r.rt != nil && r.rt.Contract != nil && r.rt.Contract.KeepDescendants {
		return false
	}
	grace := r.stopGrace
	if grace <= 0 {
		grace = config.DefaultStopGrace
	}
	gctx, cancel := context.WithTimeout(ctx, grace)
	defer cancel()
	deputyPID := ""
	if r.deputy != nil {
		deputyPID = strconv.Itoa(r.deputy.PID())
		r.awaitOnlyDeputy(gctx)
		if onlyProcess(r.cg.Path, deputyPID) {
			return false
		}
	} else if r.cgm.WaitEmpty(gctx, r.cg) == nil {
		return false
	}
	if ctx.Err() != nil {
		return false
	}
	left := treeProcesses(r.cg.Path, deputyPID)
	r.quiesced.Store(true)
	if err := r.cgm.Kill(r.cg); err != nil {
		r.log.Warn("run: kill what the main process left running", "err", err)
		r.noteDetail("the main process exited; the kill of what it left running failed: " + err.Error())
		return false
	}
	r.noteDetail(fmt.Sprintf("the main process exited; after stop_grace %s the kill ended %s", grace, left))
	return true
}

// maxNamedProcesses bounds how many processes endWithMain's detail names; the rest are counted.
const maxNamedProcesses = 8

// treeProcesses describes the processes of the cgroup at dir and of the cgroups beneath it, but the one whose pid is
// skip (the open deputy): "2 processes: 1234 sleep, 1240 sleep", the first maxNamedProcesses by pid and name, then
// how many more. A name that cannot be read (the process has exited) is "?". The walk reads at most 256 cgroups.
func treeProcesses(dir, skip string) string {
	var pids []string
	dirs := []string{dir}
	for seen := 0; len(dirs) > 0 && seen < 256; seen++ {
		d := dirs[0]
		dirs = dirs[1:]
		if b, err := os.ReadFile(filepath.Join(d, "cgroup.procs")); err == nil {
			for _, p := range strings.Fields(string(b)) {
				if p != skip {
					pids = append(pids, p)
				}
			}
		}
		entries, _ := os.ReadDir(d)
		for _, e := range entries {
			if e.IsDir() {
				dirs = append(dirs, filepath.Join(d, e.Name()))
			}
		}
	}
	if len(pids) == 0 {
		return "no process it could name"
	}
	named := make([]string, 0, min(len(pids), maxNamedProcesses))
	for _, p := range pids[:min(len(pids), maxNamedProcesses)] {
		comm := "?"
		if b, err := os.ReadFile(filepath.Join("/proc", p, "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		named = append(named, p+" "+comm)
	}
	out := fmt.Sprintf("%d processes: %s", len(pids), strings.Join(named, ", "))
	if len(pids) == 1 {
		out = "1 process: " + named[0]
	}
	if extra := len(pids) - len(named); extra > 0 {
		out += fmt.Sprintf(" and %d more", extra)
	}
	return out
}

// deputyPoll is how often awaitOnlyDeputy reads the run cgroup's processes.
const deputyPoll = 50 * time.Millisecond

// awaitOnlyDeputy returns once the open deputy is the run cgroup's only process (no other in it, none in a cgroup
// beneath it), or ctx ends, or there is no deputy or no cgroup to read. cgroup.events cannot say it: the deputy keeps
// the cgroup populated.
func (r *runner) awaitOnlyDeputy(ctx context.Context) {
	if r.deputy == nil || r.cg.Path == "" {
		return
	}
	pid := strconv.Itoa(r.deputy.PID())
	t := time.NewTicker(deputyPoll)
	defer t.Stop()
	for {
		if onlyProcess(r.cg.Path, pid) {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// onlyProcess reports whether the cgroup at dir holds pid and nothing else: its cgroup.procs names pid alone, and
// no cgroup beneath it is populated. Anything unreadable answers false, and the caller reads again.
func onlyProcess(dir, pid string) bool {
	b, err := os.ReadFile(filepath.Join(dir, "cgroup.procs"))
	if err != nil {
		return false
	}
	procs := strings.Fields(string(b))
	if len(procs) > 1 || len(procs) == 1 && procs[0] != pid {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		ev, err := os.ReadFile(filepath.Join(dir, e.Name(), "cgroup.events"))
		if err != nil || strings.Contains(string(ev), "populated 1") {
			return false
		}
	}
	return true
}

// awaitEmpty is step 12's wait for the whole cgroup to empty, which step 13 relies on beyond the reap: the
// kernel recorder's and the capture source's final drains read the bytes their ring holds when Stop begins,
// and those hold every sample of the run only once no process of the run is left to produce one
// (enforce-cgroup-observe.md §4 Stop, capture-derive.md edge case #28). ctx can end first, when a worker
// failed or the caller cancelled, and cgroup.kill delivers SIGKILL asynchronously, so descendants can still
// be exiting then: their exit samples reached the ring after the drain had measured it, and the ring was
// closed on them with no gap. So once ctx has ended with the tree still populated, the tree is killed (unless
// awaitExit already did) and waited for on a context of its own, bounded like the reap by killTimeout. A tree
// that outlasts even that (a process stuck in uninterruptible sleep) can still produce a sample after the
// drain, which gap what=record why=ringbuf-undrained, with no count, says for a run whose kernel record reads.
func (r *runner) awaitEmpty(ctx context.Context, killed bool) {
	err := r.cgm.WaitEmpty(ctx, r.cg)
	if err == nil {
		r.quiesced.Store(true)
		return
	}
	if ctx.Err() == nil {
		// A failed read of cgroup.events (an agent that chmod'd its own scope's file, an EIO) says nothing
		// about the tree being empty: it takes the cancelled path, killed and waited for again, never
		// released as a clean exit over descendants the subreaper adopted.
		r.log.Warn("run: wait for empty cgroup", "err", err)
		// The kill below ends live processes; run_end says so, at every tier and whatever the recorder.
		r.noteDetail("cgroup.events unreadable, tree killed: " + err.Error())
	}
	r.quiesced.Store(true)
	if !killed {
		if kerr := r.cgm.Kill(r.cg); kerr != nil {
			r.log.Warn("run: kill after cancel", "err", kerr)
		}
	}
	wait := r.killWait
	if wait <= 0 {
		wait = killTimeout
	}
	kctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), wait)
	defer cancel()
	if err := r.cgm.WaitEmpty(kctx, r.cg); err != nil {
		r.log.Warn("run: the cgroup did not empty after the kill; samples after the final drain are not read", "err", err)
		// A recorder that reads nothing has said so already (kernel-record-unavailable): there is no drain
		// for a late sample to miss.
		if r.kernelRecord != nil && !kernelRecordInert(r.kernelRecord) {
			r.emitGap(source.Gap{What: record.GapRecord, Why: GapRingbufUndrained})
		}
	}
}

// shutdown is §4.1 step 13 in exactly that order, and every step runs however the previous one went
// (R8, R18): cancel, stop the sources and join the workers while the queue is still read
// (pumpWhileStopping), release any producer still waiting for room, drain the queue, restore the modes of tego's own
// files (restoreRunState), close the ledger with run_end, detach and close the backend, remove the cgroup, release the
// child's descriptors. A failure in any step is logged, never returned: the alternative leaves a cgroup, a pin or a
// lock behind.
func (r *runner) shutdown(ctx context.Context) Result {
	// The run's signal subscription is released last, not when the signal goroutine returns: the CLI
	// lets a second SIGINT or SIGTERM take its default action (cli.notifyContext), and with no handler
	// left one would kill the launcher between the drain and run_end, or before the kernel state is
	// released. Held, a signal from here on lands in the subscription's buffer and is dropped.
	defer r.releaseSignals()
	r.quiesced.Store(true)
	r.group.Cancel()
	r.stopAsk()
	r.stopDNSBroker()
	r.stopPipeline()
	stopped := r.pumpWhileStopping()
	r.stopSources()
	// The workers are joined while the queue is still read. A supervisor worker emits a line after it has
	// answered the notification, so when the agent exits during a flood each of them can still be waiting for
	// room in a full supervisor lane, with the notification it records already answered. Releasing them
	// before the join (Queue.stopWaiting) dropped every one of those lines as channel-full, up to
	// DefaultWorkers per run, the losses CI's queue-flood test counted on a runner where the ledger was the
	// bottleneck. With the pump running, each waiter gets its room as the backlog drains, within the lane's
	// wait, so the join is still bounded.
	err := r.group.Wait()
	r.closeActivity() // the watcher, its one writer, has stopped
	if err != nil {
		r.log.Warn("run: worker", "err", err)
		// A worker that failed is tego's own failure whenever it came. awaitExit says so only when the
		// failure cancelled the wait for the agent; when the agent's own exit won the race — the enforce
		// listener died a moment after the agent exited — run_end said reason=exit over a run whose
		// enforcement had failed (R8). Cancellation is shutdown's own, not a failure.
		if !errors.Is(err, context.Canceled) {
			r.fail(identity.ReasonError, err.Error())
		}
	}
	// A tier-2 listener may have returned before its workers, which still answer what they hold and record
	// a line for each (enforce-cgroup-observe §6 E35). Waiting here puts those lines ahead of the drain, and
	// with the pump still running they reach a lane that is being read: the default lane never waits, so a
	// full one would drop them. The wait is bounded by killTimeout, well past E16's three deadlines, and
	// runs even when ctx is already cancelled, because a stopped run is exactly when a listener's leftover
	// workers matter.
	if w, ok := r.handle.(api.ListenerWaiter); ok {
		wctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), killTimeout)
		if err := w.WaitListener(wctx); err != nil {
			r.log.Warn("run: listener workers", "err", err)
		}
		cancel()
	}
	// Every producer the run joins has returned; one it does not join that is still waiting for room drops
	// now rather than outlast the pump, and the pump ends so the drain is the ledger's one writer.
	r.runQueue().stopWaiting()
	stopped()
	// Every worker has returned, so nothing can enqueue behind the drain (R8). The drain comes
	// first because it can still decide the run's ending: an ssl_response the queue was holding
	// when the workers stopped is observed here, and a budget it crosses must reach run_end rather
	// than leave a limit event in a ledger whose last line says the agent simply exited.
	if r.pipe != nil {
		r.pipe.drain()
		r.emitSourceGaps()
		r.emitPlaneGaps()
	}
	r.finalLimitCheck()
	r.finalTrackingCheck()
	reason, code, sig, escalated := r.ending()
	var recordErr error
	if r.writer != nil {
		// The modes Close and the next run need, which the agent could take from tego's own files (ownstate.go); no
		// process of the run is left to take them again.
		r.restoreRunState()
		network := r.runNetworkCounters()
		r.termMu.Lock()
		detail := r.detail
		r.termMu.Unlock()
		// The detail is cut to record.MaxDetailBytes: one longer (a Started hook's error) would make run_end longer
		// than a line may be, and the run unterminated.
		end := record.RunEndPayload{Reason: string(reason), ExitCode: code, Signal: sig, Escalated: escalated,
			Detail: record.CutDetail(detail), Supervisor: r.withExecPinCounts(r.supervisorCounters()),
			Resources: r.runResources(), Network: network}
		if err := r.writer.Close(end); err != nil {
			r.log.Error("run: close ledger", "err", err)
			recordErr = err
		}
	}
	// The entry goes only once the scope is removed, and after it when that removal waits on a Stop still
	// running: cleared first, a launcher that exited before its release, or died between the two, left the
	// scope and its root launch record with nothing listing the run, which no sweep met again. A scope that
	// could not be removed keeps the entry too. Listed, the next sweep's ended hook removes what the launcher
	// left.
	r.releaseKernelState(ctx, func(released bool) {
		if released {
			r.clearLive()
		}
	})
	return Result{RunID: string(r.id), ExitCode: code, Reason: string(reason), RecordErr: recordErr}
}

// stopPipeline ends the pipeline goroutine, whose context no worker's failure cancels (runPipeline).
func (r *runner) stopPipeline() {
	if r.pipeStop != nil {
		r.pipeStop()
	}
}

// pumpWhileStopping keeps the queue read while the sources stop, and returns the call that ends it. Step 13
// cancels the workers first, which ends the pipeline goroutine, and only then stops each source, whose Stop
// is where a recorder or a capture source drains what its ring still holds: a run's last exits, opens and
// exchanges (capture-derive.md edge case #28, enforce-cgroup-observe.md §4). With nothing reading the queue,
// all but QueueCapacity of them became channel-full, however far within its StopDrain a drain was. The pump
// starts once the pipeline goroutine has returned and is ended before the queue's final drain, so the ledger
// still has one writer at a time (§9). The queue is still bounded: a drain that outruns the ledger past the
// queue's depth is counted as channel-full, as it would be mid-run. It keeps reading while the workers are
// joined too, for the supervisor's workers still waiting for room with a line of the agent's last
// notifications (shutdown).
func (r *runner) pumpWhileStopping() (stop func()) {
	if r.pipe == nil || r.pipeDone == nil {
		return func() {}
	}
	quit := make(chan struct{})
	ended := make(chan struct{})
	go func() {
		defer close(ended)
		select {
		case <-r.pipeDone:
		case <-quit:
			return
		}
		r.pipe.pump(quit)
	}()
	return func() {
		close(quit)
		<-ended
	}
}

// ending decides the run's one terminal reason and the exit code of `tego run` (invariant 9). The
// launcher's own view — exec failure, stop, signal, ordinary exit — comes from launch.Ended; oom and
// pids override it because the kernel's kill is what the agent's status actually reports (R10).
func (r *runner) ending() (identity.EndReason, int, int, bool) {
	var outcome launch.Outcome
	if r.signals != nil {
		outcome = r.signals.Outcome()
	}
	reason, code := launch.Ended(r.wait, outcome)
	r.termMu.Lock()
	decided := r.terminal
	r.termMu.Unlock()
	if decided != "" {
		reason = decided
		code = identity.ExitCode(reason, r.wait.Status, outcome.Escalated, identity.ExecFailureNone)
	}
	sig := 0
	if r.wait.Status.Signaled() {
		sig = int(r.wait.Status.Signal())
	} else if outcome.Signal != 0 {
		sig = int(outcome.Signal)
	}
	return reason, code, sig, outcome.Escalated
}

// supervisorCounters is the run_end counter block: what the notification loop did over the run, including
// the notifications it held past its soft ceiling, the syscalls it performed that the agent abandoned
// (E35) and the times its worker pool ran short (R21), whose totals nothing else reads (a tier with no
// filter reports zeros).
func (r *runner) supervisorCounters() record.Supervisor {
	if r.sup == nil {
		return record.Supervisor{}
	}
	return runEndCounters(r.sup.Metrics())
}

// runEndCounters copies every counter the loop exposes into run_end.supervisor; one it leaves out is a
// counter nothing ever reads.
func runEndCounters(m supervisor.Metrics) record.Supervisor {
	return record.Supervisor{Notifications: m.Notifications, HeldMS: m.HeldMS, Anomalies: m.Anomalies,
		Orphaned: m.Orphaned, Starved: m.Starved, OrderLost: m.OrderLost, ExecRules: m.ExecRules, ExecMissing: m.ExecMissing}
}

// sourceStopWait bounds each source's Stop at shutdown (R8). A Stop drains what its producer
// still holds and joins its goroutines, and none of that has a deadline of its own: one waiting on a file a
// traced process chose, or on a kernel that never answers, held run_end, and the release of the run's
// cgroup, pins and lock, for as long as it waited.
const sourceStopWait = 30 * time.Second

// stopSources stops the run's sources in order, the kernel recorder first, and each within sourceStopWait. The
// capture sources' hook queues are closed once the recorder that feeds them has stopped (closeHookQueues), so
// a capture source stops after the hook calls of its run have been made, unless one of them outlasts
// hookQueueStopWait: that call is then still running beside the source's Stop (the source's own lock orders
// the two), and what it would have attached may be missing from the record. A Stop that does not return in time
// is left running and recorded as gap what=record why=source-stop-timeout naming the source: what it had not
// yet written is not in the record.
func (r *runner) stopSources() {
	for _, s := range r.sources {
		r.stopSource(s)
		if _, first := s.(recorderFirst); first {
			r.closeHookQueues()
		}
	}
	r.closeHookQueues() // a run with no recorder among its sources
}

// stopSource is one source's Stop within sourceStopWait.
func (r *runner) stopSource(s source.Source) {
	wait := r.stopWait
	if wait <= 0 {
		wait = sourceStopWait
	}
	done := make(chan error, 1)
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		done <- s.Stop()
	}()
	t := time.NewTimer(wait)
	defer t.Stop()
	select {
	case err := <-done:
		if err != nil {
			r.log.Warn("run: stop source", "source", s.Name(), "err", err)
		}
	case <-t.C:
		r.log.Error("run: a source did not stop in time; the run ends without the rest of its record",
			"source", s.Name(), "wait", wait)
		r.emitGap(source.Gap{What: record.GapRecord, Why: GapSourceStopTimeout, Binary: s.Name(), Count: 1})
		r.stuckStops = append(r.stuckStops, returned)
	}
}

// releaseKernelState is the tail of R8: the backend's fds and map entries, the run cgroup, and the
// child's own descriptors. Order matters — the cgroup cannot be removed while the backend still
// holds state keyed to it — and no step is skipped because an earlier one failed (R18).
//
// A source whose Stop shutdown gave up on (stopSource) may still be reading the ring buffer, maps and pins the
// handle owns: the kernel recorder draining its ring, the uprobe source detaching its links. Closing them under
// it raced a live reader. The handle's release, and the cgroup removal ordered behind it, then wait on a
// goroutine of their own for every such Stop to return; the rest is released now, and the launcher does not
// wait. A launcher that exits first leaves them to the kernel's close of its
// descriptors and to the sweep, as a launcher that died there would (sweep.go endedListed).
//
// after runs once the handle and the cgroup are released, on that goroutine when they wait, told whether the
// scope is gone: what the caller must not do before — take the run out of the live index, whose entry is what
// brings a sweep back to a scope the launcher left.
func (r *runner) releaseKernelState(ctx context.Context, after func(released bool)) {
	if after == nil {
		after = func(bool) {}
	}
	if stuck := r.stuckStops; len(stuck) > 0 {
		r.stuckStops = nil
		r.log.Warn("run: a source's Stop is still running; its kernel state is released once it returns",
			"sources", len(stuck))
		bg := context.WithoutCancel(ctx)
		go func() {
			for _, done := range stuck {
				<-done
			}
			after(r.releaseHandleAndCgroup(bg))
		}()
	} else {
		// A caller-cancelled ctx must not cut the scope's EBUSY retry short (R18): a teardown context of its own.
		tctx, cancel := teardownCtx(ctx)
		after(r.releaseHandleAndCgroup(tctx))
		cancel()
	}
	// Only the paths that never reached supervisor.New hold the listener here: startNotifyLoop moves it into
	// New, which owns it from then on, and Loop.Run is the sole closer after that (supervisor.md §3 "closed
	// by Loop.Run shutdown (E24), never reopened").
	if r.notifyFD != nil {
		if err := r.notifyFD.Close(); err != nil {
			r.log.Warn("run: close notify fd", "err", err)
		}
		r.notifyFD = nil
	}
	if r.runtimeDir != "" {
		if err := os.RemoveAll(r.runtimeDir); err != nil {
			r.log.Warn("run: remove run socket dir", "dir", r.runtimeDir, "err", err)
		}
		r.runtimeDir = ""
	}
	r.closeRuntimeLock() // after the removal: no sweep meets the directory unlocked while it is still there
	r.closeDeputy()
	if r.child != nil {
		if err := r.child.Close(); err != nil {
			r.log.Warn("run: close child", "err", err)
		}
	}
}

// releaseHandleAndCgroup is releaseKernelState's ordered pair: the backend's fds and map entries, then the run
// cgroup keyed to them.
func (r *runner) releaseHandleAndCgroup(ctx context.Context) (released bool) {
	if r.handle != nil {
		if err := r.handle.Detach(); err != nil {
			r.log.Warn("run: detach", "err", err)
		}
		if err := r.handle.Close(); err != nil {
			r.log.Warn("run: close handle", "err", err)
		}
	}
	if r.cgm != nil && r.cg.Path != "" {
		if err := r.cgm.Remove(ctx, r.cg); err != nil {
			r.log.Warn("run: remove cgroup", "path", r.cg.Path, "err", err)
			return false // the record stays with the scope, for the sweep that removes it
		}
	}
	if r.rootMarked {
		removeRootMark(string(r.id))
	}
	return true
}

// unwind releases whatever prepare acquired when the run never reached run_start (case 26: each
// resource is released only if it was actually taken, in reverse order, with no double close).
func (r *runner) unwind(ctx context.Context) {
	defer r.releaseSignals() // last, as in shutdown
	r.group.Cancel()
	r.stopAsk()
	r.stopDNSBroker()
	r.stopPipeline()
	r.stopSources()
	// The kernel recorder holds the pinned ring, its reader and epoll, the lost counter and the run set from the
	// moment startKernelRecord built it, before any source starts: a run that failed before it started leaked
	// them for the life of the launcher. One that started is in r.sources, as recorderFirst,
	// and was stopped above.
	if r.kernelRecord != nil && !slices.ContainsFunc(r.sources, func(s source.Source) bool {
		_, first := s.(recorderFirst)
		return first
	}) {
		r.stopSource(r.kernelRecord)
	}
	if r.queue != nil {
		r.queue.stopWaiting() // no pipeline will read what a waiting producer holds
	}
	if err := r.group.Wait(); err != nil {
		if !errors.Is(err, context.Canceled) {
			r.log.Warn("run: worker during unwind", "err", err)
		}
	}
	r.closeActivity()
	if r.child != nil {
		tctx, cancel := teardownCtx(ctx)
		err := r.child.Kill(tctx)
		cancel()
		if err != nil {
			r.log.Warn("run: kill child", "err", err)
		}
	}
	// Abandon, the removal and the clear wait for the handle and the scope as shutdown's clear does (L4): with the
	// directory and its entry still there, a launcher that exits first leaves an empty run whose scope the next
	// sweep removes (the ledger's empty-run hook), not a scope nothing names. A scope that could not be removed
	// keeps both, as shutdown keeps its entry: removed, the scope and its root launch record were left with
	// nothing listing the run.
	r.releaseKernelState(ctx, r.abandonRun)
}

// abandonRun is unwind's end of a run that never started: the ledger released with nothing written, and, once
// the scope is released, the run directory removed and the entry cleared. A scope still there keeps both, for
// the sweep that removes it.
func (r *runner) abandonRun(released bool) {
	if r.writer != nil {
		// Abandon releases the lock and the descriptors and writes nothing: a run that failed before
		// run_start leaves nothing behind but the returned error (case 2, invariant 2). Close appended
		// run_end as the ledger's line 0, so a launcher that died before the removal below, or a removal
		// that failed, left a run that read as ended with no run_start instead of one that never started,
		// which the next sweep clears (case 26).
		if err := r.writer.Abandon(); err != nil {
			r.log.Warn("run: release ledger during unwind", "err", err)
		}
	}
	if !released {
		r.log.Warn("run: the run's scope was not removed; its directory and live entry stay for the sweep",
			"dir", r.dir)
		return
	}
	if r.dir != "" {
		if err := removeRunDir(r.dir); err != nil {
			r.log.Warn("run: remove run dir during unwind", "dir", r.dir, "err", err)
		}
	}
	r.clearLive()
}

// removeRunDir is unwind's removal of a run directory that never started; a variable so a test can leave it
// in place and read what unwind left in it.
var removeRunDir = os.RemoveAll

// teardownCtx is the context the kill, the reap and the scope removal run on: bounded by killTimeout and cut
// loose from the caller cancellation, so a cancelled ctx (an embedder, a test) does not abandon the scope or
// leave the SIGKILLed stage unreaped, as WaitListener already does.
func teardownCtx(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.WithoutCancel(ctx), killTimeout)
}
