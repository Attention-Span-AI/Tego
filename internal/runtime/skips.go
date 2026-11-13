// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/doctor"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Skipped deciding and tracking programs (ADR 0148, GAPS C53). Where the kernel preempts kernel code it can skip a
// shared BPF program a run's rules rely on: the hooked action then goes on undecided, or a child cgroup of the run is
// left out of the run set. The handle sums the programs' skip counters (enforce.SkipCounter); the runner reads them
// before it releases the agent, every skipPollInterval while the run lives, and once more after the run's last task is
// gone, when no task of the run can reach a hook. A count that moved is a skip that may have been this run's: the
// programs are the build's, so it may as well be another run's or an ungoverned task's, and nothing in the kernel says
// whose. The run therefore cannot claim its rules held, and it fails closed:
//   - while the agent runs, a move ends the run (reason error), as a lost membership row does (tracking.go): the
//     agent does nothing more under rules that may not hold;
//   - a move or a failed reading first seen by the last reading ends the run the same way: the reason is decided
//     before run_end's ending is, so a run whose agent exited before the poll saw the skip does not end as an exit;
//   - after the last task, the counts become one gap what=enforce per class (record.GapDecidingSkip,
//     record.GapTrackingSkip, count the skips gained since the reading before release), written past the drain so a
//     full queue cannot lose them; a reading that failed is record.GapSkipCounterUnavailable, and also ends a run
//     still running.
//
// One case only records: a deciding program's skips in a fmod_ret run a test build's waiver admitted on a kernel that
// preempts kernel code (doctor.PlanePreemptWaived), where such skips are the expected cost the waiver accepts; ending
// those runs would end CI's fmod_ret cells on every busy runner. A product build has no waiver.
//
// An adoption (ADR 0055) never ends on a skip: ending it releases the agent from every rule, which is the opposite of
// failing closed, and a release is never forced on the operator's agent. It reads its base before the agent is moved
// in, so a base it cannot read refuses the adoption with the agent untouched; it keeps every rule on after a skip and
// keeps polling. An adoption can live for days, so it reports while it lives (liveSkips), through the run's serialized
// ledger writer rather than the queue a full lane can drop from: the first report as soon as run_start is on disk and
// there is anything to say, then at most one report every skipReportInterval. Each counter line counts the skips
// since that class's last successful write. A failed reading opens an outage: its opening and eventual recovery are
// retained in order until written, even if both occurred between reports. Recovery counts the outage's failed reads.
// Reports can contain several outage pairs, so the roughly 1,440 counter lines per class per day do not bound outage
// lines. Scheduling, counter reads and ledger writes add to the reporting interval. A successful prefix is committed
// line by line and starts the interval; unwritten lines wait for the next report. A report with no successful line is
// retried at the next poll. The watcher never ends an adoption or releases its agent for a line it cannot write;
// what the pipeline itself cannot write is ADR 0055's (the adoption ends and releases the agent). The last reading
// writes whatever is left, bypassing the interval.

// skipPollInterval is how often a running run reads its skip counters: one bpf(2) call per watched program, about 30
// of them on a plane run, so a few hundred calls a second at most. It is the nominal delay between a skip and the end
// of the run it ends; the poll's own scheduling, the readings, and the asynchronous kill of the run's tree add to it.
const skipPollInterval = 250 * time.Millisecond

// skipReportInterval bounds how often an adoption writes its live skip report after the first (liveSkips).
const skipReportInterval = time.Minute

// skipWatch is the runner's state of the skip counters.
type skipWatch struct {
	counter enforce.SkipCounter
	// base is the reading before the agent was released (or, adopted, moved in).
	base enforce.ProgramSkips
	// waived: the deciding programs run in fmod_ret mode a test build's waiver admitted; their skips only record.
	waived bool
	// recordOnly: an adoption, which a skip never ends.
	recordOnly bool
	// unavailable says a reading after base failed.
	unavailable atomic.Bool
	// ended ends the run once; logged logs a skip the run is not ended for once.
	ended, logged sync.Once
	// mu guards the adoption's reports: written counts successful lines only; last is the last report with any
	// successful line. Outages retain opening and closing transitions in order, including between reports.
	mu       sync.Mutex
	written  enforce.ProgramSkips
	reported bool
	last     time.Time
	ok       enforce.ProgramSkips
	haveOK   bool
	outage   bool // a launched run had an unreadable counter
	outages  []skipOutage
	writeGap func(source.Gap) error
}

// skipOutage is one adoption outage until both its opening and its closing have reached the ledger.
type skipOutage struct {
	failed   int64
	closed   bool
	reported bool // the opening is on disk
}

// startSkipWatch reads the base before the agent is released and starts the poll.
func (r *runner) startSkipWatch(ctx context.Context) error {
	if err := r.readSkipBase(false); err != nil {
		return err
	}
	r.pollSkips(ctx)
	return nil
}

// readSkipBase reads the counters' base. A handle that sums no counters (a tier with no shared BPF program) has
// nothing to watch. A base that cannot be read refuses the run or the adoption: it could not say afterwards whether
// its rules held.
func (r *runner) readSkipBase(recordOnly bool) error {
	counter, ok := r.handle.(enforce.SkipCounter)
	if !ok {
		return nil
	}
	base, err := counter.ProgramSkips()
	if err != nil {
		return fmt.Errorf("runtime: read the skip counters of the run's BPF programs: %w", err)
	}
	r.skipState = &skipWatch{counter: counter, base: base, written: base, waived: r.skipsWaived(),
		recordOnly: recordOnly, writeGap: r.writeGapNow}
	return nil
}

// pollSkips starts the poll of a watch readSkipBase set up.
func (r *runner) pollSkips(ctx context.Context) {
	if w := r.skipState; w != nil {
		r.group.Go("skips", func() error { return r.watchSkips(ctx, w, skipPollInterval) })
	}
}

// skipWaiver is doctor's test-build waiver of fmod_ret mode's preemption precondition; the tests replace it.
var skipWaiver = doctor.PlanePreemptWaived

// skipsWaived reports whether the run's deciding programs are a fmod_ret plane only a test build's waiver admitted.
func (r *runner) skipsWaived() bool {
	if !skipWaiver() {
		return false
	}
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return false
	}
	mode, _ := dp.DecisionPlane()
	return mode == "fmod_ret"
}

func (r *runner) watchSkips(ctx context.Context, w *skipWatch, interval time.Duration) error {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if r.checkSkips(w) {
				return nil
			}
		}
	}
}

// skipAction is what one reading calls for.
type skipAction int

const (
	skipNone skipAction = iota
	// skipLog: a skip or a failed reading this watch does not end the run for (an adoption, or the waived fmod_ret
	// programs): logged once, and recorded when the run ends.
	skipLog
	// skipEnd: the run ends.
	skipEnd
)

// skipDecide is the policy of one reading (the file comment), taken while the agent runs or after its last task: what it
// calls for, and why in words.
func skipDecide(base, now enforce.ProgramSkips, err error, waived, recordOnly bool) (skipAction, string) {
	act := func(keep bool, detail string) (skipAction, string) {
		if keep || recordOnly {
			return skipLog, detail
		}
		return skipEnd, detail
	}
	if err != nil {
		return act(false, "the skip counters of the BPF programs the run's rules rely on could not be read: "+err.Error())
	}
	deciding, tracking := skipDelta(now.Deciding, base.Deciding), skipDelta(now.Tracking, base.Tracking)
	switch {
	case tracking > 0:
		return act(false, fmt.Sprintf("the kernel skipped the program that adds the run's child cgroups to the run set "+
			"%d times since the run started; it is shared, so a child cgroup of this run may have gone ungoverned", tracking))
	case deciding > 0:
		return act(waived, fmt.Sprintf("the kernel skipped programs that decide the run's actions %d times since the "+
			"run started; they are shared, so an action of this run may have gone on undecided", deciding))
	}
	return skipNone, ""
}

// checkSkips reads the counters once while the run lives and acts on skipDecide's answer. It reports whether the
// watch is done: after an end, or a failed reading of a run; an adoption keeps polling, writing each new skip's line.
func (r *runner) checkSkips(w *skipWatch) bool {
	now, err := w.counter.ProgramSkips()
	if err != nil {
		w.unavailable.Store(true)
	}
	act, detail := skipDecide(w.base, now, err, w.waived, w.recordOnly)
	switch act {
	case skipNone:
		// nothing new: no skip, and the counters were read
	case skipEnd:
		r.failSkips(w, detail, err)
		return true
	case skipLog:
		w.logged.Do(func() {
			r.log.Warn("run: a BPF program the run's rules rely on was skipped, or its counter is unreadable; recorded, "+
				"not ended", "detail", detail)
		})
	}
	if w.recordOnly {
		// An adoption takes every reading, a quiet one included: it may close an outage or make a report due.
		r.liveSkips(w, now, err, skipNow())
		return false
	}
	return act == skipLog && err != nil
}

// skipNow is the clock of the adoption's live reports; the tests replace it.
var skipNow = time.Now

// liveSkips takes one of an adoption's readings (now, or readErr) at time at, and writes the live report when one is
// due (the file comment). Nothing is written before run_start is on disk: what was seen before is kept, and the first
// report after it says so.
func (r *runner) liveSkips(w *skipWatch, now enforce.ProgramSkips, readErr error, at time.Time) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.readingLocked(now, readErr)
	if !r.runStarted() || w.reported && at.Sub(w.last) < skipReportInterval {
		return
	}
	for _, g := range w.reportLocked(r.decisionPlaneMode()) {
		if err := w.writeGap(g); err != nil {
			r.log.Warn("run: the live skip report could not be written; the remaining lines are kept for the next one", "err", err)
			return
		}
		// Append preserves a successful line even if a later one fails. Commit that line before attempting the next;
		// a nonempty successful prefix also starts the reporting interval, so a retry cannot exceed the rate bound.
		w.commitLocked(g)
		w.reported, w.last = true, at
	}
}

// readingLocked retains every adoption outage until its transitions are reported. A successful reading closes only
// the latest outage, so another failure before the report opens a distinct one rather than erasing that recovery.
func (w *skipWatch) readingLocked(now enforce.ProgramSkips, readErr error) {
	if readErr != nil {
		if !w.recordOnly {
			w.outage = true
			return
		}
		if len(w.outages) == 0 || w.outages[len(w.outages)-1].closed {
			w.outages = append(w.outages, skipOutage{})
		}
		w.outages[len(w.outages)-1].failed++
		return
	}
	w.ok, w.haveOK = now, true
	if n := len(w.outages); n > 0 {
		w.outages[n-1].closed = true
	}
}

// reportLocked returns the pending counter deltas, followed by outage transitions in their original order. An opening is
// retained even if recovery preceded the report. w.mu is held, so successful lines can be committed individually.
func (w *skipWatch) reportLocked(mode string) []source.Gap {
	var gs []source.Gap
	if w.haveOK {
		gs = skipGaps(w.written, w.ok, true, w.outage, mode)
	} else if w.outage {
		gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapSkipCounterUnavailable})
	}
	for _, outage := range w.outages {
		if !outage.reported {
			gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapSkipCounterUnavailable})
		}
		if outage.closed {
			gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapSkipCounterRestored, Count: outage.failed})
		}
	}
	return gs
}

// commitLocked advances only the state represented by the line that reached the ledger.
func (w *skipWatch) commitLocked(g source.Gap) {
	switch g.Why {
	case record.GapDecidingSkip:
		w.written.Deciding = w.ok.Deciding
	case record.GapTrackingSkip:
		w.written.Tracking = w.ok.Tracking
	case record.GapSkipCounterUnavailable:
		w.outages[0].reported = true
	case record.GapSkipCounterRestored:
		w.outages = w.outages[1:]
		if len(w.outages) == 0 {
			w.outages = nil
		}
	}
}

// runStarted reports whether run_start is on disk (r.started closed), before which no line may be written.
func (r *runner) runStarted() bool {
	if r.started == nil {
		return true
	}
	select {
	case <-r.started:
		return true
	default:
		return false
	}
}

// writeGapNow writes one gap through the run's serialized ledger writer. A full queue cannot drop it, and each
// success is committed before the next line is tried. The watcher keeps a refused line without releasing the agent.
func (r *runner) writeGapNow(g source.Gap) error {
	if r.writer == nil {
		return errors.New("runtime: no ledger to write to")
	}
	ev := gapEvent(g)
	if ev == nil {
		return fmt.Errorf("runtime: encode the %s line", g.Why)
	}
	ev.PID, ev.TID, ev.Cgroup = os.Getpid(), syscall.Gettid(), r.cg.ID
	return r.writer.RedactStage(r.writer.SplitBlobsStage(r.writer.Append))(ev)
}

// failSkips ends the run once for a skip or an unreadable counter.
func (r *runner) failSkips(w *skipWatch, detail string, err error) {
	w.ended.Do(func() {
		attrs := []any{"detail", detail}
		if err != nil {
			attrs = append(attrs, "err", err)
		}
		r.endRun(identity.ReasonError, "kernel skips: "+detail,
			"run: a BPF program the run's rules rely on was skipped, or its counter is unreadable; ending the run",
			"run: kill after a skipped BPF program", attrs...)
	})
}

// finalSkipCheck reads the counters after the drain, once no task of the run can reach a hook, and writes the run's
// skip gaps directly (finalTrackingCheck's reasoning: a full queue must not lose them). A tree that did not empty even
// after the kill (treeOutlived) can still reach a hook after this reading, so the reading does not cover the run:
// that is a reading never had, written as GapSkipCounterUnavailable.
//
// It runs before run_end's ending is computed, and holds this reading to the same policy as the poll's (finding the
// skip a run's agent exited too soon for the poll to see): a run it calls to end ends with reason error, so its exit
// code says what its gap line says. An adoption and the waived fmod_ret programs only record, as in the poll.
func (r *runner) finalSkipCheck() {
	w := r.skipState
	if w == nil {
		return
	}
	now, err := w.counter.ProgramSkips()
	if err != nil {
		r.log.Warn("run: read the skip counters of the run's BPF programs at the end", "err", err)
		w.unavailable.Store(true)
	}
	policyErr := err
	if r.treeOutlived.Load() {
		w.unavailable.Store(true)
		if policyErr == nil {
			policyErr = errors.New("the run's tree outlived its kill, so a task of it can reach a hook after this reading")
		}
	}
	if act, detail := skipDecide(w.base, now, policyErr, w.waived, w.recordOnly); act == skipEnd {
		r.failSkips(w, detail, policyErr)
	}
	// What is left: a run's whole count (it wrote nothing live); an adoption's since its last report, with an outage
	// it has not reported (or one this reading opens), or the close of one it did.
	w.mu.Lock()
	w.readingLocked(now, err)
	if w.unavailable.Load() && !w.recordOnly {
		w.outage = true // a run's failed reading, or a tree that outlived its kill, is not covered by any later one
	}
	gs := w.reportLocked(r.decisionPlaneMode())
	if r.treeOutlived.Load() && w.recordOnly && (len(w.outages) == 0 || w.outages[len(w.outages)-1].closed) {
		gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapSkipCounterUnavailable})
	}
	w.mu.Unlock()
	for _, g := range gs {
		r.emitGapNow(g)
	}
}

// skipGaps is the gap lines of one run's skip counters: one per class that moved between base and final (final
// unread when ok is false), and one GapSkipCounterUnavailable when any reading after base failed. A run with no skip
// and no failed reading writes none.
func skipGaps(base, final enforce.ProgramSkips, ok, unavailable bool, mode string) []source.Gap {
	var gs []source.Gap
	if ok {
		if d := skipDelta(final.Deciding, base.Deciding); d > 0 {
			gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapDecidingSkip, Count: gapCount(d),
				DecisionPlane: mode})
		}
		if d := skipDelta(final.Tracking, base.Tracking); d > 0 {
			gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapTrackingSkip, Count: gapCount(d)})
		}
	}
	if !ok || unavailable {
		gs = append(gs, source.Gap{What: record.GapEnforce, Why: record.GapSkipCounterUnavailable})
	}
	return gs
}

// skipDelta is how many skips a counter gained. The counters are per-program-instance u64s that only grow while the
// instance lives, and the watch holds the instances it reads, so a reading below base cannot happen; were it to, the
// counter is not the one base read, and that is a skip that cannot be ruled out: one is counted.
func skipDelta(now, base uint64) uint64 {
	if now < base {
		return 1
	}
	return now - base
}

// gapCount fits a skip count into a gap's count.
func gapCount(n uint64) int64 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	return int64(n)
}

// decisionPlaneMode is the run's decision plane mode, "" without one.
func (r *runner) decisionPlaneMode() string {
	dp, ok := r.handle.(enforce.DecisionPlaneReporter)
	if !ok {
		return ""
	}
	mode, _ := dp.DecisionPlane()
	return mode
}
