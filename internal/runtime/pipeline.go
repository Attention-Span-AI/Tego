// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// Stage is one middleware step between producers and the ledger: stampRule, attribute, redact, splitBlobs
// (docs/REPO-LAYOUT.md "middleware"). A stage may drop an event by not calling next.
type Stage func(next func(*record.Event)) func(*record.Event)

// Compose chains stages left to right in front of the terminal writer.
func Compose(terminal func(*record.Event), stages ...Stage) func(*record.Event) {
	h := terminal
	for i := len(stages) - 1; i >= 0; i-- {
		h = stages[i](h)
	}
	return h
}

// Queue is the bounded event channel between producers and the pipeline goroutine. A full lane drops the
// event and counts it; the count becomes a gap event (P0-DESIGN §6).
//
// It is split into lanes, one per class of producer, each with its own capacity, and the pipeline reads them
// fairly (a select picks uniformly among the ready ones). With one shared channel the agent chose which of
// the run's lines were lost: eight processes making refused connects for 3 s left 17,748 lines and 97,538
// drops, every exec, connect and model exchange of the run among them, as channel-full counts. Now a flood
// fills the lane of the producer it drives and no other. The supervisor's lane also pushes back: its worker
// waits for room, up to supervisorBacklogWait (auditd's backlog_wait_time), before it drops, and a worker
// that waits is a notification of the agent's that waits, so a flooding agent is slowed to what the ledger
// can write rather than let past it. The capture lane waits longer, captureBacklogWait, because a lost
// ssl_response is spend the token and cost budgets never see. The default lane never waits: it carries only
// the run's own lines and gaps. The kernel recorder and the tier-2 listener have lanes of their own, where
// a wait would stall the kernel's ring or the host's opens.
// *R8:* the recorder and the listener once shared the default lane with the facade's gaps, so at tier 2 a flood of reads
// (each its own event under record: full) or of refused opens crowded out the run's exec and connect lines
// and fanotify's refusals, the agent choosing again what the ledger lost. Each now has a lane of its own
// that never waits, so a flood fills its own producer's lane and no other.
//
// Beside the lanes it keeps one reserved slot, which only BudgetSink fills and which the pipeline reads
// before any lane's backlog: the run's limit event.
type Queue struct {
	lanes [numLanes]chan *record.Event
	// limit holds the run's limit event. One slot is enough because a run has at most one
	// (limits-check-doctor-cli.md I1), and it cannot be taken by anything else, so the one line
	// that says why the run was killed never depends on how far behind the pipeline is.
	limit   chan *record.Event
	dropped [numLanes]atomic.Int64
	// closing ends every wait for room: the run is shutting down and a producer still waiting drops.
	closing   chan struct{}
	closeOnce sync.Once
}

// Lane is one class of producer with its own share of the queue.
type Lane int

// The lanes.
const (
	// LaneDefault carries the run's own lines (its gaps) and any producer not given a lane; it never waits.
	LaneDefault Lane = iota
	// LaneSupervisor carries the seccomp supervisor's lines; a full lane waits up to supervisorBacklogWait.
	LaneSupervisor
	// LaneCapture carries model traffic; a full lane waits up to captureBacklogWait.
	LaneCapture
	// LaneKernel carries the tier's kernel recorder; it never waits, which would stall the kernel's ring.
	LaneKernel
	// LaneListener carries tier 2's fanotify listener; it never waits, which would hold the host's opens.
	LaneListener
	numLanes
)

// How long a producer of each lane waits for room before it drops. The supervisor's wait slows a flooding
// agent to the ledger's pace without holding a notification long enough to look like a hung syscall; the
// capture wait outlasts any pipeline stall short of a ledger that has stopped writing, which ends the run.
const (
	supervisorBacklogWait = 250 * time.Millisecond
	captureBacklogWait    = 5 * time.Second
)

// laneWait is each lane's wait for room.
var laneWait = [numLanes]time.Duration{LaneSupervisor: supervisorBacklogWait, LaneCapture: captureBacklogWait}

// NewQueue makes a queue whose every lane holds capacity events (P0 default 4096).
func NewQueue(capacity int) *Queue {
	q := &Queue{limit: make(chan *record.Event, 1), closing: make(chan struct{})}
	for i := range q.lanes {
		q.lanes[i] = make(chan *record.Event, capacity)
	}
	return q
}

// Emit enqueues on the default lane without blocking; on a full lane the event is dropped and counted.
func (q *Queue) Emit(ev *record.Event) {
	select {
	case q.lanes[LaneDefault] <- ev:
	default:
		q.dropped[LaneDefault].Add(1)
	}
}

// Lane is the sink of one lane, for the producer of that class.
func (q *Queue) Lane(l Lane) source.Sink { return laneSink{q: q, l: l} }

// laneSink is Lane's sink.
type laneSink struct {
	q *Queue
	l Lane
}

// Emit enqueues on the sink's lane, waiting for room up to the lane's wait, and drops and counts the event
// when none comes or the run is shutting down.
func (s laneSink) Emit(ev *record.Event) {
	ch := s.q.lanes[s.l]
	select {
	case ch <- ev:
		return
	default:
	}
	if wait := laneWait[s.l]; wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		select {
		case ch <- ev:
			return
		case <-t.C:
		case <-s.q.closing:
		}
	}
	s.q.dropped[s.l].Add(1)
}

// stopWaiting releases every producer waiting for room; each then drops its event. Shutdown calls it once
// its sources are stopped and its workers joined while the queue was still read, so it releases no producer
// the run was going to wait for, and none can hang on a pipeline that no longer reads.
func (q *Queue) stopWaiting() { q.closeOnce.Do(func() { close(q.closing) }) }

// BudgetSink is the sink a run gives its limits.Watcher. A limit event goes to the reserved slot;
// everything else the watcher raises, its price gaps, takes Emit like any producer's event.
//
// The ordinary channel cannot carry the limit event: it drops when full, and it is full exactly when
// the pipeline is behind — the busy run that crosses a budget. Dropping it would leave a run whose
// run_end says reason=limit and whose ledger never says which ceiling, with only a channel-full count
// to show something went missing. Should the slot ever be occupied, which I1 rules out, the event
// falls back to Emit and is at worst counted there.
func (q *Queue) BudgetSink() source.Sink { return budgetSink{q} }

// budgetSink is BudgetSink's routing.
type budgetSink struct{ q *Queue }

// Emit routes one watcher event: the limit event to the reserved slot, the rest to the queue.
func (s budgetSink) Emit(ev *record.Event) {
	if ev != nil && ev.Kind == record.KindLimit {
		select {
		case s.q.limit <- ev:
			return
		default:
		}
	}
	s.q.Emit(ev)
}

// droppedLanes returns and resets every lane's drop count, each lane swapped exactly once, so a drop that
// lands during the pass is counted under its own lane and never lost to a second swap.
func (q *Queue) droppedLanes() [numLanes]int64 {
	var c [numLanes]int64
	for i := range q.dropped {
		c[i] = q.dropped[i].Swap(0)
	}
	return c
}

// anyDropped reports whether some lane has dropped since the last droppedLanes, without resetting.
func (q *Queue) anyDropped() bool {
	for i := range q.dropped {
		if q.dropped[i].Load() != 0 {
			return true
		}
	}
	return false
}

// UnmatchedRule is the rule name of an action no contract entry admitted (spec/policy/SEMANTICS.md
// §2: "unmatched" is its own bucket in every view, never an empty string). Every other value this
// package's producers put in the field comes from agent.FSRule/NetRule/ExecRule.RuleName, the one
// spelling of a `rule` (spec/record/v1/README.md: "the declared entry or unmatched").
const UnmatchedRule = agent.UnmatchedRule

// runStamp is what the pipeline fills in on an event a producer left blank: the launcher's own pid
// and tid, and the run's cgroup id.
type runStamp struct {
	PID, TID int
	Cgroup   uint64
}

// stampRule is the first pipeline stage (P0-DESIGN §4.1 step 4): it completes the decision fields
// of an action event. The producer that saw the syscall owns the verdict (the backend's kernel
// decision, or the compiled table's evaluation); this stage only fills what was left blank, so an
// event can never reach the ledger with an empty rule that views would silently bucket as "no
// rule": an unmatched action is named UnmatchedRule and, having matched nothing, is recorded as
// observed with no authority. It also stamps the launcher's pid/tid and the run's cgroup id on
// events produced by the facade itself (gap, limit), which have no process of their own.
func stampRule(s runStamp) Stage {
	return func(next func(*record.Event)) func(*record.Event) {
		return func(ev *record.Event) {
			if ev.PID == 0 {
				ev.PID, ev.TID = s.PID, s.TID
			}
			if ev.Cgroup == 0 && ev.Kind != record.KindRunEnd {
				ev.Cgroup = s.Cgroup
			}
			if ev.Kind.IsAction() {
				if ev.Rule == "" {
					ev.Rule = UnmatchedRule
				}
				if ev.Verdict == "" {
					ev.Verdict = record.VerdictObserved
				}
				if ev.Authority == "" && ev.Rule != UnmatchedRule {
					ev.Authority = record.AuthorityRule
				}
			}
			next(ev)
		}
	}
}

// attribute is the second pipeline stage (E28a) for a run with no model traffic to derive turns from:
// it records every action as unattributed with method none, which says no attribution was attempted
// rather than that one was attempted and found nothing. A run that does capture model traffic gets
// derive.Steps.Stage here instead, which is the M2 half of P0-DESIGN §5's "Attribution: none (M1) →
// time (M2)". A producer that already attributed an event is left alone.
func attribute(method string) Stage {
	return func(next func(*record.Event)) func(*record.Event) {
		return func(ev *record.Event) {
			if ev.Kind.IsAction() && ev.Attr == nil {
				ev.Attr = &record.Attribution{Confidence: record.ConfidenceUnattributed, Method: method}
			}
			next(ev)
		}
	}
}

// budgets is the run's limits.Watcher as one pipeline stage (limits-check-doctor-cli.md §4:
// "Observe ... called once per event, pipeline order, before ledger.Writer.Append"). The watcher
// passes every event on unchanged and can only ever drop the run, never an event.
//
// It fills in mono_ns first when the producer left it blank, as supervisor.Loop does (it stamps ts
// but no monotonic reading) and as the facade's own gap events do. ledger.Writer.Append would only
// fill it at write time, after every stage, so without this the watcher would read those events as
// time zero, its LastEventMonoNS would never move, and the two ceilings only the clock can cross,
// wall (R3) and the stall gap (R4), could never fire. The value is the run's own clock, the one
// Append would have read a few microseconds later, and Append keeps it (record-ledger.md §4: a
// non-zero mono_ns is the producer's capture reading), so what the watcher measured is what the
// ledger says. A producer that took its own reading, the kernel recorder or the forwarder, keeps it.
func budgets(w *limits.Watcher, clk Clock) Stage {
	return func(next func(*record.Event)) func(*record.Event) {
		observe := w.Stage(next)
		return func(ev *record.Event) {
			if ev.MonoNS == 0 {
				ev.MonoNS = clk.MonoNS()
			}
			observe(ev)
		}
	}
}

// ledgerStage adapts one of the ledger's own stages (redaction, blob split), which report an error,
// to the facade's Stage, which cannot: the error is reported to onErr and the event is dropped,
// because a payload the ledger refused to transform must never reach Append in its raw form.
func ledgerStage(s ledger.Stage, onErr func(*record.Event, error)) Stage {
	return func(next func(*record.Event)) func(*record.Event) {
		sink := s(func(ev *record.Event) error {
			next(ev)
			return nil
		})
		return func(ev *record.Event) {
			if err := sink(ev); err != nil {
				onErr(ev, err)
			}
		}
	}
}

// pipeline drains the run's queue into the ledger through the stage chain of P0-DESIGN §4.1 step 4:
// stampRule → attribute → redact → splitBlobs → Append. One goroutine owns it, so the ledger has
// exactly one writer (§6), and it starts writing only once run_start is on disk: the queue buffers
// whatever the sources produce before that (ledger.Append refuses any event before run_start).
type pipeline struct {
	q      *Queue
	handle func(*record.Event)
	stamp  runStamp
	log    *slog.Logger

	// failed counts events a stage or Append refused; reportRefused turns it into a gap at drain time.
	failed atomic.Int64
	// written counts events appended, for the run's own diagnostics.
	written atomic.Int64
	// onLedgerFail is told, once, that the terminal refused a line: a record that cannot be written is
	// the run's end (record-ledger.md §7), not a count. nil in tests that do not care.
	onLedgerFail func(error)
	// onCaptureLost is told how many capture events the queue dropped, each time some were: the runner ends a
	// run with a token or cost budget, which can no longer be enforced.
	onCaptureLost func(int64)
	// lastDropReport is when maybeReportDrops last reported.
	lastDropReport time.Time
	ledgerFailed   sync.Once
	// requests maps an ssl_request's pair token to the seq the ledger gave its line, until the response
	// that carries the same token takes it (request_seq). Only the pipeline goroutine touches it. It is
	// bounded: an exchange whose response never comes (an aborted request) would otherwise hold its entry for
	// the rest of the run.
	requests     map[uint64]uint64
	requestOrder []uint64
}

// maxPendingRequests bounds the requests map: the oldest token is forgotten first, and a response that
// comes after its request was forgotten omits request_seq, which is what a dropped request line gives too.
const maxPendingRequests = 4096

// newPipeline builds the stage chain in front of terminal. terminal is the ledger writer's Append
// in production and a test double otherwise. budget is the run's budget watcher as a stage, nil
// when the caller runs no budgets.
func newPipeline(q *Queue, terminal ledger.Sink, redact, split ledger.Stage, stamp runStamp, attr, budget Stage, log *slog.Logger) *pipeline {
	p := &pipeline{q: q, stamp: stamp, log: log}
	onErr := func(ev *record.Event, err error) {
		p.failed.Add(1)
		p.log.Warn("pipeline: event dropped", "kind", string(ev.Kind), "err", err)
	}
	write := func(ev *record.Event) {
		if ev.Kind == record.KindSSLResponse && ev.Pair != 0 {
			p.fillRequestSeq(ev)
		}
		if err := terminal(ev); err != nil {
			onErr(ev, err)
			if p.onLedgerFail != nil {
				p.ledgerFailed.Do(func() { p.onLedgerFail(err) })
			}
			return
		}
		p.written.Add(1)
		if ev.Kind == record.KindSSLRequest && ev.Pair != 0 {
			p.rememberRequest(ev.Pair, ev.Seq)
		}
	}
	// The budget watcher sits third, and the position is the contract: after stampRule and
	// attribute, so it only ever sees a complete event; before mirrorRefusals, so one refused
	// action is one piece of activity and not two; and before the ledger's own stages, because
	// redaction rewrites payload fields and splitBlobs moves a large one into a blob file, and R1
	// and R2 have to read the ssl_response `usage` object the producer actually wrote.
	if attr == nil {
		attr = attribute(record.MethodNone)
	}
	stages := []Stage{stampRule(stamp), attr}
	if budget != nil {
		stages = append(stages, budget)
	}
	stages = append(stages, p.mirrorRefusals, ledgerStage(redact, onErr), ledgerStage(split, onErr))
	p.handle = Compose(write, stages...)
	return p
}

// run drains the queue until ctx ends. It waits for started (run_start written) first, so no event
// can race ahead of the run's first line; a cancelled ctx before that returns without writing.
func (p *pipeline) run(ctx context.Context, started <-chan struct{}) error {
	select {
	case <-started:
	case <-ctx.Done():
		return nil
	}
	p.pump(ctx.Done())
	return nil
}

// pump writes the queue's events as they arrive, and returns once the until channel is closed. It is the
// body of run, and the run's shutdown calls it again once run has returned, for as long as the sources are
// stopping and the workers are joined (runner.shutdown): their final drains and emits put a run's last lines
// into the queue, and with nothing reading it the queue held QueueCapacity of them and dropped the rest as
// channel-full. The two calls never overlap, so the ledger keeps its one writer.
func (p *pipeline) pump(until <-chan struct{}) {
	// Drops are reported after a handled event, and also on this ticker: a burst that overfilled a lane and
	// then went quiet would otherwise leave its channel-full gap unwritten until the drain at shutdown.
	tick := time.NewTicker(dropReportEvery)
	defer tick.Stop()
	for {
		// The reserved slot first, on every pass: a limit event raised while this goroutine was
		// handling the event that crossed the budget is written right after that event, and one the
		// wall/stall ticker raised is written ahead of a backlog the kill has already made moot.
		select {
		case ev := <-p.q.limit:
			p.handle(ev)
			continue
		default:
		}
		// Every lane in one select: Go picks uniformly among the ready cases, so no lane's backlog can starve
		// another's (Queue).
		select {
		case ev := <-p.q.limit:
			p.handle(ev)
		case ev := <-p.q.lanes[LaneDefault]:
			p.handle(ev)
			p.maybeReportDrops()
		case ev := <-p.q.lanes[LaneSupervisor]:
			p.handle(ev)
			p.maybeReportDrops()
		case ev := <-p.q.lanes[LaneCapture]:
			p.handle(ev)
			p.maybeReportDrops()
		case ev := <-p.q.lanes[LaneKernel]:
			p.handle(ev)
			p.maybeReportDrops()
		case ev := <-p.q.lanes[LaneListener]:
			p.handle(ev)
			p.maybeReportDrops()
		case <-tick.C:
			p.maybeReportDrops()
		case <-until:
			return
		}
	}
}

// dropReportEvery bounds how often a live run writes a channel-full gap. Reported after every event, a full
// queue wrote one gap line for nearly every event it handled: 200k refused write-opens left 54,014 gaps of
// count 1. The drain at shutdown reports whatever is left.
const dropReportEvery = 100 * time.Millisecond

// maybeReportDrops reports the drop counts when some lane has dropped and dropReportEvery has passed since
// the last report.
func (p *pipeline) maybeReportDrops() {
	if !p.q.anyDropped() {
		return
	}
	if now := time.Now(); now.Sub(p.lastDropReport) >= dropReportEvery {
		p.lastDropReport = now
		p.reportDrops()
	}
}

// drain writes whatever is still buffered after every producer has stopped, then reports both of the
// run's loss counters. It is called once, after the worker group has been waited on (R8), so nothing
// can enqueue behind it and the ledger's next write is run_end.
func (p *pipeline) drain() {
	for {
		ev, ok := p.buffered()
		if !ok {
			p.reportDrops()
			// After the drops, so that a drop gap the ledger itself refused is counted here too.
			p.reportRefused()
			// Reporting can queue an event of its own (a capture loss after quiesce emits its gap on the
			// queue), and nothing polls the queue once drain returns: it is handled here.
			if ev, ok = p.buffered(); !ok {
				return
			}
		}
		p.handle(ev)
	}
}

// buffered takes the next event without waiting, the reserved slot before the queue. Handling a
// drained response can still cross a budget, and the limit event that puts in the slot is found by
// the next call rather than left behind when the queue runs dry.
func (p *pipeline) buffered() (*record.Event, bool) {
	select {
	case ev := <-p.q.limit:
		return ev, true
	default:
	}
	for _, ch := range p.q.lanes {
		select {
		case ev := <-ch:
			return ev, true
		default:
		}
	}
	return nil, false
}

// reportDrops turns the queue's drop counter into one gap event (P0-DESIGN §2.4: "the producer
// increments a drop counter that becomes a gap event with count at the next opportunity"). The gap
// goes straight through the stage chain rather than back onto the queue, which may be full — that
// is what is being reported.
func (p *pipeline) reportDrops() {
	counts := p.q.droppedLanes()
	capture := counts[LaneCapture]
	var n int64
	for _, c := range counts {
		n += c
	}
	if n == 0 {
		return
	}
	if capture > 0 && p.onCaptureLost != nil {
		// A model exchange the capture lane could not hold, even after its wait, is spend the token and
		// cost budgets never saw.
		p.onCaptureLost(capture)
	}
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: record.GapRecord, Why: GapChannelFull, Count: int(n)}); err != nil {
		p.log.Warn("pipeline: gap payload", "err", err)
		return
	}
	p.handle(ev)
}

// reportRefused turns the count of events a stage or Append refused into one gap event, which is the
// same treatment P0-DESIGN §2.4 gives a queue-full drop and what this counter's own contract promises.
//
// Without it the run's two loss channels differ in the one way that matters to a reader: a queue-full
// drop leaves a `gap what=record why=channel-full count=N` line, while an event the pipeline itself
// refused — an unwritable blob file (SplitBlobsStage), a payload that will not unmarshal
// (RedactStage), a failed Append — leaves nothing at all. That is the worst loss an audit record can
// take, because the hash chain stays intact and complete: `check` verifies it and a reader concludes
// the agent never took the action.
//
// The counter is taken to zero before the gap is written, so a gap those same stages also refuse is
// counted for a later report instead of looping here.
func (p *pipeline) reportRefused() {
	n := p.failed.Swap(0)
	if n == 0 {
		return
	}
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: record.GapRecord, Why: GapStageRefused, Count: int(n)}); err != nil {
		p.log.Warn("pipeline: gap payload", "err", err)
		return
	}
	p.handle(ev)
}

// Gap reasons this package writes (spec/record/v1 gap payload).
const (
	// GapChannelFull is the events channel overflowing: the count says how many were lost.
	GapChannelFull = "channel-full"
	// GapStageRefused is an event a pipeline stage or the ledger's Append refused, which is a loss
	// the queue never saw: the count says how many the run lost that way.
	GapStageRefused = "stage-refused"
	// GapKernelRecordUnavailable marks a run whose tier writes a kernel ring buffer that nothing
	// drained: the enforcement is intact and the events those programs produced were never read.
	GapKernelRecordUnavailable = "kernel-record-unavailable"
	// GapRingbufUndrained is a kernel record's sample of the run that its final drain did not record: with a
	// count, the samples the drain counted past its budget (internal/runtime/observe); with none, a run whose
	// cgroup still held processes when the drain began, which can produce samples after it (awaitEmpty).
	GapRingbufUndrained = "ringbuf-undrained"
	// GapSourceStopTimeout is a source whose Stop did not return within sourceStopWait at shutdown; the binary
	// field names the source. What it still held is not in the record.
	GapSourceStopTimeout = "source-stop-timeout"
	// GapBudgetUnmetered is a tokens, cost_usd or repeats budget with no model traffic to meter: the run
	// captures nothing (capture off, or the forwarder alone with no models: endpoint, so it never started).
	// The binary field names the budget; it never trips (limits-check-doctor-cli.md R32).
	GapBudgetUnmetered = "budget-unmetered"
	// GapUnmeteredAfterExit is model exchanges capture could not count, reported under a token or cost budget
	// once the run had quiesced (its cgroup empty, or tego's teardown begun): the count says how many. They no
	// longer end the run, which has ended, so the record says what the budget did not see (ADR 0037).
	GapUnmeteredAfterExit = "unmetered-after-exit"
)

// mirrorRefusals writes the `refused` line that mirrors a refused action (spec/record/v1: "mirrors the
// refused action"). The action event stays the primary record and keeps its own verdict; the mirror is
// what a reader scanning for refusals alone finds, and what the ledger turns into last-refusal.json for
// the reason channel. Doing it here means no producer has to remember: every refusal, from any tier or
// source, passes through this one stage.
//
// The mirror is built before the action goes on, and written only if the action's own line was: the ledger's
// stages rewrite the action in place, and splitBlobs had already moved a path over 4 KiB to path_blob, so
// the mirror named no target; and a mirror written after its action was dropped was a refusal with no
// action behind it.
func (p *pipeline) mirrorRefusals(next func(*record.Event)) func(*record.Event) {
	return func(ev *record.Event) {
		if !ev.Kind.IsAction() || ev.Verdict != record.VerdictRefused {
			next(ev)
			return
		}
		// A refused line carries rule and reason in the common fields and nothing else the action had:
		// the schema forbids a verdict, an authority and an attribution on it (pkg/spec/record Validate).
		m := *ev
		m.Kind = record.KindRefused
		m.Verdict = ""
		m.Authority = ""
		m.Attr = nil
		m.ID, m.Prev, m.Seq = "", "", 0 // the writer stamps the mirror as its own line
		m.Payload = refusedPayload(ev)
		written := p.written.Load()
		next(ev)
		if p.written.Load() == written {
			return // the action's line was not written
		}
		next(&m)
	}
}

// refusedPayload names the refused operation and its target, the mechanism that refused it when the action line
// names one (a decision plane's refusal and its mode; a read the Landlock ruleset refused, ADR 0077), and for an exec
// a command rule refused that rule and its match, read from the action's own payload so the mirror says what happened
// without the reader opening the action line.
func refusedPayload(ev *record.Event) json.RawMessage {
	var p struct {
		Op     string `json:"op,omitempty"`
		Path   string `json:"path,omitempty"`
		Dst    string `json:"dst,omitempty"`
		Target string `json:"target,omitempty"`
		// An exec a command rule refused names the rule and how it matched (ADR 0048 (8)). command_list says which
		// list decided; the mirror carries the command rule only when the command rule itself refused (deny, ask or a
		// constrained tool's unlisted invocation), never when it allowed and the gate refused, nor on a sentinel
		// refusal that writes no command_list.
		CommandRule   string `json:"command_rule,omitempty"`
		CommandMatch  string `json:"command_match,omitempty"`
		CommandList   string `json:"command_list,omitempty"`
		Mechanism     string `json:"mechanism,omitempty"`
		DecisionPlane string `json:"decision_plane,omitempty"`
	}
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &p)
	}
	out := record.RefusedPayload{Op: p.Op, Mechanism: p.Mechanism, DecisionPlane: p.DecisionPlane}
	if p.CommandList == "deny" || p.CommandList == "ask" || p.CommandList == "unlisted" {
		out.CommandRule, out.CommandMatch = p.CommandRule, p.CommandMatch
	}
	switch {
	case p.Target != "":
		out.Target = p.Target
	case p.Path != "":
		out.Target = p.Path
	case p.Dst != "":
		out.Target = p.Dst
	}
	if out.Op == "" {
		out.Op = string(ev.Kind)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return b
}

// rememberRequest records the seq an ssl_request's line was given, under its pair token.
func (p *pipeline) rememberRequest(pair, seq uint64) {
	if p.requests == nil {
		p.requests = map[uint64]uint64{}
	}
	if _, ok := p.requests[pair]; !ok {
		p.requestOrder = append(p.requestOrder, pair)
	}
	p.requests[pair] = seq
	for len(p.requestOrder) > maxPendingRequests {
		delete(p.requests, p.requestOrder[0])
		p.requestOrder = p.requestOrder[1:]
	}
}

// forgetRequest takes an answered request's token out of requestOrder as well as out of the map.
// Left there, the order counted answered requests toward maxPendingRequests: a request still waiting was
// evicted once 4096 later requests had been made, however few of them were still waiting, and its response
// lost its request_seq — a long stream beside a busy tool loop.
// Responses come mostly in request order, so the token is looked for from the oldest end.
func (p *pipeline) forgetRequest(pair uint64) {
	for i, t := range p.requestOrder {
		if t == pair {
			p.requestOrder = append(p.requestOrder[:i], p.requestOrder[i+1:]...)
			return
		}
	}
}

// fillRequestSeq gives an ssl_response the seq of its request's line, when that line was written and is
// still remembered; otherwise request_seq stays absent. The field is inserted into the payload object as it
// stands: MarshalLine orders the keys, and re-encoding the whole payload could change how its strings are
// escaped.
func (p *pipeline) fillRequestSeq(ev *record.Event) {
	seq, ok := p.requests[ev.Pair]
	if !ok {
		return
	}
	delete(p.requests, ev.Pair)
	p.forgetRequest(ev.Pair)
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(ev.Payload, &keys); err != nil {
		return
	}
	if _, set := keys["request_seq"]; set {
		return
	}
	field := `"request_seq":` + strconv.FormatUint(seq, 10)
	body := bytes.TrimSpace(ev.Payload)
	if len(body) < 2 || body[0] != '{' {
		return
	}
	inner := bytes.TrimSpace(body[1 : len(body)-1])
	if len(inner) == 0 {
		ev.Payload = json.RawMessage("{" + field + "}")
		return
	}
	ev.Payload = json.RawMessage("{" + field + "," + string(inner) + "}")
}
