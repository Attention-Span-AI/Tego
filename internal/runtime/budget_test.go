// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/limits"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// stepClock is a monotonic clock the test moves by hand, so a budget's arithmetic is exact rather
// than a race against the machine's own.
type stepClock struct{ mono atomic.Uint64 }

func (c *stepClock) Now() time.Time          { return time.Unix(0, int64(c.mono.Load())).UTC() }
func (c *stepClock) MonoNS() uint64          { return c.mono.Load() }
func (c *stepClock) advance(d time.Duration) { c.mono.Add(uint64(d.Nanoseconds())) }

// sslResponse is one ssl_response carrying a usage object and a credential header, the two things
// the budget stage's position in the chain is about: the usage must still be there when the watcher
// reads it, the header must be gone by the time the ledger does.
func sslResponse(t *testing.T, in, out int) *record.Event {
	t.Helper()
	ev := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder}
	if err := ev.SetPayload(record.SSLResponsePayload{
		Status: 200, Model: "claude-sonnet-4-5-20250929", ParserVersion: "1",
		Usage:   &record.Usage{Input: in, Output: out},
		Headers: map[string]string{"x-api-key": "sk-secret", "request-id": "req_1"},
	}); err != nil {
		t.Fatal(err)
	}
	return ev
}

// TestBudgetStageSitsAfterTheStampAndBeforeTheLedgersOwnStages pins the position newPipeline gives
// the budget watcher: after stampRule and attribute, so it only ever sees a complete event; before
// mirrorRefusals, so one refused action is one piece of activity and not two; and before
// RedactStage — and therefore before SplitBlobsStage, which Compose places after it — so R1 and R2
// read the usage object the producer actually wrote.
func TestBudgetStageSitsAfterTheStampAndBeforeTheLedgersOwnStages(t *testing.T) {
	var seen []*record.Event
	recorder := func(next func(*record.Event)) func(*record.Event) {
		return func(ev *record.Event) {
			clone := *ev
			seen = append(seen, &clone)
			next(ev)
		}
	}
	sink := &collectSink{}
	p := newPipeline(NewQueue(8), sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 11, TID: 12, Cgroup: 99}, nil, recorder, slog.New(slog.DiscardHandler))

	p.handle(&record.Event{Kind: record.KindFS, Source: record.SourceSeccomp,
		Verdict: record.VerdictRefused, Reason: record.ReasonWriteOutsideContract})
	if len(seen) != 1 {
		t.Fatalf("the budget position saw %d events for one refused action, want 1", len(seen))
	}
	if got := seen[0]; got.Rule != UnmatchedRule || got.Verdict != record.VerdictRefused || got.Attr == nil ||
		got.PID != 11 || got.Cgroup != 99 {
		t.Fatalf("the budget position saw an unstamped event: %+v", got)
	}
	if n := sink.count(); n != 2 {
		t.Fatalf("%d events reached the ledger, want the action and its refused mirror", n)
	}

	p.handle(sslResponse(t, 10, 20))
	if len(seen) != 2 {
		t.Fatalf("the budget position saw %d events, want 2", len(seen))
	}
	if !strings.Contains(string(seen[1].Payload), "x-api-key") {
		t.Fatal("the budget watcher must see the payload before redaction rewrites it")
	}
	written := sink.all()
	if last := written[len(written)-1]; strings.Contains(string(last.Payload), "x-api-key") {
		t.Fatalf("redaction did not run after the budget stage: %s", last.Payload)
	}
}

// TestBudgetStageStampsTheMonotonicReadingTheWatcherNeeds covers why the stage exists at all:
// ledger.Writer.Append fills a blank mono_ns only at write time, after every stage, and supervisor.Loop
// leaves it blank, so without this the watcher would read every event as time zero and R3's wall
// ceiling and R4's stall gap could never fire. A producer that has its own reading keeps it.
func TestBudgetStageStampsTheMonotonicReadingTheWatcherNeeds(t *testing.T) {
	clk := &stepClock{}
	clk.advance(5 * time.Second)
	w := limits.NewWatcher(agent.ResolvedLimits{}, nil, nil, cgroup.Cgroup{}, clk, NewQueue(4))
	var wrote int
	h := budgets(w, clk)(func(*record.Event) { wrote++ })

	blank := sslResponse(t, 10, 20)
	h(blank)
	if blank.MonoNS != uint64(5*time.Second) {
		t.Fatalf("mono_ns %d, want the run's clock reading", blank.MonoNS)
	}
	if got := w.Snapshot(); got.Tokens() != 30 || got.StartMonoNS != uint64(5*time.Second) {
		t.Fatalf("the watcher accumulated %+v", got)
	}

	clk.advance(time.Second)
	own := sslResponse(t, 1, 1)
	own.MonoNS = 42
	h(own)
	if own.MonoNS != 42 {
		t.Fatalf("mono_ns %d, want the producer's own reading kept", own.MonoNS)
	}
	if wrote != 2 {
		t.Fatalf("%d events passed on, want 2: the watcher never drops one", wrote)
	}
}

// budgetRunner is a runner wired exactly as startWorkers wires one — watcher, queue and pipeline —
// over a collecting terminal, so the breach path can be driven without a child process.
func budgetRunner(t *testing.T, l agent.ResolvedLimits) (*runner, *fakeCgroups, *collectSink, *stepClock) {
	t.Helper()
	return pricedBudgetRunner(t, l, nil)
}

// pricedBudgetRunner is budgetRunner with prices as the run's price table.
func pricedBudgetRunner(t *testing.T, l agent.ResolvedLimits, prices *limits.PriceTable) (*runner, *fakeCgroups, *collectSink, *stepClock) {
	t.Helper()
	clk := &stepClock{}
	clk.advance(time.Second)
	cgroups := &fakeCgroups{root: t.TempDir()}
	r := &runner{
		log:   slog.New(slog.DiscardHandler),
		rt:    &agent.RuleTable{Contract: &agent.Contract{Name: "budget"}, Limits: l},
		deps:  Deps{Clock: clk, Prices: prices},
		cgm:   cgroups,
		cg:    cgroup.Cgroup{Path: cgroups.root, ID: 4242},
		queue: NewQueue(16),
	}
	r.newBudget()
	sink := &collectSink{}
	r.pipe = newPipeline(r.queue, sink.append, ledger.RedactStage, passthroughStage,
		runStamp{PID: 11, TID: 12, Cgroup: 4242}, nil, budgets(r.budget, clk), slog.New(slog.DiscardHandler))
	r.startBudgetClock()
	return r, cgroups, sink, clk
}

// TestATokenBreachEndsTheRunWithLimitAndExit124 is the acceptance at the facade's own level:
// the ceiling is crossed on the pipeline goroutine, WithOnBreach makes the run's terminal reason
// `limit`, the watcher's limit event takes the run's own queue back through the chain, the cgroup
// is killed once, and the exit table turns the reason into 124 (§4 trip, §7).
func TestATokenBreachEndsTheRunWithLimitAndExit124(t *testing.T) {
	r, cgroups, sink, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 100})

	r.pipe.handle(sslResponse(t, 40, 20))
	if r.terminal != "" {
		t.Fatalf("60 tokens under a ceiling of 100 ended the run as %q", r.terminal)
	}
	r.pipe.handle(sslResponse(t, 40, 20))
	if r.terminal != identity.ReasonLimit {
		t.Fatalf("terminal reason %q, want limit", r.terminal)
	}
	if cgroups.killed != 1 {
		t.Fatalf("the cgroup was killed %d times, want exactly one cgroup.kill", cgroups.killed)
	}
	r.pipe.drain() // the limit event was queued from inside the stage, as a real run queues it

	var lim *record.Event
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			if lim != nil {
				t.Fatal("two limit events for one run (I1)")
			}
			lim = ev
		}
	}
	if lim == nil {
		t.Fatal("no limit event reached the ledger")
	}
	if lim.Reason != record.ReasonLimitTokens || lim.Cgroup != 4242 {
		t.Fatalf("limit event %+v: want reason limit-tokens, stamped with the run's cgroup", lim)
	}
	var p record.LimitPayload
	if err := lim.DecodePayload(&p); err != nil {
		t.Fatal(err)
	}
	if p.Which != record.LimitTokens || p.Value != 120 || p.Ceiling != 100 {
		t.Fatalf("limit payload %+v, want tokens 120 over 100", p)
	}
	reason, code, _, _ := r.ending()
	if reason != identity.ReasonLimit || code != identity.ExitLimit {
		t.Fatalf("the run ended %q/%d, want limit/124", reason, code)
	}
}

// TestAnUnbudgetedRunIsNeverStopped is the other half: the same wiring, no ceilings, nothing trips.
func TestAnUnbudgetedRunIsNeverStopped(t *testing.T) {
	r, cgroups, sink, clk := budgetRunner(t, agent.ResolvedLimits{})
	for range 5 {
		clk.advance(time.Hour)
		r.pipe.handle(sslResponse(t, 1_000_000, 1_000_000))
	}
	r.pipe.drain()
	if r.terminal != "" || cgroups.killed != 0 {
		t.Fatalf("an unbudgeted run was stopped as %q after %d kills", r.terminal, cgroups.killed)
	}
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			t.Fatal("an unbudgeted run wrote a limit event")
		}
	}
}

// TestTheWallCeilingTripsFromTheWatchersOwnGoroutine covers the clock-only half of the wiring: the
// origin startBudgetClock seeded, the ticker started as a member of the run's group, and the same
// breach path from Tick (R3).
func TestTheWallCeilingTripsFromTheWatchersOwnGoroutine(t *testing.T) {
	r, cgroups, _, clk := budgetRunner(t, agent.ResolvedLimits{Wall: 30 * time.Second})
	clk.advance(31 * time.Second)
	if _, err := r.budget.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if r.terminal != identity.ReasonLimit || cgroups.killed != 1 {
		t.Fatalf("a crossed wall ceiling left the run %q after %d kills", r.terminal, cgroups.killed)
	}
}

// TestTheFirstTerminalReasonStands: three workers can decide a run's ending, and the one that got
// there first is the cause — a later decision is its consequence.
func TestTheFirstTerminalReasonStands(t *testing.T) {
	r := &runner{}
	if !r.setTerminal(identity.ReasonLimit) {
		t.Fatal("the first decision must be recorded")
	}
	if r.setTerminal(identity.ReasonOOM) {
		t.Fatal("a second decision must not win")
	}
	if r.terminal != identity.ReasonLimit {
		t.Fatalf("terminal %q, want limit", r.terminal)
	}
}

// TestAMissingPriceTableIsRecordedAsAGap is §7's last budget row: a table this binary has not got
// is a gap and a warning, never a failed run. The gap is written whether or not the run ever sees a
// response, because what it says is that no cost ceiling could be enforced at all (E15, R32).
func TestAMissingPriceTableIsRecordedAsAGap(t *testing.T) {
	q := NewQueue(4)
	r := &runner{log: slog.New(slog.DiscardHandler), queue: q,
		deps: Deps{PriceGap: limits.GapNoPriceTable}}
	r.emitPriceGap()
	select {
	case ev := <-q.C():
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if ev.Kind != record.KindGap || p.What != record.GapRecord || p.Why != limits.GapNoPriceTable {
			t.Fatalf("event %s payload %+v, want gap what=record why=no-price-table", ev.Kind, p)
		}
	default:
		t.Fatal("no gap was recorded for a missing price table")
	}

	priced := &runner{log: slog.New(slog.DiscardHandler), queue: NewQueue(4)}
	priced.emitPriceGap()
	select {
	case ev := <-priced.queue.C():
		t.Fatalf("a run with a price table recorded %s", ev.Kind)
	default:
	}
}

// TestABreachFoundWhileDrainingStillReachesRunEnd covers the shutdown ordering: the queue can still
// be holding a response when the workers stop, so the drain runs before the ending is decided. A
// limit event in the ledger whose run_end said the agent simply exited would be a record that
// contradicts itself.
func TestABreachFoundWhileDrainingStillReachesRunEnd(t *testing.T) {
	r, cgroups, sink, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 100})
	for range 3 {
		r.queue.Emit(sslResponse(t, 60, 0))
	}
	if r.terminal != "" {
		t.Fatal("a queued event decides nothing until the pipeline reads it")
	}
	r.pipe.drain()
	reason, code, _, _ := r.ending()
	if reason != identity.ReasonLimit || code != identity.ExitLimit {
		t.Fatalf("the run ended %q/%d, want limit/124", reason, code)
	}
	if cgroups.killed != 1 {
		t.Fatalf("the cgroup was killed %d times, want one", cgroups.killed)
	}
	var limits int
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			limits++
		}
	}
	if limits != 1 {
		t.Fatalf("%d limit events reached the ledger, want exactly one (I1)", limits)
	}
}

type nopSignaler struct{}

func (nopSignaler) Signal(syscall.Signal) error { return nil }

type nopKiller struct{}

func (nopKiller) Kill() error { return nil }

// stopHandler is a signal handler whose stop marker is always present, as after a `tego stop`.
func stopHandler(t *testing.T) *launch.SignalHandler {
	t.Helper()
	h, err := launch.NewSignalHandler(nopSignaler{}, nopKiller{}, launch.SignalPolicy{
		StopGrace: time.Hour, StopRequested: func() bool { return true }})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// TestALimitTripAndAnOperatorStopAreIndependentDecisions is limits-check-doctor-cli.md E25: the breach and
// the stop are separate booleans (the runner's terminal reason and the signal handler's outcome), neither
// consulting the other, and run_end reads the breach first, so a run both stopped and over budget ends
// as limit (exit 124) in whichever order the two arrived.
func TestALimitTripAndAnOperatorStopAreIndependentDecisions(t *testing.T) {
	for _, stopFirst := range []bool{true, false} {
		h := stopHandler(t)
		r := &runner{signals: h}
		r.wait.Status = syscall.WaitStatus(uint32(syscall.SIGKILL)) // the cgroup kill both paths end in
		if stopFirst {
			h.Handle(syscall.SIGTERM)
		}
		r.log = slog.New(slog.DiscardHandler)
		r.onBreach(limits.Breach{})
		if !stopFirst {
			h.Handle(syscall.SIGTERM)
		}
		if o := h.Outcome(); !o.Stopped {
			t.Fatalf("stopFirst=%v: the stop was not recorded as one: %+v", stopFirst, o)
		}
		reason, code, _, _ := r.ending()
		if reason != identity.ReasonLimit || code != 124 {
			t.Errorf("stopFirst=%v: ended %q exit %d, want limit and 124", stopFirst, reason, code)
		}
	}
	// The stop alone still reads as a stop: the breach flag is not implied by the kill.
	h := stopHandler(t)
	r := &runner{signals: h}
	h.Handle(syscall.SIGTERM)
	if reason, _, _, _ := r.ending(); reason != identity.ReasonStopped {
		t.Errorf("a stop with no breach ended %q, want stopped", reason)
	}
}
