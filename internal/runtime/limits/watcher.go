// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TickInterval is how often Run checks the two ceilings no event can announce: wall time and the
// stall gap (R3, R4). One second is the spec's rate; it bounds how far past a ceiling a run may go.
const TickInterval = time.Second

// Sink receives the events this watcher produces: the one limit event of a breach and the price
// gaps of R2/E15. It is satisfied by the runtime facade's own queue, so a limit event takes the same
// pipeline every other event takes — stamped, redacted and appended exactly once — and this package
// never touches the ledger itself.
//
// A sink must not lose the limit event. The facade's queue drops when it is full, and it is full
// exactly when the pipeline is behind, which is when a busy run crosses a budget; so the facade
// hands this watcher a sink that holds a reserved slot for the run's one limit event (I1) and
// drains that slot before its backlog, and trip's promise that the ledger says why the run died
// rests on it.
type Sink interface {
	// Emit hands over one event. It must not block the caller for long.
	Emit(ev *record.Event)
}

// Clock is the run's wall and monotonic time. Only MonoNS decides a budget: a wall clock that NTP
// steps mid-run would otherwise fabricate or hide a wall/stall breach (E7, E27).
type Clock interface {
	Now() time.Time
	MonoNS() uint64
}

// Killer ends every process of a run's cgroup. It is the only effect this package has on the
// world, and cgroup.Manager is its one real implementation: the narrower interface is what keeps a
// budget watcher from reaching for anything else in the manager (§1 "limits never opens a file").
type Killer interface {
	Kill(c cgroup.Cgroup) error
}

// State is the live accumulator of one run. The zero value is a fresh run; Snapshot returns a copy,
// so a reader never races the watcher.
type State struct {
	// TokensIn and TokensOut are the cumulative uncached tokens of every ssl_response (R1).
	TokensIn, TokensOut uint64
	// CacheRead and CacheWrite are the cumulative cache tokens. They count toward cost (R2), never
	// toward the token ceiling (R1).
	CacheRead, CacheWrite uint64
	// CostUSD is the summed per-response estimate; every surface labels it "est." (R2).
	CostUSD float64
	// Unpriced counts responses no price table covered, so a zero cost can be told from a free one.
	Unpriced uint64
	// UnpricedMaxUSD is what the unpriced responses would cost at the table's highest price per counter.
	// Under a cost budget it counts toward the ceiling, never into CostUSD, whose estimate stays the table's
	// own: a model the table does not name is charged as the dearest one it does, so an agent that picks a
	// model the table has not caught up with cannot spend past the budget for free (R2).
	UnpricedMaxUSD float64
	// Responses counts ssl_response events with a usage object.
	Responses uint64
	// StartMonoNS is run_start's mono_ns, or the first event's when a run has no run_start yet.
	StartMonoNS uint64
	// LastEventMonoNS is the last non-gap event's mono_ns: a dropped-event burst must not read as
	// activity (R4).
	LastEventMonoNS uint64
	// RepeatTool and RepeatHash are the last decision's tool and input hash (R5).
	RepeatTool, RepeatHash string
	// RepeatCount is how many consecutive decisions carried that same pair; 0 before the first.
	RepeatCount int
}

// Tokens is the sum the token ceiling is compared against: input plus output, cache excluded (R1).
func (s State) Tokens() uint64 { return ledger.SatAdd(s.TokensIn, s.TokensOut) }

// Breach is one crossed ceiling, as the limit event records it (spec/record/v1: which, value,
// ceiling).
type Breach struct {
	// Which is one of record.LimitTokens, LimitCostUSD, LimitWall, LimitStallAfter, LimitRepeats, LimitLedgerBytes.
	Which string
	// Value is the measured quantity: tokens, USD, seconds for wall and stall_after, bytes for ledger_bytes.
	Value float64
	// Ceiling is the budget Value crossed, in the same unit.
	Ceiling float64
}

// Reason is the limit-* code of the closed reason set that names this breach (I2). The switch is
// exhaustive by construction: an unknown Which returns "" and the event carries no reason rather
// than an invented one, which record.Validate would reject. LimitLedgerBytes is one such: the set has no
// code for it, and its limit line names it in which alone (record.MinorLedgerCap).
func (b Breach) Reason() record.Reason {
	switch b.Which {
	case record.LimitTokens:
		return record.ReasonLimitTokens
	case record.LimitCostUSD:
		return record.ReasonLimitCost
	case record.LimitWall:
		return record.ReasonLimitWall
	case record.LimitStallAfter:
		return record.ReasonLimitStall
	case record.LimitRepeats:
		return record.ReasonLimitRepeats
	}
	return ""
}

// String renders the breach the way the CLI reports it: "which value ceiling".
func (b Breach) String() string {
	return fmt.Sprintf("%s %s over ceiling %s", b.Which, trimFloat(b.Value), trimFloat(b.Ceiling))
}

// Option configures a Watcher at construction. Every option is independent of the others.
type Option func(*Watcher)

// WithLogger gives the watcher somewhere to report a failed kill, which is never swallowed (§7).
func WithLogger(l *slog.Logger) Option {
	return func(w *Watcher) {
		if l != nil {
			w.log = l
		}
	}
}

// WithOnBreach registers the facade's callback, invoked once, under no lock, after the limit event
// is emitted and before the cgroup is killed. It is how the runtime learns that this run's terminal
// reason is `limit`, which its own exit table turns into run_end reason=limit and exit 124: the
// watcher never writes run_end itself (§4 trip).
func WithOnBreach(fn func(Breach)) Option {
	return func(w *Watcher) { w.onBreach = fn }
}

// WithOnUnmetered tells the facade of a response under a cost budget whose spend the price table cannot bound
// (PriceTable.UnfeedServerTool): n exchanges and why, as a capture source reports spend it could not count. The
// facade ends the run there (source.ReportUnmetered). It is called outside the watcher's lock.
func WithOnUnmetered(fn func(n int64, why string)) Option {
	return func(w *Watcher) { w.onUnmetered = fn }
}

// WithPriceGap tells the watcher that the run has already recorded why it has no price table: why
// is limits.GapNoPriceTable or GapVersionMismatch, the reason the caller's FromMachine gave, and ""
// means a table did load. The facade writes that gap once, right after run_start (E15, R32), so
// that a run which never sees a response still says its cost column is empty. Without this
// option the watcher would record no-price-table a second time on the first unpriced response,
// and a version-mismatch run would carry two gaps that give different reasons for one cause.
func WithPriceGap(why string) Option {
	return func(w *Watcher) {
		if why != "" {
			w.gapped[GapNoPriceTable] = true
		}
	}
}

// WithHeld tells the watcher when Tego itself holds the agent: while held
// reports true (a published ask awaiting its human, agent-contract R22) each
// Tick counts as activity for R4's stall check, so the wait, up to the ask
// timeout, is not a stall and the stall clock restarts when it ends. held is
// called outside the watcher's lock and must not call back into it.
func WithHeld(held func() bool) Option {
	return func(w *Watcher) { w.held = held }
}

// WithActivityPublisher hands Run the place to publish the stall check's activity that has no ledger line: a
// Touch or a pulled AddActivity reading, which `tego status` cannot see in the ledger and would otherwise read as
// idle while the watcher does not (limits-check-doctor-cli.md R9). Run calls publish after a Tick that finds no
// breach, outside the lock, at most once per tick and only when the reading rose since the last call. A line is
// never published, since status reads the ledger itself, nor a held tick, since status ranks a pending approval
// on its own.
func WithActivityPublisher(publish func(monoNS uint64)) Option {
	return func(w *Watcher) { w.publish = publish }
}

// WithLedgerCeiling ends the run once size, the bytes of the run's events.jsonl, reaches ceiling: the machine's
// record.max_run_bytes (record.MinorLedgerCap), a limit which=ledger_bytes. size is called outside the watcher's lock,
// at each Observe and each Tick, and must not block for long; a ceiling of 0 or less, or a nil size, is none. Observe
// reads it before the event it observes is written, so a run passes the ceiling by the events its pipeline held
// then; a line written beside the pipeline (run_start, a run with no events) is caught by the next Tick.
func WithLedgerCeiling(ceiling int64, size func() int64) Option {
	return func(w *Watcher) {
		if ceiling > 0 && size != nil {
			w.ledgerCeiling, w.ledgerSize = ceiling, size
		}
	}
}

// Watcher enforces one run's budgets: cumulative tokens, estimated cost, wall time, the stall gap
// and the repeat detector (R1-R6). It is the only P0 component that stops a run for a non-security
// reason, and its whole effect is one limit event plus one Kill.
//
// Observe (or Stage) is driven by the event pipeline; Run drives the clock-only ceilings. Both are
// safe to call concurrently, and at most one limit event is ever produced (I1).
type Watcher struct {
	ceiling agent.ResolvedLimits
	prices  *PriceTable
	mgr     Killer
	cg      cgroup.Cgroup
	sink    Sink
	clock   Clock
	log     *slog.Logger
	tick    time.Duration

	onBreach    func(Breach)
	onUnmetered func(n int64, why string)
	held        func() bool
	publish     func(monoNS uint64)
	// ledgerCeiling and ledgerSize are WithLedgerCeiling's.
	ledgerCeiling int64
	ledgerSize    func() int64
	// activity holds the sources AddActivity added (R4). Tick loads it without the lock, so a run with no
	// source pays one atomic load per tick, not a second critical section; AddActivity replaces the slice
	// under mu rather than appending to the one a Tick may be reading.
	activity atomic.Pointer[[]func() uint64]

	mu      sync.Mutex
	state   State
	tripped bool
	breach  Breach
	// lineless is the newest activity counted without a line (Touch, a pulled reading), and published the
	// reading last handed to publish (WithActivityPublisher).
	lineless, published uint64
	// killPending is a breach's kill that failed on the pipeline goroutine (Observe), where the error has no
	// caller: Run retries it and, if it fails again, returns the error to the run's worker group.
	killPending bool
	gapped      map[string]bool
	// unpricedModels counts the models named in an unpriced-model gap line so far (maxUnpricedModels).
	unpricedModels int
}

// NewWatcher returns a watcher for one run.
//
// ceiling is the contract's budgets after the machine's ceilings were applied by agent.Compile. A
// dimension is enforced when ResolvedLimits.Bounded says it was asked for, not when its number is
// positive: an explicit ceiling of 0 is the tightest budget there is, and reading it as unbounded
// would hand a run that asked for nothing a run with no budget at all (E16). prices may be nil, which
// disables cost breaches and records the no-price-table gap once (E15). mgr and cg are the run's
// cgroup, sink the pipeline the limit event flows through, clk the run's monotonic clock.
//
// It does no I/O and cannot fail.
func NewWatcher(ceiling agent.ResolvedLimits, prices *PriceTable, mgr Killer, cg cgroup.Cgroup, clk Clock, sink Sink, opts ...Option) *Watcher {
	w := &Watcher{
		ceiling: ceiling,
		prices:  prices,
		mgr:     mgr,
		cg:      cg,
		sink:    sink,
		clock:   clk,
		log:     slog.New(slog.DiscardHandler),
		tick:    TickInterval,
		gapped:  make(map[string]bool, 4),
	}
	for _, o := range opts {
		o(w)
	}
	return w
}

// Stage is the watcher as one pipeline middleware step: it observes the event, then passes it on
// unchanged. Its type matches the facade's Stage, so a run wires the watcher in with one Compose
// entry and no second event path exists.
func (w *Watcher) Stage(next func(*record.Event)) func(*record.Event) {
	return func(ev *record.Event) {
		w.Observe(ev)
		next(ev)
	}
}

// Observe updates the run's accumulators from one event and trips the budgets an event can cross:
// tokens (R1), cost (R2) and repeats (R5). It never blocks, never errors and never decides a
// verdict; a payload it cannot decode simply contributes nothing.
func (w *Watcher) Observe(ev *record.Event) {
	if ev == nil {
		return
	}
	// The ledger's size is read before the lock, as Tick reads it: the event before this one is on disk by now, so a
	// busy run is ended within a pipeline's backlog of its ceiling, not a second's writing.
	var ledgerBytes int64
	if w.ledgerSize != nil {
		ledgerBytes = w.ledgerSize()
	}
	w.mu.Lock()
	gaps, b := w.observeLocked(ev, ledgerBytes)
	if b != nil && w.mgr != nil {
		// Pending from the moment tripped is set, under the same lock: a Run that starts while trip is
		// still in flight, or before it, must see a kill owed and stay, not return on tripped alone.
		w.killPending = true
	}
	w.mu.Unlock()

	for _, g := range gaps {
		if g.unmetered {
			if w.onUnmetered != nil {
				w.onUnmetered(1, g.why)
			}
			continue
		}
		w.emitGap(g.why, g.model)
	}
	if b != nil {
		// Observe runs on the pipeline goroutine and must not block it: the kill is a single write
		// to cgroup.kill, which the kernel answers without waiting for the processes to die.
		if err := w.trip(*b); err != nil {
			w.log.Error("limits: kill after breach", "which", b.Which, "err", err)
		} else if w.mgr != nil {
			w.mu.Lock()
			w.killPending = false
			w.mu.Unlock()
		}
	}
}

// Touch records activity the ledger does not carry, for R5's stall check: under record: off the producers
// keep only refusals, so an agent busy with allowed work reached no Observe and was killed for stalling
// (R4). monoNS is a CLOCK_MONOTONIC reading, as an event's mono_ns is.
func (w *Watcher) Touch(monoNS uint64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.state.StartMonoNS == 0 && monoNS > 0 {
		w.state.StartMonoNS = monoNS
	}
	if monoNS > w.state.LastEventMonoNS {
		w.state.LastEventMonoNS = monoNS
	}
	w.lineless = max(w.lineless, monoNS)
}

// AddActivity adds a source of activity the ledger does not carry and nothing pushes, which Tick pulls before
// its stall check (R4): fn returns the CLOCK_MONOTONIC reading of the run's latest activity, as an event's
// mono_ns is, or 0 for none. It is how a stamp the kernel keeps per run (a map value, not a ring sample) counts
// without a line and without a wakeup per action.
//
// A reading raises LastEventMonoNS as Touch does, never lowers it, and is ignored below the run's monotonic
// origin (StartMonoNS) and before there is one: such a value is a previous holder's of the same slot, not this
// run's. A reading past the clock's own is clamped to it, so a bogus value cannot hold the stall window open
// beyond one stall_after. fn is called outside the watcher's lock, once per Tick, and must not block. Sources
// are added before Run.
func (w *Watcher) AddActivity(fn func() uint64) {
	if fn == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	var sources []func() uint64
	if old := w.activity.Load(); old != nil {
		sources = append(sources, *old...)
	}
	sources = append(sources, fn)
	w.activity.Store(&sources)
}

// pullActivity is the newest reading of AddActivity's sources, called outside w.mu.
func (w *Watcher) pullActivity() uint64 {
	sources := w.activity.Load()
	if sources == nil {
		return 0
	}
	var latest uint64
	for _, fn := range *sources {
		latest = max(latest, fn())
	}
	return latest
}

// gapRequest is one gap event observeLocked decided on but could not emit while holding the lock.
type gapRequest struct {
	why   string
	model string
	// unmetered makes it a report to onUnmetered, with why its detail, instead of a gap.
	unmetered bool
}

// observeLocked applies R1-R5 to one event and reports the gaps to emit and the breach to trip, if
// any. w.mu must be held; nothing here emits, kills or blocks.
func (w *Watcher) observeLocked(ev *record.Event, ledgerBytes int64) ([]gapRequest, *Breach) {
	if w.state.StartMonoNS == 0 && ev.MonoNS > 0 {
		w.state.StartMonoNS = ev.MonoNS
	}
	// R4: a gap is the record admitting it lost events, not evidence the agent did anything.
	if ev.Kind != record.KindGap && ev.MonoNS > w.state.LastEventMonoNS {
		w.state.LastEventMonoNS = ev.MonoNS
	}

	var gaps []gapRequest
	switch ev.Kind {
	case record.KindSSLResponse:
		gaps = w.usageLocked(ev)
	case record.KindDecision:
		w.decisionLocked(ev)
	}
	if w.tripped {
		return gaps, nil
	}
	var b *Breach
	switch ev.Kind {
	case record.KindSSLResponse:
		b = w.tokenBreachLocked()
		if b == nil {
			b = w.costBreachLocked()
		}
	case record.KindDecision:
		b = w.repeatBreachLocked()
	}
	if b == nil {
		b = w.ledgerBreachLocked(ledgerBytes)
	}
	if b != nil {
		w.tripped, w.breach = true, *b
	}
	return gaps, b
}

// usageLocked applies R1 and R2 to one ssl_response. The decode is ledger.Usage, the one measure
// uses too (§4, I5), and it clamps a negative count to 0 so a malformed reply can neither underflow a
// total nor fabricate a breach. A response with no usage object (a streamed error, an unparsed body)
// contributes nothing but its timestamp — decision: unparsed events are the same case (E14).
func (w *Watcher) usageLocked(ev *record.Event) []gapRequest {
	u, ok := ledger.Usage(ev)
	if !ok {
		return nil
	}
	w.state.Responses++
	w.state.TokensIn = ledger.SatAdd(w.state.TokensIn, u.In)
	w.state.TokensOut = ledger.SatAdd(w.state.TokensOut, u.Out)
	w.state.CacheRead = ledger.SatAdd(w.state.CacheRead, u.CacheRead)
	w.state.CacheWrite = ledger.SatAdd(w.state.CacheWrite, u.CacheWrite)

	cost, priced := w.prices.Cost(u)
	if priced {
		w.state.CostUSD += cost
		return nil
	}
	w.state.Unpriced++
	var out []gapRequest
	if w.ceiling.Bounded(agent.BudgetCostUSD) {
		if c, ok := w.prices.MaxCost(u); ok {
			w.state.UnpricedMaxUSD += c
		} else if w.prices.UnfeedServerTool(u) {
			// No fee bounds these requests, and charging them $0 would let a cost ceiling pass unseen spend: the
			// response is unmetered, as a capture source's unreadable one is (ADR 0037 amendment 2026-09-24).
			out = append(out, gapRequest{unmetered: true,
				why: "server-tool requests with no server_tool_per_request fee in the price table"})
		} else if w.prices != nil && len(w.prices.Models) > 0 {
			// The table names models but prices none of them (every entry lacks an input or output price): no
			// bound exists, and passing the response at $0 would leave the ceiling unenforced without a word.
			out = append(out, gapRequest{unmetered: true, why: "price table prices no model"})
		}
	}
	return append(w.unpricedGapLocked(u), out...)
}

// unpricedGapLocked is the gap, at most once per reason and model, that an unpriced response records.
func (w *Watcher) unpricedGapLocked(u ledger.TokenUsage) []gapRequest {
	switch {
	case w.prices == nil || len(w.prices.Models) == 0:
		if w.markGapLocked(GapNoPriceTable) {
			return []gapRequest{{why: GapNoPriceTable}}
		}
	case w.unpricedModels >= maxUnpricedModels:
		// The response names a model after the first maxUnpricedModels: its model is not kept, and one gap
		// line without a model says that more went unpriced. The agent chooses usage.model, and every
		// distinct name added a map entry and a ledger line without end (R2).
		if w.markGapLocked(GapUnpricedModel + "\x00") {
			return []gapRequest{{why: GapUnpricedModel}}
		}
	default:
		if w.markGapLocked(GapUnpricedModel + "\x00" + u.Model) {
			w.unpricedModels++
			return []gapRequest{{why: GapUnpricedModel, model: u.Model}}
		}
	}
	return nil
}

// maxUnpricedModels is how many distinct unpriced models a run names in its own gap line each (usageLocked).
const maxUnpricedModels = 32

// decisionLocked applies R5's repeat detector: the streak is over the consecutive (tool, input
// hash) pairs of tool-calling decisions. A text-only or unparsed decision carries no tool and
// leaves the streak alone rather than breaking it — a model that narrates between two identical
// calls is still looping. An empty input hash is a value like any other (E13).
func (w *Watcher) decisionLocked(ev *record.Event) {
	var p record.DecisionPayload
	if err := ev.DecodePayload(&p); err != nil || p.Tool == "" {
		return
	}
	if w.state.RepeatCount > 0 && p.Tool == w.state.RepeatTool && p.InputHash == w.state.RepeatHash {
		w.state.RepeatCount++
		return
	}
	w.state.RepeatTool, w.state.RepeatHash, w.state.RepeatCount = p.Tool, p.InputHash, 1
}

// tokenBreachLocked is R1: input plus output over the ceiling, cache excluded.
func (w *Watcher) tokenBreachLocked() *Breach {
	if !w.ceiling.Bounded(agent.BudgetTokens) {
		return nil
	}
	// A negative ceiling would convert into an enormous uint64 and waive the budget it asked for;
	// there is no budget below zero, so it is one.
	ceiling := max(w.ceiling.Tokens, 0)
	if got := w.state.Tokens(); got > uint64(ceiling) {
		return &Breach{Which: record.LimitTokens, Value: float64(got), Ceiling: float64(ceiling)}
	}
	return nil
}

// costBreachLocked is R2: the running estimate over the ceiling, the unpriced responses charged at the table's
// highest prices (UnpricedMaxUSD).
func (w *Watcher) costBreachLocked() *Breach {
	if !w.ceiling.Bounded(agent.BudgetCostUSD) {
		return nil
	}
	ceiling := max(w.ceiling.CostUSD, 0)
	if cost := w.state.CostUSD + w.state.UnpricedMaxUSD; cost > ceiling {
		return &Breach{Which: record.LimitCostUSD, Value: cost, Ceiling: ceiling}
	}
	return nil
}

// repeatBreachLocked is R5: the current streak at or above the ceiling. The comparison is >=, not
// >, because the ceiling names how many identical calls in a row are already too many.
//
// The streak has to be non-zero as well: a ceiling of 0 means no repeated tool call is tolerated, and
// the check runs on every decision event, including the ones that carry no tool_use at all and so have
// no streak to judge.
func (w *Watcher) repeatBreachLocked() *Breach {
	if !w.ceiling.Bounded(agent.BudgetRepeats) {
		return nil
	}
	ceiling := max(w.ceiling.Repeats, 0)
	if w.state.RepeatCount > 0 && w.state.RepeatCount >= ceiling {
		return &Breach{Which: record.LimitRepeats, Value: float64(w.state.RepeatCount), Ceiling: float64(ceiling)}
	}
	return nil
}

// Tick checks the two ceilings only the clock can cross — wall time (R3) and the stall gap (R4) —
// and trips the first one crossed. It returns a non-nil Breach exactly on the tick that crosses,
// nil on every later call (R6, I1).
//
// A Kill that fails is wrapped and returned, never swallowed: the limit event is appended either
// way, because the ceiling was in fact crossed (§7). The context is not consulted: the one effect
// Tick has is cgroup.kill, a single write(2) that does not block, and Run's loop is what the
// context bounds.
func (w *Watcher) Tick(context.Context) (*Breach, error) {
	held := w.held != nil && w.held()
	// The pulled activity is read before the clock, so a stamp the source took before this Tick is never
	// later than now; one that is anyway (another clock, a bogus value) is clamped to now (AddActivity).
	pulled := w.pullActivity()
	var ledgerBytes int64
	if w.ledgerSize != nil {
		ledgerBytes = w.ledgerSize()
	}
	w.mu.Lock()
	now := w.clock.MonoNS()
	if held && w.state.StartMonoNS != 0 && now > w.state.LastEventMonoNS {
		w.state.LastEventMonoNS = now
	}
	if pulled = min(pulled, now); w.state.StartMonoNS != 0 && pulled >= w.state.StartMonoNS {
		w.state.LastEventMonoNS = max(w.state.LastEventMonoNS, pulled)
		w.lineless = max(w.lineless, pulled)
	}
	b := w.tickLocked(now, ledgerBytes)
	w.mu.Unlock()
	if b == nil {
		return nil, nil
	}
	return b, w.trip(*b)
}

// ledgerBreachLocked is the ledger_bytes breach of a ledger that holds ledgerBytes, nil under the ceiling or with none
// (WithLedgerCeiling). w.mu must be held.
func (w *Watcher) ledgerBreachLocked(ledgerBytes int64) *Breach {
	if w.ledgerCeiling <= 0 || ledgerBytes < w.ledgerCeiling {
		return nil
	}
	return &Breach{Which: record.LimitLedgerBytes, Value: float64(ledgerBytes), Ceiling: float64(w.ledgerCeiling)}
}

// tickLocked decides the wall, stall and ledger size breaches at now, ledgerBytes the size read for this Tick. w.mu
// must be held.
func (w *Watcher) tickLocked(now uint64, ledgerBytes int64) *Breach {
	if w.tripped || w.state.StartMonoNS == 0 {
		// Before run_start there is no monotonic origin, so neither ceiling has a meaning yet.
		return nil
	}
	var b *Breach
	if w.ceiling.Bounded(agent.BudgetWall) && now > w.state.StartMonoNS {
		d := max(w.ceiling.Wall, 0)
		if elapsed := now - w.state.StartMonoNS; elapsed > uint64(d.Nanoseconds()) {
			b = &Breach{Which: record.LimitWall, Value: seconds(elapsed), Ceiling: d.Seconds()}
		}
	}
	if b == nil && w.ceiling.Bounded(agent.BudgetStallAfter) && w.state.LastEventMonoNS > 0 && now > w.state.LastEventMonoNS {
		d := max(w.ceiling.StallAfter, 0)
		if idle := now - w.state.LastEventMonoNS; idle > uint64(d.Nanoseconds()) {
			b = &Breach{Which: record.LimitStallAfter, Value: seconds(idle), Ceiling: d.Seconds()}
		}
	}
	if b == nil {
		b = w.ledgerBreachLocked(ledgerBytes)
	}
	if b != nil {
		w.tripped, w.breach = true, *b
	}
	return b
}

// Run is the watcher's one goroutine: it ticks until the context ends or a budget trips, and is
// started by the run's worker group so shutdown joins it like every other worker (C3).
//
// It returns nil when the context ends or after a clean trip — including at once when a budget has
// already tripped, since nothing is left to watch — and the wrapped kill error when the cgroup
// could not be killed, a failure the run must not continue past silently.
func (w *Watcher) Run(ctx context.Context) error {
	if _, tripped := w.Tripped(); tripped && !w.pendingKill() {
		return nil
	}
	t := time.NewTicker(w.tick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if err := w.retryKill(); err != nil {
				return err
			}
			b, err := w.Tick(ctx)
			if err != nil {
				return err
			}
			if b != nil {
				return nil
			}
			w.publishActivity()
		}
	}
}

// publishActivity hands WithActivityPublisher's callback the activity counted without a line, when it rose since
// the last call. It runs on Run's goroutine only.
func (w *Watcher) publishActivity() {
	if w.publish == nil {
		return
	}
	w.mu.Lock()
	v := w.lineless
	fresh := v > w.published
	if fresh {
		w.published = v
	}
	w.mu.Unlock()
	if fresh {
		w.publish(v)
	}
}

func (w *Watcher) pendingKill() bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.killPending
}

// retryKill repeats the kill of a breach Observe raised and could not carry out. A failure is returned, so
// the run's worker group ends and awaitExit's own kill of the cgroup follows: a run past its ceiling is never
// left running because the one write that ends it failed (§7).
func (w *Watcher) retryKill() error {
	w.mu.Lock()
	pending, b := w.killPending, w.breach
	w.mu.Unlock()
	if !pending || w.mgr == nil {
		return nil
	}
	if err := w.mgr.Kill(w.cg); err != nil {
		return fmt.Errorf("limits: kill %s after %s: %w", w.cg.Path, b.Which, err)
	}
	w.mu.Lock()
	w.killPending = false
	w.mu.Unlock()
	return nil
}

// trip is the one path from a crossed ceiling to a stopped run (§4): it appends the limit event,
// tells the facade the run's terminal reason is `limit`, then kills the cgroup. The event goes
// first so a reader of the ledger always finds why the run died, even if the kill fails; the
// callback goes before the kill so the facade's reason is set before the child's exit is observed.
// run_end is never written here — that is the facade's, on the cgroup's populated=0 transition.
func (w *Watcher) trip(b Breach) error {
	w.emitLimit(b)
	if w.onBreach != nil {
		w.onBreach(b)
	}
	if w.mgr == nil {
		return nil
	}
	if err := w.mgr.Kill(w.cg); err != nil {
		return fmt.Errorf("limits: kill %s after %s: %w", w.cg.Path, b.Which, err)
	}
	return nil
}

// emitLimit appends the run's one limit event (I1).
func (w *Watcher) emitLimit(b Breach) {
	if w.sink == nil {
		return
	}
	ev := &record.Event{Kind: record.KindLimit, Source: record.SourceSupervisor, Reason: b.Reason()}
	// A cost that overflowed to +Inf (an absurd but finite price) is not JSON: record it clamped, so the run's
	// death is never left without its limit event (I1).
	value := min(b.Value, math.MaxFloat64)
	if err := ev.SetPayload(record.LimitPayload{Which: b.Which, Value: value, Ceiling: b.Ceiling}); err != nil {
		w.log.Error("limits: limit payload", "which", b.Which, "err", err)
		return
	}
	w.sink.Emit(ev)
}

// emitGap records once that a response could not be priced (R2, E15): the whole table is missing,
// or this model is not in it. Cost is the only measurement affected; the run continues.
func (w *Watcher) emitGap(why, model string) {
	if w.sink == nil {
		return
	}
	ev := &record.Event{Kind: record.KindGap, Source: record.SourceSupervisor}
	if err := ev.SetPayload(record.GapPayload{What: record.GapRecord, Why: why, Binary: model}); err != nil {
		w.log.Error("limits: gap payload", "why", why, "err", err)
		return
	}
	w.sink.Emit(ev)
}

// markGapLocked reports whether key is being recorded for the first time this run. w.mu must be held.
func (w *Watcher) markGapLocked(key string) bool {
	if w.gapped[key] {
		return false
	}
	w.gapped[key] = true
	return true
}

// Snapshot copies the live accumulator, for tests only (no production caller; run_end carries no limits state). It takes the
// same lock the pipeline does, so it is safe at any time.
func (w *Watcher) Snapshot() State {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.state
}

// Tripped reports the breach that stopped this run, if one did. It is the facade's way to ask after
// the fact, without a callback.
func (w *Watcher) Tripped() (Breach, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.breach, w.tripped
}

// seconds converts a monotonic nanosecond span to the seconds a wall or stall breach reports.
func seconds(ns uint64) float64 { return float64(ns) / float64(time.Second) }

// trimFloat renders a breach value without a trailing ".00" on whole numbers, so a token count
// reads as 60420 and a cost as 25.01.
func trimFloat(v float64) string {
	if v == float64(int64(v)) {
		return fmt.Sprintf("%d", int64(v))
	}
	return fmt.Sprintf("%.2f", v)
}
