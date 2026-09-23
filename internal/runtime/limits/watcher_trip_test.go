// SPDX-License-Identifier: Apache-2.0

package limits

import (
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUsageCountersNeverUnderflow pins R1 (and, by the same accumulator, R2's cache-priced fields):
// a writer's usage counters are a signed `int` on the wire (pkg/spec/record.Usage), so nothing stops
// a buggy or hostile writer from sending a negative one. ledger.Usage's clamp is the only thing
// standing between that and an unsigned underflow: uint64(int(-1)) wraps to about 1.8e19, which
// would both corrupt every later measurement and fabricate an instant token-ceiling breach out of a
// single-digit response. Every existing test only ever feeds non-negative usage, so this clamp had
// no test proving it does anything.
func TestUsageCountersNeverUnderflow(t *testing.T) {
	const model = "claude-sonnet-4-5-20250929"
	tests := []struct {
		name                                 string
		in, out, cacheRead, cacheWrite       int
		wantIn, wantOut, wantRead, wantWrite uint64
	}{
		{name: "negative input clamps to zero", in: -5, out: 10, wantIn: 0, wantOut: 10},
		{name: "negative output clamps to zero", in: 10, out: -5, wantIn: 10, wantOut: 0},
		{name: "negative cache read clamps to zero", cacheRead: -5, wantRead: 0},
		{name: "negative cache write clamps to zero", cacheWrite: -5, wantWrite: 0},
		{name: "every counter negative clamps every field", in: -1, out: -1, cacheRead: -1, cacheWrite: -1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// A ceiling low enough that an unclamped underflow (~1.8e19 tokens) would trip it, but
			// any correctly-clamped result (well under 100) never does.
			w, _, killer, _, _ := newTestWatcher(t, agent.ResolvedLimits{Tokens: 1_000}, testTable())
			w.Observe(runStart(1_000))
			w.Observe(response(2_000, model, tc.in, tc.out, tc.cacheRead, tc.cacheWrite))

			got := w.Snapshot()
			if got.TokensIn != tc.wantIn || got.TokensOut != tc.wantOut {
				t.Errorf("tokens in/out = %d/%d, want %d/%d", got.TokensIn, got.TokensOut, tc.wantIn, tc.wantOut)
			}
			if got.CacheRead != tc.wantRead || got.CacheWrite != tc.wantWrite {
				t.Errorf("cache read/write = %d/%d, want %d/%d", got.CacheRead, got.CacheWrite, tc.wantRead, tc.wantWrite)
			}
			if _, tripped := w.Tripped(); tripped {
				t.Errorf("a negative usage counter fabricated a token breach (R1): state %+v", got)
			}
			if n := killer.kills.Load(); n != 0 {
				t.Errorf("%d kills from a negative usage counter, want 0", n)
			}
		})
	}
}

// TestEventTripReportsKillFailureWithoutBlocking covers trip's §4/§7 guarantee — "the event is
// appended even if Kill errors" — driven through the Observe/event path (an R1 token breach), which
// TestKillFailureIsReported never exercises: that test only ever trips through Tick (R3/R4), and
// Observe's own error handling (the `if err := w.trip(...)` branch inside Observe, which logs
// rather than returning, since Observe's contract is "never errors") is a different code path with
// no coverage of its own. A regression there — e.g. a panic instead of a log on a failed Kill —
// nothing else in the suite would catch, since it only fires when a breach trips from an event.
func TestEventTripReportsKillFailureWithoutBlocking(t *testing.T) {
	sink, clk := &fakeSink{}, &fakeClock{}
	boom := errors.New("cgroup is gone")
	killer := &fakeKiller{err: boom}
	var breaches []Breach
	w := NewWatcher(agent.ResolvedLimits{Tokens: 100}, testTable(), killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithOnBreach(func(b Breach) { breaches = append(breaches, b) }))
	w.Observe(runStart(1_000))

	// Must not panic or hang even though the killer always errors.
	w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 60, 60, 0, 0)) // 120 tokens > 100

	b, tripped := w.Tripped()
	if !tripped || b.Which != record.LimitTokens {
		t.Fatalf("breach %+v tripped=%v, want a token breach", b, tripped)
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want exactly 1 even though Kill failed (§4 trip)", n)
	}
	if len(breaches) != 1 {
		t.Fatalf("%d onBreach callbacks, want 1 even though Kill failed", len(breaches))
	}
	if n := killer.kills.Load(); n != 1 {
		t.Fatalf("%d kill attempts, want exactly 1", n)
	}
}

// TestRunPropagatesTickKillFailure covers Run's own documented contract ("the wrapped kill error
// when the cgroup could not be killed, a failure the run must not continue past silently"). Every
// existing Run test starts Run() only after the watcher had already tripped, so Run's early-return
// guard (`if _, tripped := w.Tripped(); tripped { return nil }`) always fires first and the loop's
// own `case <-t.C: ... if err != nil { return err }` branch — the one that actually surfaces a
// failed Kill discovered by Run's own ticking, not a pre-existing trip — has never run.
func TestRunPropagatesTickKillFailure(t *testing.T) {
	sink, clk := &fakeSink{}, &fakeClock{}
	boom := errors.New("cgroup is gone")
	killer := &fakeKiller{err: boom}
	w := NewWatcher(agent.ResolvedLimits{Wall: time.Second}, nil, killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithTickInterval(5*time.Millisecond))
	w.Observe(runStart(1_000))
	clk.set(1_000 + 2*uint64(time.Second)) // already past the 1s wall ceiling before Run starts

	done := make(chan error, 1)
	go func() { done <- w.Run(t.Context()) }()

	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("Run returned %v, want it to wrap %v (never swallowed)", err, boom)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return after its own tick's Kill failed")
	}
}

// orderingKiller records, at the moment Kill is invoked, whether trip's other two effects had
// already happened — proving trip's documented order (§4): "The event goes first so a reader of the
// ledger always finds why the run died, even if the kill fails; the callback goes before the kill so
// the facade's reason is set before the child's exit is observed."
type orderingKiller struct {
	sink                *fakeSink
	breached            func() bool
	sawEventBeforeKill  bool
	sawBreachBeforeKill bool
}

func (k *orderingKiller) Kill(cgroup.Cgroup) error {
	k.sawEventBeforeKill = len(k.sink.kinds(record.KindLimit)) == 1
	k.sawBreachBeforeKill = k.breached()
	return nil
}

// TestTripOrdersEventCallbackThenKill proves the order TestKillFailureIsReported's counts alone
// cannot: that the limit event and the onBreach callback both precede the Kill call, not merely that
// all three eventually happen.
// (limits-check-doctor-cli.md E25: a breach racing an operator stop still has its limit event appended before the kill, so run_end's reason precedence can consult it.)
func TestTripOrdersEventCallbackThenKill(t *testing.T) {
	sink, clk := &fakeSink{}, &fakeClock{}
	var breached bool
	killer := &orderingKiller{sink: sink, breached: func() bool { return breached }}
	w := NewWatcher(agent.ResolvedLimits{Wall: time.Second}, nil, killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithOnBreach(func(Breach) { breached = true }))
	w.Observe(runStart(1_000))
	clk.set(1_000 + 2*uint64(time.Second))

	if _, err := w.Tick(t.Context()); err != nil {
		t.Fatalf("Tick: %v", err)
	}
	if !killer.sawEventBeforeKill {
		t.Error("Kill ran before the limit event was appended (§4 trip: the event must go first)")
	}
	if !killer.sawBreachBeforeKill {
		t.Error("Kill ran before the onBreach callback fired (§4 trip: the callback must go before the kill)")
	}
}

// TestStageObservesBeforeForwarding pins the production wiring doc.go itself documents: "Observe —
// or the equivalent Stage, which the facade's pipeline composes." Every other test in this package
// drives Observe directly; none exercises Stage at all (0% coverage). A Stage that forwarded an
// event to the rest of the pipeline before applying Observe's effect — a one-line reordering bug —
// would pass every other test here while silently letting a breaching event reach the ledger and the
// agent's next turn before the watcher had any chance to trip on it.
func TestStageObservesBeforeForwarding(t *testing.T) {
	w, _, killer, _, _ := newTestWatcher(t, agent.ResolvedLimits{Tokens: 100}, testTable())
	var forwarded []*record.Event
	observedFirst := true
	next := func(ev *record.Event) {
		if ev.Kind == record.KindSSLResponse && killer.kills.Load() == 0 {
			observedFirst = false
		}
		forwarded = append(forwarded, ev)
	}
	stage := w.Stage(next)
	stage(runStart(1_000))
	stage(response(2_000, "claude-sonnet-4-5-20250929", 60, 60, 0, 0)) // 120 tokens > 100, breaches

	if len(forwarded) != 2 {
		t.Fatalf("%d events forwarded, want 2: Stage must pass every event on unchanged", len(forwarded))
	}
	if !observedFirst {
		t.Error("Stage forwarded the breaching event before Observe had tripped the watcher")
	}
	if _, tripped := w.Tripped(); !tripped {
		t.Fatal("Stage never called Observe: the watcher never tripped")
	}
}

// gateKiller blocks its first Kill until released, then fails every call.
type gateKiller struct {
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func (k *gateKiller) Kill(cgroup.Cgroup) error {
	k.once.Do(func() {
		close(k.entered)
		<-k.release
	})
	return k.err
}

// TestRunStaysWhileObservesKillIsInFlight: a Run that starts after a breach set tripped but before
// Observe's kill has failed must not return nil on that alone, or the failed kill is never retried.
func TestRunStaysWhileObservesKillIsInFlight(t *testing.T) {
	sink, clk := &fakeSink{}, &fakeClock{}
	boom := errors.New("cgroup is gone")
	killer := &gateKiller{entered: make(chan struct{}), release: make(chan struct{}), err: boom}
	w := NewWatcher(agent.ResolvedLimits{Tokens: 100}, testTable(), killer,
		cgroup.Cgroup{Path: "/sys/fs/cgroup/test"}, clk, sink,
		WithTickInterval(5*time.Millisecond))
	w.Observe(runStart(1_000))
	go w.Observe(response(2_000, "claude-sonnet-4-5-20250929", 60, 60, 0, 0))
	<-killer.entered // tripped is set, the kill has not returned

	done := make(chan error, 1)
	go func() { done <- w.Run(t.Context()) }()
	select {
	case err := <-done:
		t.Fatalf("Run returned %v while a kill was still owed", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(killer.release)
	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Fatalf("Run returned %v, want it to wrap %v", err, boom)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not surface the failed kill")
	}
}

// TestTokenTotalsSaturateInsteadOfWrapping pins R1's no-wrap half: input and output counts near MaxInt64 from a
// hostile upstream add to a total that wrapped to a small number below the ceiling, so the token breach never
// fired. The totals hold at MaxUint64 instead.
func TestTokenTotalsSaturateInsteadOfWrapping(t *testing.T) {
	const model = "claude-sonnet-4-5-20250929"
	w, _, _, _, _ := newTestWatcher(t, agent.ResolvedLimits{Tokens: 1_000}, testTable())
	w.Observe(runStart(1_000))
	w.Observe(response(2_000, model, 3, 0, 0, 0))
	w.Observe(response(3_000, model, math.MaxInt64, math.MaxInt64, 0, 0))
	w.Observe(response(4_000, model, math.MaxInt64, math.MaxInt64, math.MaxInt64, math.MaxInt64))
	got := w.Snapshot()
	if got.Tokens() < 1_000 {
		t.Errorf("Tokens() = %d wrapped below the ceiling: state %+v", got.Tokens(), got)
	}
	if _, tripped := w.Tripped(); !tripped {
		t.Errorf("the token ceiling was not crossed: state %+v", got)
	}
	if got.Tokens() != math.MaxUint64 {
		t.Errorf("Tokens() = %d, want the saturated total", got.Tokens())
	}
}
