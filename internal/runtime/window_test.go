// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// windowClock is a run's wall and monotonic clock in one, which a test moves by hand: the ledger stamps with it, the
// run id is minted from it and the watcher reads its monotonic time.
type windowClock struct {
	base time.Time
	mono atomic.Uint64
}

func (c *windowClock) Now() time.Time          { return c.base.Add(time.Duration(c.mono.Load())) }
func (c *windowClock) MonoNS() uint64          { return c.mono.Load() }
func (c *windowClock) Mono() uint64            { return c.mono.Load() }
func (c *windowClock) advance(d time.Duration) { c.mono.Add(uint64(d)) }

// windowRig is a ledger root and its chain.log, and the one agent whose restarts the tests drive.
type windowRig struct {
	t      *testing.T
	root   string
	anchor string
	clk    *windowClock
	source *record.ContractSource
	n      int
	// tier, when set, is the tier the run's backend reports: nothing else of the backend is asked.
	tier backend.Tier
}

func newWindowRig(t *testing.T) *windowRig {
	t.Helper()
	dir := t.TempDir()
	clk := &windowClock{base: time.Date(2026, 11, 24, 8, 0, 0, 0, time.UTC)}
	clk.advance(time.Second)
	return &windowRig{t: t, root: filepath.Join(dir, "runs"), anchor: filepath.Join(dir, "chain.log"), clk: clk,
		source: &record.ContractSource{Path: "/etc/tego/agents/retriever.yaml", Name: "retriever", Registry: "user"}}
}

func (g *windowRig) machine(retention time.Duration) *config.Machine {
	m := &config.Machine{}
	m.LedgerRoot.Value = g.root
	m.Retention.Value = retention
	return m
}

// start is a run of the agent as the launcher has it just before its agent starts: a minted id, an open ledger with
// run_start written, the window read, and the budget watcher and pipeline wired as startWorkers wires them.
func (g *windowRig) start(limits agent.ResolvedLimits, retention time.Duration) (*runner, *fakeCgroups, *collectSink, error) {
	g.t.Helper()
	g.n++
	id, err := identity.NewRunID([32]byte{}, g.clk.Now(), strings.NewReader("\x01\x02\x03\x04"))
	if err != nil {
		g.t.Fatal(err)
	}
	// A distinct rand6 per run, so two runs started in one second do not collide.
	id = identity.RunID(string(id)[:len(id)-1] + string(rune('a'+g.n)))
	dir := filepath.Join(g.root, string(id))
	if err := os.MkdirAll(g.root, 0o700); err != nil {
		g.t.Fatal(err)
	}
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "retriever"}, ledger.WithAnchor(ledger.NewFileChainAnchor(g.anchor)),
		ledger.WithClock(g.clk), ledger.WithFreshRunDir())
	if err != nil {
		g.t.Fatal(err)
	}
	g.t.Cleanup(func() { _ = w.Abandon() })
	cgroups := &fakeCgroups{root: g.t.TempDir()}
	r := &runner{
		log:    slog.New(slog.DiscardHandler),
		rt:     &agent.RuleTable{Contract: &agent.Contract{Name: "retriever"}, Limits: limits},
		deps:   Deps{Clock: g.clk, Config: g.machine(retention), ContractSource: g.source, AnchorPath: g.anchor},
		cgm:    cgroups,
		cg:     cgroup.Cgroup{Path: cgroups.root, ID: 4242},
		queue:  NewQueue(16),
		writer: w, id: id, dir: dir,
	}
	if g.tier != "" {
		r.deps.Enforce = tierBackend{tier: g.tier}
	}
	g.t.Cleanup(r.closeWindow)
	if err := r.openWindow(context.Background()); err != nil {
		return nil, nil, nil, err
	}
	r.newBudget()
	sink := &collectSink{}
	terminal := func(ev *record.Event) error { sink.append(ev); return w.Append(ev) }
	r.pipe = newPipeline(r.queue, terminal, w.RedactStage, w.SplitBlobsStage, runStamp{PID: 11, TID: 12, Cgroup: 4242}, nil,
		budgets(r.budget, g.clk), slog.New(slog.DiscardHandler), w.AppendBatch)
	if err := w.WriteRunStart(record.RunStartPayload{Tier: "landlock", Command: []string{"agent"}, Cwd: "/p", ContractSource: g.source,
		Limits: runLimits(limits, 0)}); err != nil {
		g.t.Fatal(err)
	}
	r.startBudgetClock()
	return r, cgroups, sink, nil
}

// end closes the run's ledger as a finished run's: run_end and its line in chain.log, and the window released.
func (g *windowRig) end(r *runner) {
	g.t.Helper()
	r.pipe.drain()
	if err := r.writer.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		g.t.Fatal(err)
	}
	r.closeWindow()
}

func windowLimits(tokens int64) agent.ResolvedLimits {
	return agent.ResolvedLimits{Tokens: tokens, Window: 24 * time.Hour, Set: agent.BudgetTokens}
}

const thirtyDays = 30 * 24 * time.Hour

// TestARestartedRunCountsTheRunsBeforeIt is AO-7: the first run spends 600 of 1000 tokens and ends; its restart is
// ended at the 1000th token of the two, by the limit it would not have reached on its own, and its ledger says it
// counted an earlier run.
func TestARestartedRunCountsTheRunsBeforeIt(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 400, 200))
	g.end(first)

	g.clk.advance(30 * time.Minute)
	second, cgroups, sink, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	if second.window == nil || second.windowRuns != 1 {
		t.Fatalf("window %+v, runs %d: the earlier run was not read", second.window, second.windowRuns)
	}
	second.pipe.handle(sslResponse(t, 200, 100)) // 600 + 300
	if second.terminal != "" {
		t.Fatalf("ended as %q at 900 of 1000", second.terminal)
	}
	second.pipe.handle(sslResponse(t, 100, 100)) // 1100 across the two runs, 500 in this one
	if second.terminal != identity.ReasonLimit || cgroups.killed != 1 {
		t.Fatalf("terminal %q, %d kills: the restart was not stopped at the window's ceiling", second.terminal, cgroups.killed)
	}
	second.pipe.drain()
	var lim record.LimitPayload
	found := false
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			found = true
			if err := ev.DecodePayload(&lim); err != nil {
				t.Fatal(err)
			}
		}
	}
	if !found || lim.Which != record.LimitTokens || lim.Value != 1100 || lim.Ceiling != 1000 {
		t.Fatalf("limit %+v (seen %v), want tokens 1100 over 1000", lim, found)
	}
	// The ledger says the run counted an earlier run: the gap is on disk, valid, with the number of runs read.
	second.emitWindowGap()
	second.pipe.drain()
	b, err := os.ReadFile(filepath.Join(second.dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"why":"window-carried"`) || !strings.Contains(string(b), `"what":"limits"`) {
		t.Fatalf("the run's ledger has no window-carried gap:\n%s", b)
	}
}

// TestAWindowDoesNotCountARunOlderThanTheWindow: the same restart a day and a minute later starts from zero.
func TestAWindowDoesNotCountARunOlderThanTheWindow(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 900, 0))
	g.end(first)
	g.clk.advance(24*time.Hour + 5*time.Minute)
	second, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	second.pipe.handle(sslResponse(t, 900, 0))
	if second.terminal != "" {
		t.Fatalf("a day-old run was counted: ended as %q", second.terminal)
	}
}

// TestAPriorLedgerEditedAfterItClosedRefusesTheRestart: the agent's count is the ledgers', so a ledger that no longer
// matches chain.log is no count, and the restart is refused rather than started with a lower one.
func TestAPriorLedgerEditedAfterItClosedRefusesTheRestart(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 900, 0))
	g.end(first)
	path := filepath.Join(first.dir, ledger.EventsFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	edited := strings.Replace(string(b), `"input":900`, `"input":9`, 1)
	if edited == string(b) {
		t.Fatal("no input 900 in the test ledger")
	}
	if err := os.WriteFile(path, []byte(edited), 0o600); err != nil {
		t.Fatal(err)
	}
	g.clk.advance(time.Hour)
	_, _, _, err = g.start(windowLimits(1000), thirtyDays)
	if !errors.Is(err, ErrBudgetWindow) || !strings.Contains(err.Error(), string(first.id)) || !strings.Contains(err.Error(), "Fix:") {
		t.Fatalf("err = %v, want ErrBudgetWindow naming %s and a fix", err, first.id)
	}
}

// TestAMissingAnchorCountsTheRunAndSaysSo: chain.log without the line of an ended run (the anchor write failed, or the
// file was lost) leaves the run's chain to be checked on its own. The restart starts, counts what that record holds,
// logs the run and writes a gap that names how many. Red before: the restart was refused until gc deleted the run.
func TestAMissingAnchorCountsTheRunAndSaysSo(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 900, 0))
	g.end(first)
	if err := os.Remove(g.anchor); err != nil {
		t.Fatal(err)
	}
	g.clk.advance(time.Hour)
	second, cgroups, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatalf("a run with no chain.log line refused the restart: %v", err)
	}
	if second.windowRuns != 1 || second.windowUnanchored != 1 {
		t.Fatalf("read %d runs, %d unanchored; want 1 and 1", second.windowRuns, second.windowUnanchored)
	}
	second.pipe.handle(sslResponse(t, 200, 0)) // 900 carried + 200
	if second.terminal != identity.ReasonLimit || cgroups.killed != 1 {
		t.Fatalf("terminal %q: the unanchored run's spend was not counted", second.terminal)
	}
	second.emitWindowGap()
	second.pipe.drain()
	b, err := os.ReadFile(filepath.Join(second.dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"why":"window-unanchored"`) {
		t.Fatalf("the run's ledger does not say it counted an unanchored run:\n%s", b)
	}
}

// TestAnotherAgentsDamagedRunDoesNotRefuseTheStart: the other agent's ledger is edited and the start is not refused.
func TestAnotherAgentsDamagedRunDoesNotRefuseTheStart(t *testing.T) {
	g := newWindowRig(t)
	g.source = &record.ContractSource{Path: "/etc/tego/agents/writer.yaml", Name: "writer", Registry: "user"}
	other, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	other.pipe.handle(sslResponse(t, 900, 0))
	g.end(other)
	path := filepath.Join(other.dir, ledger.EventsFile)
	b, _ := os.ReadFile(path)
	if err := os.WriteFile(path, []byte(strings.Replace(string(b), `"input":900`, `"input":9`, 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	g.source = &record.ContractSource{Path: "/etc/tego/agents/retriever.yaml", Name: "retriever", Registry: "user"}
	if _, _, _, err := g.start(windowLimits(1000), thirtyDays); err != nil {
		t.Fatalf("another agent's damaged ledger refused this agent: %v", err)
	}
}

// TestTwoProjectsWithOneAgentNameRunSideBySide: bot in /a and bot in /b are two agents: neither is refused for the
// other being live, and neither counts the other. Red before: the second was refused as a live sibling.
func TestTwoProjectsWithOneAgentNameRunSideBySide(t *testing.T) {
	g := newWindowRig(t)
	g.source = &record.ContractSource{Path: "/srv/a/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	a, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	a.pipe.handle(sslResponse(t, 900, 0))
	g.source = &record.ContractSource{Path: "/srv/b/.tego/agents/bot.yaml", Name: "bot", Registry: "project"}
	b, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatalf("bot of /b was refused while bot of /a runs: %v", err)
	}
	b.pipe.handle(sslResponse(t, 900, 0))
	if b.terminal != "" || a.terminal != "" {
		t.Fatalf("one agent's spend ended the other: a %q, b %q", a.terminal, b.terminal)
	}
}

// TestAWindowIsRefusedWhereTheAgentCanReachItsRecords: a record-only run holds nothing back, so the agent could edit
// the ledgers the count is read from. The refusal says why, and each held tier starts. Red before: observe started.
func TestAWindowIsRefusedWhereTheAgentCanReachItsRecords(t *testing.T) {
	g := newWindowRig(t)
	g.tier = backend.TierObserve
	_, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if !errors.Is(err, ErrBudgetWindow) || !strings.Contains(err.Error(), "record-only") || !strings.Contains(err.Error(), "Fix:") {
		t.Fatalf("observe: err = %v, want ErrBudgetWindow saying a record-only run cannot protect the count, and a fix", err)
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		g := newWindowRig(t)
		g.tier = tier
		if _, _, _, err := g.start(windowLimits(1000), thirtyDays); err != nil {
			t.Fatalf("tier %s: %v", tier, err)
		}
	}
}

// TestTwoRunsOfOneAgentAtOnce: the second is refused while the first holds the agent's window, and starts once the
// first has ended and counts it.
func TestTwoRunsOfOneAgentAtOnce(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 500, 0))
	if _, _, _, err = g.start(windowLimits(1000), thirtyDays); !errors.Is(err, ErrBudgetWindow) || !strings.Contains(err.Error(), "live") {
		t.Fatalf("err = %v, want ErrBudgetWindow for a live run", err)
	}
	g.end(first)
	second, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatalf("after the first ended: %v", err)
	}
	if second.windowRuns != 1 {
		t.Fatalf("the second read %d runs, want the first", second.windowRuns)
	}
}

// TestALockThatCannotBeOpenedIsNotALedgerFault: the agent's lock file in the ledger root is refused for what it is. The
// ledger-shaped fix a damaged run gets (restore a copy, move the run's directory) names nothing here.
func TestALockThatCannotBeOpenedIsNotALedgerFault(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	g.end(first)
	locks, _ := filepath.Glob(filepath.Join(g.root, ".window-*.lock"))
	if len(locks) != 1 {
		t.Fatalf("locks %v, want one", locks)
	}
	if err := os.Remove(locks[0]); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(locks[0], 0o700); err != nil { // not openable for writing, whoever opens it
		t.Fatal(err)
	}
	_, _, _, err = g.start(windowLimits(1000), thirtyDays)
	if !errors.Is(err, ErrBudgetWindow) {
		t.Fatalf("err = %v, want ErrBudgetWindow", err)
	}
	for _, want := range []string{filepath.Base(locks[0]), "lock file", "chmod u+rw"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal %q lacks %q", err, want)
		}
	}
	if strings.Contains(err.Error(), "restore that run's ledger") {
		t.Errorf("the refusal sends a person to a ledger that is not at fault: %v", err)
	}
}

// TestAnotherAgentsSpendIsNotCounted: the window is one agent's.
func TestAnotherAgentsSpendIsNotCounted(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 900, 0))
	g.end(first)
	g.source = &record.ContractSource{Path: "/etc/tego/agents/writer.yaml", Name: "writer", Registry: "user"}
	second, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	second.pipe.handle(sslResponse(t, 900, 0))
	if second.terminal != "" || second.windowRuns != 0 {
		t.Fatalf("another agent's run was counted: %q after %d runs", second.terminal, second.windowRuns)
	}
}

// TestAWindowNeedsANamedContractAndRetention: the other two refusals, each with its fix.
func TestAWindowNeedsANamedContractAndRetention(t *testing.T) {
	g := newWindowRig(t)
	g.source = nil
	if _, _, _, err := g.start(windowLimits(1000), thirtyDays); !errors.Is(err, ErrBudgetWindow) || !strings.Contains(err.Error(), "--agent") {
		t.Fatalf("no contract source: err = %v", err)
	}
	g = newWindowRig(t)
	if _, _, _, err := g.start(windowLimits(1000), 12*time.Hour); !errors.Is(err, ErrBudgetWindow) || !strings.Contains(err.Error(), "retention") {
		t.Fatalf("short retention: err = %v", err)
	}
}

// TestNoWindowIsNoCheck: a contract without limits.window reads no ledger and takes no lock.
func TestNoWindowIsNoCheck(t *testing.T) {
	g := newWindowRig(t)
	r, _, _, err := g.start(agent.ResolvedLimits{Tokens: 1000, Set: agent.BudgetTokens}, 0)
	if err != nil || r.window != nil || r.windowLock != nil {
		t.Fatalf("err %v, window %v, lock %v", err, r.window, r.windowLock)
	}
}

// TestRunStartRecordsTheWindow: run_start.limits.window is the span, so a verifier needs no contract to know it.
func TestRunStartRecordsTheWindow(t *testing.T) {
	got := runLimits(agent.ResolvedLimits{Tokens: 10, Window: 36 * time.Hour, Set: agent.BudgetTokens}, 0)
	if got == nil || got.Window != "36h0m0s" || got.Tokens == nil || *got.Tokens != 10 {
		t.Fatalf("runLimits = %+v, want window 36h0m0s beside tokens 10", got)
	}
	if got := runLimits(agent.ResolvedLimits{Tokens: 10, Set: agent.BudgetTokens}, 0); got.Window != "" {
		t.Fatalf("a contract with no window recorded %q", got.Window)
	}
}

// recomputedWindowTokens is a verifier that reads nothing but the ledgers, as spec/record/v1/README.md "A budget over a
// window" describes: the agent of run id (its run_start's contract_source), the window (its run_start's limits), every
// other run of that agent in the root, each response placed in its minute, and the minutes still inside the window at
// the time of the limit line. It shares no code with the launcher's reading.
func recomputedWindowTokens(t *testing.T, root, id string, identityOf func(*record.ContractSource) string) float64 {
	t.Helper()
	type resp struct {
		at     time.Time
		tokens int
	}
	read := func(run string) (start *record.Event, p record.RunStartPayload, resps []resp, limit *record.Event) {
		r, err := ledger.OpenReader(filepath.Join(root, run))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Close() }()
		for ev, err := range r.Iter() {
			if err != nil {
				t.Fatal(err)
			}
			switch ev.Kind {
			case record.KindRunStart:
				start = ev
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
			case record.KindSSLResponse:
				var sp record.SSLResponsePayload
				if err := ev.DecodePayload(&sp); err != nil {
					t.Fatal(err)
				}
				if sp.Usage != nil {
					resps = append(resps, resp{ev.TS, sp.Usage.Input + sp.Usage.Output})
				}
			case record.KindLimit:
				limit = ev
			}
		}
		return
	}
	start, p, mine, limit := read(id)
	if limit == nil || p.Limits == nil || p.Limits.Window == "" {
		t.Fatalf("run %s has no limit line or no limits.window in run_start", id)
	}
	window, err := time.ParseDuration(p.Limits.Window)
	if err != nil {
		t.Fatal(err)
	}
	me := identityOf(p.ContractSource)
	ents, _ := os.ReadDir(root)
	var all []resp
	for _, e := range ents {
		if !e.IsDir() || !ledger.IsRunID(e.Name()) || e.Name() == id {
			continue
		}
		_, op, rs, _ := read(e.Name())
		if identityOf(op.ContractSource) != me {
			continue
		}
		for _, x := range rs {
			if x.at.After(start.TS) {
				x.at = start.TS
			}
			all = append(all, x)
		}
	}
	all = append(all, mine...)
	n := limit.TS.Unix()
	edge := n - int64(window/time.Second)
	var total int
	for _, x := range all {
		if x.at.After(limit.TS) {
			continue
		}
		minute := x.at.Unix() / 60
		if (minute+1)*60 > edge {
			total += x.tokens
		}
	}
	return float64(total)
}

// TestTheCarriedCountIsRecomputableFromTheRecords: a restart stopped at the window's ceiling carries a limit value that
// a reader of the ledgers alone, following the record spec, arrives at again. Red before: run_start did not say the window,
// so nothing but the contract (which the record holds only as a hash) gave the span.
func TestTheCarriedCountIsRecomputableFromTheRecords(t *testing.T) {
	g := newWindowRig(t)
	first, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	first.pipe.handle(sslResponse(t, 400, 200))
	g.end(first)
	g.clk.advance(30 * time.Minute)
	// A third agent's spend and an older run of this agent beyond the window are in the same root and must not count.
	g.source = &record.ContractSource{Path: "/etc/tego/agents/writer.yaml", Name: "writer", Registry: "user"}
	other, _, _, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	other.pipe.handle(sslResponse(t, 5000, 0))
	g.end(other)
	g.source = &record.ContractSource{Path: "/etc/tego/agents/retriever.yaml", Name: "retriever", Registry: "user"}
	second, _, sink, err := g.start(windowLimits(1000), thirtyDays)
	if err != nil {
		t.Fatal(err)
	}
	second.pipe.handle(sslResponse(t, 200, 100))
	second.pipe.handle(sslResponse(t, 100, 100))
	second.pipe.drain()
	var lim record.LimitPayload
	for _, ev := range sink.all() {
		if ev.Kind == record.KindLimit {
			if err := ev.DecodePayload(&lim); err != nil {
				t.Fatal(err)
			}
		}
	}
	if lim.Which != record.LimitTokens || lim.Value != 1100 {
		t.Fatalf("limit %+v, want tokens 1100", lim)
	}
	// The sink saw the limit line; the verifier needs it in the ledger, which the writer flushes at its close.
	g.end(second)
	identityOf := func(cs *record.ContractSource) string {
		if cs == nil {
			return ""
		}
		if cs.Name != "" {
			return cs.Registry + "/" + cs.Name
		}
		return cs.Path
	}
	if got := recomputedWindowTokens(t, g.root, string(second.id), identityOf); got != lim.Value {
		t.Fatalf("a verifier recomputes %v from the records, the run's limit line says %v", got, lim.Value)
	}
}
