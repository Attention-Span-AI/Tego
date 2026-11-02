// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"os"
	"runtime"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// judgeTB records what a helper said to its test instead of failing the real one.
type judgeTB struct {
	testing.TB
	logs, errs, fatals []string
}

func (r *judgeTB) Helper() {}
func (r *judgeTB) Logf(format string, args ...any) {
	r.logs = append(r.logs, fmt.Sprintf(format, args...))
}
func (r *judgeTB) Errorf(format string, args ...any) {
	r.errs = append(r.errs, fmt.Sprintf(format, args...))
}
func (r *judgeTB) Fatalf(format string, args ...any) {
	r.fatals = append(r.fatals, fmt.Sprintf(format, args...))
}

func (r *judgeTB) logged(sub string) bool {
	for _, l := range r.logs {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// TestTimingModeReadsItsSwitch: unset or empty is the unit gate, "1" budget mode, and anything else fails the test
// rather than holding only the ceilings in a run that meant to assert the budgets.
func TestTimingModeReadsItsSwitch(t *testing.T) {
	for _, c := range []struct {
		value   string
		budgets bool
		fatal   bool
	}{
		{"", false, false},
		{"1", true, false},
		{"true", false, true},
		{"0", false, true},
		{"yes", false, true},
	} {
		t.Setenv(BudgetsEnv, c.value)
		r := &judgeTB{TB: t}
		m := TimingMode(r)
		if m.Budgets() != c.budgets || (len(r.fatals) > 0) != c.fatal {
			t.Errorf("%s=%q: budgets %v, fatal %q; want budgets %v, fatal %v", BudgetsEnv, c.value, m.Budgets(), r.fatals,
				c.budgets, c.fatal)
		}
	}
}

// TestMeasureTakesEachModesClocks: budget mode measures on the wall clock alone, as a budget's spec writes it; the
// unit gate the calling thread's figures, from the same samples.
func TestMeasureTakesEachModesClocks(t *testing.T) {
	work := func() { spinCPU(time.Millisecond) }
	const least = 900 * time.Microsecond // a millisecond of work, less any clock's own cost
	for _, f := range (Mode{budgets: true}).Measure(3, work) {
		if f.OnThread || f.Wall < least {
			t.Errorf("budget mode measured %v; want a wall-clock figure of about 1ms and no thread figures", f)
		}
	}
	for _, f := range (Mode{}).Measure(3, work) {
		if !f.OnThread || f.Wall < least || f.Own < least || f.CPU < least || f.Own < f.CPU {
			t.Errorf("the unit gate measured %v; want the thread's figures, each about 1ms, its own time no less than "+
				"its CPU time", f)
		}
	}
}

// TestJudgeHoldsTheBudgetInBudgetMode: in budget mode a figure over the Limit fails and one over the Target prints
// TARGET-MISS, with the budget's own numbers; a figure that carries the thread's figures is refused there.
func TestJudgeHoldsTheBudgetInBudgetMode(t *testing.T) {
	b := Budget{Name: "case", Target: 6 * time.Microsecond, Limit: 12 * time.Microsecond, Spec: "ADR 0048 C8", Added: true}
	bm := Mode{budgets: true}
	for _, c := range []struct {
		d          time.Duration
		miss, fail bool
	}{
		{5 * time.Microsecond, false, false},
		{6 * time.Microsecond, false, false},
		{6*time.Microsecond + 1, true, false},
		{12 * time.Microsecond, true, false},
		{12*time.Microsecond + 1, true, true},
		{120 * time.Microsecond, true, true},
	} {
		r := &judgeTB{TB: t}
		bm.Judge(r, b, Figure{Wall: c.d})
		if r.logged("TARGET-MISS: case +") != c.miss || (len(r.errs) > 0) != c.fail || len(r.fatals) > 0 {
			t.Errorf("budget mode, %v: logs %q errors %q fatals %q; want TARGET-MISS %v, failure %v", c.d, r.logs, r.errs,
				r.fatals, c.miss, c.fail)
		}
		if c.fail && !strings.Contains(r.errs[0], "over the +12µs limit (ADR 0048 C8)") {
			t.Errorf("budget mode, %v: failure %q does not name the limit", c.d, r.errs[0])
		}
	}
	r := &judgeTB{TB: t}
	bm.Judge(r, b, Figure{Wall: time.Microsecond, Own: time.Microsecond, CPU: time.Microsecond, OnThread: true})
	if len(r.fatals) != 1 || len(r.errs) != 0 {
		t.Errorf("budget mode took a figure with the thread's figures: fatals %q errors %q", r.fatals, r.errs)
	}
	r = &judgeTB{TB: t}
	bm.Judge(r, Budget{Name: "pace", Limit: 11 * time.Second, Spec: "R22"}, Figure{Wall: 12 * time.Second})
	if r.logged("TARGET-MISS") || len(r.errs) != 1 {
		t.Errorf("a budget with no target: logs %q errors %q; want no TARGET-MISS and one failure", r.logs, r.errs)
	}
}

// TestJudgeHoldsTheCeilingInTheUnitGate: in the unit gate a figure fails only over CeilingFactor times the Limit, no
// TARGET-MISS is printed, and the log names the limit and the switch that asserts it. A thread's figure is held on
// its own time: a wait the code makes (own time far over its CPU time) fails, and a wait for a CPU (wall clock over
// the own time) does not, until the wall clock passes WallCeilingFactor times the Limit, which fails whatever the own
// time says. A figure with no thread's figures (a pace) is held on the wall clock to CeilingFactor times the Limit.
func TestJudgeHoldsTheCeilingInTheUnitGate(t *testing.T) {
	b := Budget{Name: "case", Target: 6 * time.Microsecond, Limit: 12 * time.Microsecond, Spec: "ADR 0048 C8", Added: true}
	if b.Ceiling() != 120*time.Microsecond || b.WallCeiling() != 1200*time.Microsecond {
		t.Fatalf("ceilings %v and %v, want 120µs and 1.2ms", b.Ceiling(), b.WallCeiling())
	}
	const us = time.Microsecond
	thread := func(wall, own, cpu time.Duration) Figure {
		return Figure{Wall: wall, Own: own, CPU: cpu, OnThread: true, RunQueue: true}
	}
	for _, c := range []struct {
		f    Figure
		fail string // the failure wanted, "" for none
	}{
		{Figure{Wall: 5 * us}, ""},
		{Figure{Wall: 120 * us}, ""},
		{Figure{Wall: 120*us + 1}, "of wall clock, over the unit gate's +120µs ceiling"},
		{thread(13*us, 13*us, 13*us), ""},
		{thread(120*us, 120*us, 120*us), ""},
		// A run queue the scheduler kept the thread on for nearly a millisecond: the code's own 40 µs passes.
		{thread(1200*us, 40*us, 40*us), ""},
		// A wall clock past a hundred Limits fails though the own time does not: a wait another process's work fills
		// hides from the own time.
		{thread(1200*us+1, 40*us, 40*us), "of wall clock, over the unit gate's +1.2ms wall-clock ceiling"},
		// A 1 ms wait the code made: its own time is over, though its CPU time is 40 µs.
		{thread(time.Millisecond, time.Millisecond, 40*us), "of the thread's own time, over the unit gate's +120µs ceiling"},
		{thread(200*us, 200*us, 200*us), "of the thread's own time, over the unit gate's +120µs ceiling"},
		// Run-queue waits not read: the own time is the wall clock, and is held as it is.
		{Figure{Wall: time.Millisecond, Own: time.Millisecond, CPU: 40 * us, OnThread: true},
			"of the thread's own time, over the unit gate's +120µs ceiling"},
	} {
		r := &judgeTB{TB: t}
		Mode{}.Judge(r, b, c.f)
		if (c.fail == "") != (len(r.errs) == 0) || len(r.errs) > 1 || (c.fail != "" && !strings.Contains(r.errs[0], c.fail)) ||
			r.logged("TARGET-MISS") || len(r.fatals) > 0 {
			t.Errorf("unit gate, %v: logs %q errors %q fatals %q; want the failure %q and no TARGET-MISS", c.f, r.logs,
				r.errs, r.fatals, c.fail)
		}
		if !r.logged("+12µs limit of ADR 0048 C8, which " + BudgetsEnv + "=1 asserts") {
			t.Errorf("unit gate, %v: logs %q do not say where the limit is asserted", c.f, r.logs)
		}
	}
	r := &judgeTB{TB: t}
	Mode{}.Judge(r, b, Figure{Wall: time.Millisecond, Own: time.Millisecond, CPU: 40 * us, OnThread: true})
	if !r.logged("could not be read") {
		t.Errorf("a figure whose run-queue waits were not read: logs %q do not say so", r.logs)
	}
}

// TestJudgeRatioInBothModes: budget mode fails a ratio over its limit, the unit gate only one over ten times it, on
// the thread's own times where it has them, else on the wall clock; budget mode refuses a ratio of thread figures.
func TestJudgeRatioInBothModes(t *testing.T) {
	thread := func(wall, own float64) Ratio {
		return Ratio{Wall: wall, Own: own, CPU: own, OnThread: true, RunQueue: true}
	}
	if r := (&judgeTB{TB: t}); true {
		Mode{}.JudgeRatio(r, "Borrow", "ADR 0023 P1", thread(250.01, 3), 2.5)
		if len(r.errs) != 1 || !strings.Contains(r.errs[0], "over the unit gate's 250.0 wall-clock ceiling") {
			t.Errorf("a wall-clock ratio past a hundred limits: errors %q, want one wall-clock failure", r.errs)
		}
	}
	for _, c := range []struct {
		budgets bool
		r       Ratio
		fail    bool
	}{
		{true, Ratio{Wall: 2.5}, false},
		{true, Ratio{Wall: 2.51}, true},
		{false, Ratio{Wall: 2.51}, false},
		{false, Ratio{Wall: 25}, false},
		{false, Ratio{Wall: 25.01}, true},
		{false, thread(3, 3), false},
		{false, thread(44, 3), false}, // the wall clock's waits for a CPU are not the code's
		{false, thread(3, 44), true},
		{false, thread(44, 44), true},
	} {
		r := &judgeTB{TB: t}
		Mode{budgets: c.budgets}.JudgeRatio(r, "Borrow", "ADR 0023 P1", c.r, 2.5)
		if (len(r.errs) > 0) != c.fail || len(r.errs) > 1 || len(r.fatals) > 0 {
			t.Errorf("budgets %v, ratio %+v: errors %q fatals %q, want failure %v", c.budgets, c.r, r.errs, r.fatals, c.fail)
		}
		if !c.budgets && !r.logged("which "+BudgetsEnv+"=1 asserts") {
			t.Errorf("unit gate, ratio %+v: logs %q do not say where the limit is asserted", c.r, r.logs)
		}
	}
	r := &judgeTB{TB: t}
	Mode{budgets: true}.JudgeRatio(r, "Borrow", "ADR 0023 P1", thread(1, 1), 2.5)
	if len(r.fatals) != 1 {
		t.Errorf("budget mode took a ratio of thread figures: fatals %q", r.fatals)
	}
}

// TestFigureArithmetic: an A/B figure is each figure's difference, never below zero; a batch's is shared out per
// call; a ratio is taken on each figure both sides have.
func TestFigureArithmetic(t *testing.T) {
	a := Figure{Wall: 30, Own: 26, CPU: 20, OnThread: true, RunQueue: true}
	b := Figure{Wall: 10, Own: 13, CPU: 25, OnThread: true, RunQueue: true}
	if got := a.Sub(b); got != (Figure{Wall: 20, Own: 13, CPU: 0, OnThread: true, RunQueue: true}) {
		t.Errorf("Sub: %+v", got)
	}
	if got := a.Sub(Figure{Wall: 10}); got.OnThread || got.RunQueue {
		t.Errorf("Sub of a wall-only figure kept thread figures: %+v", got)
	}
	if got := a.Div(10); got != (Figure{Wall: 3, Own: 2, CPU: 2, OnThread: true, RunQueue: true}) {
		t.Errorf("Div: %+v", got)
	}
	if got := a.Over(Figure{Wall: 10, Own: 13, CPU: 5, OnThread: true}); got != (Ratio{Wall: 3, Own: 2, CPU: 4, OnThread: true}) {
		t.Errorf("Over: %+v", got)
	}
	if got := (Figure{Wall: 30}).Over(Figure{Wall: 10}); got != (Ratio{Wall: 3}) {
		t.Errorf("Over, wall clock alone: %+v", got)
	}
}

// TestMinOfRotatesAndKeepsTheFastest: every function runs once a round, the one that goes first rotating, and each
// figure is that function's fastest sample, on one clock or on the thread's figures.
func TestMinOfRotatesAndKeepsTheFastest(t *testing.T) {
	var order []string
	n := map[string]int{}
	fn := func(name string) func() {
		return func() { order = append(order, name); n[name]++ }
	}
	MinOf(Wall, 3, fn("a"), fn("b"), fn("c"))
	if got := strings.Join(order, ""); got != "abcbcacab" {
		t.Errorf("order %q, want abcbcacab", got)
	}
	if n["a"] != 3 || n["b"] != 3 || n["c"] != 3 {
		t.Errorf("runs %v, want 3 each", n)
	}
	order = nil
	MinOfThread(3, fn("a"), fn("b"), fn("c"))
	if got := strings.Join(order, ""); got != "abcbcacab" {
		t.Errorf("MinOfThread: order %q, want abcbcacab", got)
	}
	// One sample of the first function spins far longer than every other: the fastest is kept, not the mean.
	round := 0
	slow := func() {
		round++
		if round == 2 {
			spinCPU(20 * time.Millisecond)
		}
	}
	for _, c := range []Clock{Wall, ThreadCPU} {
		round = 0
		m := MinOf(c, 5, slow, func() {})
		if m[0] > 10*time.Millisecond {
			t.Errorf("%v: %v kept for a function whose fastest sample was nearly nothing", c, m[0])
		}
	}
	round = 0
	if f := MinOfThread(5, slow, func() {})[0]; f.Wall > 10*time.Millisecond || f.Own > 10*time.Millisecond ||
		f.CPU > 10*time.Millisecond {
		t.Errorf("the thread's figures: %v kept for a function whose fastest sample was nearly nothing", f)
	}
}

// TestMinOfTakesOutTheClocksCost: an empty function measures far less than one read of the thread CPU clock, a
// system call of hundreds of nanoseconds that, left in, would read a ratio of two samples closer to 1. The read's
// cost is measured here, on the same thread, as the fastest of many back-to-back pairs; with MinOf's subtraction
// removed the empty function reads it whole (686 ns under load, 2026-10-16). MinOfThread takes each figure's cost out
// of that figure: its CPU time brackets the wall clock's and the run-queue delay's reads too, and its own time the
// two reads of /proc/thread-self/schedstat.
func TestMinOfTakesOutTheClocksCost(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	read := time.Duration(1<<63 - 1)
	for range 500 {
		start := ThreadCPU.read()
		read = min(read, ThreadCPU.read()-start)
	}
	if m := MinOf(ThreadCPU, 500, func() {}); m[0] >= read/2 {
		t.Errorf("an empty function measured %v of thread CPU time, where one read of the clock costs %v: the clock's "+
			"own cost is left in", m[0], read)
	}
	if m := MinOf(Wall, 500, func() {}); m[0] >= time.Microsecond {
		t.Errorf("an empty function measured %v on the wall clock", m[0])
	}
	// A thread sample reads two more clocks inside the CPU clock's bracket (getrusage and schedstat, each twice), each a
	// system call whose cost varies more than one read does, so its cost is measured as a whole sample's: the fastest
	// of many empty samples, figure by figure, and MinOfThread must take out at least half of each.
	rq := openRunQueue()
	defer rq.close()
	raw := sample{wall: 1<<63 - 1, own: 1<<63 - 1, cpu: 1<<63 - 1}
	for range 500 {
		s := threadSample(rq, func() {})
		raw.wall, raw.own, raw.cpu = min(raw.wall, s.wall), min(raw.own, s.own), min(raw.cpu, s.cpu)
	}
	if f := MinOfThread(500, func() {})[0]; f.CPU >= raw.cpu/2 || f.Own >= max(raw.own, raw.cpu)/2 || f.Wall >= raw.wall/2 {
		t.Errorf("an empty function measured %v, where an empty thread sample costs %v of CPU time, %v of own time and "+
			"%v of wall clock: a figure's own cost is left in", f, raw.cpu, raw.own, raw.wall)
	}
}

// TestThreadCPULeavesOutWaits: a sleep costs the thread no CPU time, and work on the thread costs what it took. That
// is why no budget is held on CPU time alone (TestTheUnitGateSeesTheWaitsCPUTimeLeavesOut).
func TestThreadCPULeavesOutWaits(t *testing.T) {
	m := MinOf(ThreadCPU, 1, func() { time.Sleep(50 * time.Millisecond) }, func() { spinCPU(20 * time.Millisecond) })
	if m[0] > 10*time.Millisecond {
		t.Errorf("a 50 ms sleep read %v of thread CPU time", m[0])
	}
	if m[1] < 20*time.Millisecond {
		t.Errorf("20 ms of work on the thread read %v of its CPU time", m[1])
	}
}

// TestTheUnitGateSeesTheWaitsCPUTimeLeavesOut: a wait the code causes is part of its cost. A sleep, a wait on a lock
// another goroutine holds and a wait for a reply from another goroutine each read at least as long as they last on
// the wall clock, while the CPU time reads almost nothing, and a budget whose wall-clock ceiling they pass fails
// whatever the own time says (on a busy machine a wait hides from the own time where another process's work fills
// it and the thread never blocks, and the fastest sample can be one where it did). Before 2026-10-17 the unit gate
// read CPU time alone, and a copy of ADR 0048 C8's path that slept 20 ms in every command-rule decision passed it.
func TestTheUnitGateSeesTheWaitsCPUTimeLeavesOut(t *testing.T) {
	const d = 5 * time.Millisecond
	var mu sync.Mutex
	acquired := 0
	locked := func() {
		mu.Lock()
		go func() { time.Sleep(d); mu.Unlock() }()
		mu.Lock() // waits for the other goroutine's Unlock
		acquired++
		mu.Unlock()
	}
	reply := func() {
		ch := make(chan struct{})
		go func() { time.Sleep(d); close(ch) }()
		<-ch
	}
	waits := []func(){func() { time.Sleep(d) }, locked, reply}
	figures := (Mode{}).Measure(3, waits...)
	if acquired != 3 {
		t.Errorf("the lock was taken %d times, want once a round", acquired)
	}
	for i, f := range figures {
		if !f.OnThread || f.Wall < d || f.CPU >= d/2 {
			t.Errorf("wait %d (sleep, lock, reply) of %v measured %v: want at least %v of wall clock and under %v of "+
				"CPU time", i, d, f, d, d/2)
		}
		// 40 µs: ceilings of 400 µs of own time and 4 ms of wall clock, which the 5 ms wait passes.
		r := &judgeTB{TB: t}
		Mode{}.Judge(r, Budget{Name: "wait", Limit: 40 * time.Microsecond, Spec: "test"}, f)
		if !slices.ContainsFunc(r.errs, func(e string) bool {
			return strings.Contains(e, "of wall clock, over the unit gate's 4ms wall-clock ceiling")
		}) {
			t.Errorf("wait %d measured %v: errors %q, want a failure of its wall clock against the 4ms ceiling", i, f, r.errs)
		}
	}
}

// TestOwnTimeLeavesOutRunQueueWaits: work that waits for its CPU behind another process's runnable thread reads the
// waits on the wall clock and not in its own time, which stays at its CPU time. The calling thread and a spinning
// child process are held to one CPU (sched_setaffinity), so the waits are certain however idle the machine is; on a
// busy one other tenants add their own, which the own time leaves out alike. This is what keeps the unit gate's
// ceiling a figure of the code on a machine with more runnable threads than CPUs, where the wall clock has no bound.
// The spinner is another process because a thread of this one is the code's: the CPU time the process's other threads
// had over a sample stays in its own time (TestAHandOffShowsInTheOwnTime).
func TestOwnTimeLeavesOutRunQueueWaits(t *testing.T) {
	requireRunQueue(t)
	onOneCPU(t, func(cpu int) {
		stop := startSpinner(t)
		defer stop()
		rq := openRunQueue()
		defer rq.close()
		// The work is a little longer than a scheduler slice (3 ms here), so the spinning process usually takes the
		// CPU from it once; but the scheduler may let it run whole, and a sample can block: the Go runtime preempts a
		// goroutine that has run for 10 ms of wall clock, which parks a locked thread, and on a machine already busy
		// the waits alone pass 10 ms. So every try holds what must be true of any sample: its own time is its wall
		// clock where it blocked, and where it did not, the wall clock less at most the run-queue delay read around it
		// (a little wider than the sample's own reading) and within 1 ms of its CPU time plus the process's other
		// threads' (which stay in the own time; on a loaded machine they were 1.26 ms once), however long its waits
		// were. The tries stop at one that waited at least a quarter of the work without blocking; a machine so busy
		// that none does is logged, the formula itself being held by TestOwnTimeTakesOutTheRunQueueDelay. A Gosched
		// first starts the 10 ms afresh.
		const work = 4 * time.Millisecond
		waited := false
		for try := range 10 {
			runtime.Gosched()
			q0 := rq.delay()
			s := threadSample(rq, func() { spinCPU(work) })
			delay := rq.delay() - q0
			t.Logf("try %d: %v of work on CPU %d beside a spinning process: %+v, %v of run-queue delay around it", try,
				work, cpu, s, delay)
			// The CPU clock brackets the sample's other reads too, so a sample's own time can be a few microseconds
			// under its CPU time; MinOfThread's figure is never under it.
			if s.cpu < work || s.own > s.wall {
				t.Errorf("try %d measured %+v: want the work's %v of CPU time, and an own time no more than the wall "+
					"clock", try, s, work)
			}
			if s.blocked {
				if s.own != s.wall {
					t.Errorf("try %d blocked and measured %+v: want its own time the wall clock", try, s)
				}
				continue
			}
			if s.own < s.wall-delay || s.own-s.cpu-s.others > time.Millisecond || s.cpu-s.own > time.Millisecond {
				t.Errorf("try %d did not block and measured %+v with %v of delay around it: want the run-queue waits "+
					"on the wall clock alone, and its own time within 1ms of its CPU time plus the other threads' (%v)",
					try, s, delay, s.others)
			}
			if s.wall-s.own >= work/4 {
				waited = true
				break
			}
		}
		if !waited {
			t.Logf("no try waited a quarter of the work without blocking: this machine is too busy, or too idle, to " +
				"show it")
		}
	})
}

// TestOwnTimeTakesOutTheRunQueueDelay: a sample that does not block reads its own time as its wall clock less the
// run-queue delay schedstat reports over it beyond its process's other threads' CPU time (ownTime), to the
// nanosecond. The sample reads a schedstat stand-in whose delay the measured function moves by 100 µs after 200 µs of
// work, and writing it must not block the thread: the stand-in is a memfd (schedStandIn) rewritten in place with
// pwrite, where a file on disk rewritten with os.WriteFile blocked the thread in all five tries in 53 runs of 200
// while small fsync'd writes kept the filesystem's journal committing (2026-10-17). A try counts where the other
// threads had under half the delay's CPU time, so the delay visibly comes out.
func TestOwnTimeTakesOutTheRunQueueDelay(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd := schedStandIn(t)
	rq := &runQueue{fd: fd}
	defer rq.close()
	const delay = 100 * time.Microsecond
	before, after := []byte("100 0005000 3\n"), []byte("200 0105000 4\n")
	for try := range 10 {
		if _, err := syscall.Pwrite(fd, before, 0); err != nil {
			t.Fatal(err)
		}
		runtime.Gosched()
		var werr error
		s := threadSample(rq, func() {
			spinCPU(2 * delay)
			_, werr = syscall.Pwrite(fd, after, 0)
		})
		if werr != nil {
			t.Fatal(werr)
		}
		t.Logf("try %d: %+v", try, s)
		if s.blocked {
			if s.own != s.wall {
				t.Errorf("try %d blocked and measured %+v: want its own time the wall clock", try, s)
			}
			continue
		}
		if want := max(s.wall-max(delay-s.others, 0), 0); s.own != want {
			t.Errorf("a sample over which the run-queue delay moved by %v measured %+v: want its own time %v, its wall "+
				"clock less the delay beyond the other threads' CPU time", delay, s, want)
		}
		if s.others < delay/2 {
			return
		}
	}
	t.Error("no try ran without blocking, and with the process's other threads idle enough to show the delay come out")
}

// TestOwnTimeFormula: ownTime keeps the wall clock of a sample that blocked, and of one that did not takes out the
// run-queue delay only where the process's other threads' CPU time does not account for it, never going under zero.
func TestOwnTimeFormula(t *testing.T) {
	const us = time.Microsecond
	for _, c := range []struct {
		wall, delay, others time.Duration
		blocked             bool
		want                time.Duration
	}{
		{1000 * us, 400 * us, 0, false, 600 * us},        // another process's waits come out
		{1000 * us, 400 * us, 100 * us, false, 700 * us}, // the part the process's own threads filled stays
		{1000 * us, 400 * us, 500 * us, false, 1000 * us},
		{1000 * us, 400 * us, 0, true, 1000 * us}, // a sample that blocked counts whole
		{1000 * us, 1200 * us, 0, false, 0},       // a delay read a little wide never makes it negative
	} {
		if got := ownTime(c.wall, c.delay, c.others, c.blocked); got != c.want {
			t.Errorf("ownTime(wall %v, delay %v, others %v, blocked %v) = %v, want %v", c.wall, c.delay, c.others,
				c.blocked, got, c.want)
		}
	}
}

// schedStandIn is a descriptor a schedstat stand-in can be read from with pread and rewritten in place with pwrite,
// neither of which waits on a disk or a journal: a memfd (memfd_create, its number from LinuxSyscalls, since the
// syscall package does not name it on amd64), or, where the kernel refuses one, a file in /dev/shm. A test that
// finds neither fails rather than measuring a write that can block.
func schedStandIn(t *testing.T) int {
	t.Helper()
	const mfdCloexec = 1 // MFD_CLOEXEC
	if tab, err := LinuxSyscalls(runtime.GOARCH); err == nil {
		if nr, ok := tab["memfd_create"]; ok {
			name := []byte("tego-schedstat\x00")
			fd, _, errno := syscall.Syscall(uintptr(nr), uintptr(unsafe.Pointer(&name[0])), mfdCloexec, 0)
			runtime.KeepAlive(name)
			if errno == 0 {
				return int(fd)
			}
			t.Logf("memfd_create: %v; the stand-in is a file in /dev/shm", errno)
		}
	}
	f, err := os.CreateTemp("/dev/shm", "tego-schedstat-")
	if err != nil {
		t.Fatalf("no memfd and no /dev/shm for the schedstat stand-in: %v", err)
	}
	_ = os.Remove(f.Name())
	fd, err := syscall.Dup(int(f.Fd()))
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	syscall.CloseOnExec(fd)
	return fd
}

// TestASampleThatBlocksCountsWhole: a sample in which the thread blocks counts whole on the wall clock, its waits for
// a CPU included, so that none of a wait the code makes can hide among them. The sample reads the schedstat stand-in
// (schedStandIn), and the measured function moves its run-queue delay by 1 ms before it blocks, so a measure that took
// the delay out of a sample that blocked would read the own time 1 ms under the wall clock on any machine: the real
// delay across a 2 ms receive often reads 0, and such a measure passed 99 runs of 100 against the real schedstat
// (2026-10-17). The thread blocks all but for certain: the goroutine that releases it waits until the measured
// function has started its receive and the kernel reports the thread asleep (/proc/thread-self/task/<tid>/stat's
// state S), then waits 2 ms more; a try in which it still did not (preempted as it parked) is logged and retried.
func TestASampleThatBlocksCountsWhole(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	fd := schedStandIn(t)
	rq := &runQueue{fd: fd}
	defer rq.close()
	stat := fmt.Sprintf("/proc/self/task/%d/stat", syscall.Gettid())
	asleep := func() bool {
		b, err := os.ReadFile(stat)
		if err != nil {
			return false
		}
		// The state follows the command name's closing parenthesis.
		i := strings.LastIndexByte(string(b), ')')
		return i >= 0 && i+2 < len(b) && b[i+2] == 'S'
	}
	const wait = 2 * time.Millisecond
	before, after := []byte("100 0005000 3\n"), []byte("200 1005000 4\n") // the delay moves by 1 ms
	for try := range 5 {
		if _, err := syscall.Pwrite(fd, before, 0); err != nil {
			t.Fatal(err)
		}
		var started atomic.Bool
		ch := make(chan struct{})
		go func() {
			for !started.Load() || !asleep() {
				time.Sleep(50 * time.Microsecond)
			}
			time.Sleep(wait)
			close(ch)
		}()
		var werr error
		s := threadSample(rq, func() {
			_, werr = syscall.Pwrite(fd, after, 0)
			started.Store(true)
			<-ch
		})
		if werr != nil {
			t.Fatal(werr)
		}
		t.Logf("try %d: a receive released 2ms after the thread slept, 1ms of run-queue delay over it: %+v", try, s)
		if !s.blocked {
			continue
		}
		if s.own != s.wall || s.wall < wait {
			t.Errorf("a receive that blocked, with 1ms of run-queue delay over it, measured %+v: want its own time its "+
				"wall clock, at least %v", s, wait)
		}
		return
	}
	t.Error("the thread never blocked in a receive released 2ms after it slept")
}

// TestRunQueueParsesSchedstat: the delay is schedstat's second figure, and a line that is not schedstat's reads as
// none.
func TestRunQueueParsesSchedstat(t *testing.T) {
	dir := t.TempDir()
	for _, c := range []struct {
		text string
		want time.Duration
		ok   bool
	}{
		{"2373488 0 1\n", 0, true},
		{"95129418123 1234567 9001\n", 1234567, true},
		{"95129418123\n", 0, false},
		{"", 0, false},
		{"x y z\n", 0, false},
	} {
		p := dir + "/schedstat"
		if err := os.WriteFile(p, []byte(c.text), 0o600); err != nil {
			t.Fatal(err)
		}
		fd, err := syscall.Open(p, syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		q := &runQueue{fd: fd}
		got, ok := q.read()
		q.close()
		if got != c.want || ok != c.ok {
			t.Errorf("%q: %v, %v; want %v, %v", c.text, got, ok, c.want, c.ok)
		}
	}
}

// spinCPU works on the calling thread until its CPU time has advanced by d.
func spinCPU(d time.Duration) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	start := ThreadCPU.read()
	x := uint64(1)
	for ThreadCPU.read()-start < d {
		for range 1000 {
			x = x*6364136223846793005 + 1
		}
	}
	spinSink = x
}

var spinSink uint64
