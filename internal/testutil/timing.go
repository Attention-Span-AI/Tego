// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"testing"
	"time"
	"unsafe"
)

// BudgetsEnv is the switch of budget mode. TEGO_TIMING_BUDGETS=1 makes a timing test assert each absolute budget
// it holds (a Limit, most with a Target, written as figures on the reference box: a duration, or a ratio to a fixed
// workload) exactly as its spec defines it: on the wall clock, against its Limit (over it fails) and its Target
// (over it prints TARGET-MISS). scripts/timing-budgets.sh sets it, in CI's bench-gate job, where the budgets run
// alone on the job's own runner before anything else of the job does, and in `make budgets` on a developer's quiet
// machine. Unset, a test is in the unit gate (precommit, CI's test jobs, any `go test`) and holds the same
// measurement to CeilingFactor times the Limit: where the cost is the calling goroutine's, on the thread's own time
// (Figure.Own: the wall clock less the waits for a CPU that other processes filled, in a sample in which the thread
// never blocked, so the code's work, the work it hands to the process's other threads and the waits it causes
// itself, but for a wait that another process's work fills without the thread blocking), with its wall clock, which
// hides no wait, held to WallCeilingFactor times the Limit too, and where it is a pace across threads and processes,
// on the wall clock. docs/BENCHMARKS.md, "Timing budgets in the test suites", has the method and the measurements
// behind it.
const BudgetsEnv = "TEGO_TIMING_BUDGETS"

// CeilingFactor is how many times its Limit a figure must reach before the unit gate fails it. A busy machine
// slows CPU work by a lower clock and a busy sibling hyperthread, which no statistic over its samples removes and
// no measuring of the machine models (the code's own sensitivity to them differs from any yardstick's): under 16
// busy loops on the reference box (an i7-10870H, 8 cores and 16 threads) ADR 0048 C8's cases measured 2.3 to 4.9
// times their quiet figures in thread CPU time, up to 2.2 times their Limits. The thread's own time keeps that
// slowdown, which the hardware bounds, and leaves out the waits for a CPU, which nothing bounds, from every sample
// that did not block; the fastest of many samples is one that did not. Ten Limits stays clear of it, so in the unit
// gate a failure of a thread's figure means the code does or waits several times what its budget allows, whatever
// else the machine runs; whether it meets the budget itself is budget mode's question, asked where the machine is
// quiet. A pace across threads and processes (a Figure with only its wall clock) is held to ten Limits as well, and
// has no own time to keep the machine's waits out: its margin is the machine's (docs/BENCHMARKS.md).
const CeilingFactor = 10

// WallCeilingFactor is how many times its Limit a measurement's wall clock must reach before the unit gate fails it
// where the figure is the thread's own time (Figure.OnThread). The own time can hide a wait the code makes where
// another process's work fills it and the thread never blocks: a thread another process's thread takes the CPU from
// just as its goroutine parks for a sleep is still in the run queue when the sleep ends, so the sleep is all run-queue
// delay and never a voluntary switch, and the fastest of many samples is one where that happened (a 2 ms sleep read
// 4.0 ms of own time for 4 ms of work so, on a CPU shared with a spinning thread, 2026-10-17); a wait that yields its
// CPU (sched_yield) instead of sleeping hides so on any CPU another process keeps busy (a 1 ms one read +27.9 µs).
// A wait for work the code hands to another goroutine does not hide: that work is the process's, and stays in the own
// time (MinOfThread). The wall clock never hides a wait, and its fastest sample is one the machine delayed least:
// under 16 busy loops in a 4-vCPU KVM guest the worst fastest wall-clock sample of any unmodified case was 6.1 times
// its Limit (ADR 0048 C8's 8192-argument cases, whose samples of milliseconds span scheduler slices; four sweeps of 28
// runs, 2026-10-17). A hundred Limits fails any wait of more than a hundred times the budget on any machine, and
// leaves the own time's ten Limits for the code's work and its waits; one that another process fills on a busy
// machine, between ten and a hundred Limits, only budget mode sees.
const WallCeilingFactor = 100

// Clock is what a timing sample reads.
type Clock int

const (
	// Wall is the monotonic wall clock: what a budget is written in, and the clock that sees everything a sample
	// took, the code's work, every wait it causes (a sleep, a lock, a read that blocks, a reply from another
	// thread) and every wait the machine adds (another tenant's slice, a run queue).
	Wall Clock = iota
	// ThreadCPU is the CPU time of the calling thread (CLOCK_THREAD_CPUTIME_ID), user and system: the work the code
	// did on it, with every wait left out, the scheduler's and the code's own alike. It suits a relative bound, two
	// sizes of the same code; a budget's unit-gate figure is the thread's own time (MinOfThread), which keeps the
	// code's own waits. MinOf locks the goroutine to its thread while it measures on it; the code measured must do
	// its work on the calling goroutine.
	ThreadCPU
)

func (c Clock) String() string {
	if c == ThreadCPU {
		return "thread CPU time"
	}
	return "wall clock"
}

// clockProcessCPUTimeID and clockThreadCPUTimeID are CLOCK_PROCESS_CPUTIME_ID and CLOCK_THREAD_CPUTIME_ID; the
// syscall package does not name them.
const (
	clockProcessCPUTimeID = 2
	clockThreadCPUTimeID  = 3
)

// read is c's reading now.
func (c Clock) read() time.Duration {
	if c != ThreadCPU {
		return time.Duration(nanotime())
	}
	return cpuClock(clockThreadCPUTimeID)
}

// processCPU is the CPU time of every thread of the process so far.
func processCPU() time.Duration { return cpuClock(clockProcessCPUTimeID) }

// cpuClock reads the CPU-time clock id.
func cpuClock(id uintptr) time.Duration {
	var ts syscall.Timespec
	_, _, errno := syscall.Syscall(syscall.SYS_CLOCK_GETTIME, id, uintptr(unsafe.Pointer(&ts)), 0)
	if errno != 0 {
		panic(fmt.Sprintf("testutil: clock_gettime(%d): %v", id, errno))
	}
	return time.Duration(ts.Nano())
}

// epoch anchors nanotime: time.Since reads the monotonic clock.
var epoch = time.Now()

// nanotime is the monotonic clock in nanoseconds since epoch.
func nanotime() int64 { return int64(time.Since(epoch)) }

// MinOf runs rounds rounds of fns, one sample of each a round, with the order rotated from round to round, and
// returns each one's fastest sample on c, in the order fns were given, less the clock's own cost. Another tenant on
// the machine only ever adds to a sample, so the fastest of many is the closest to the code's own cost, and
// interleaving puts a change in the machine's load over the measurement on every side alike, where measuring A's
// rounds and then B's lets a burst land on one side only. The clock's cost is the fastest empty sample, one taken in
// each round the same way as the others and readOverheadSamples before them, and is taken out because a ratio of two
// samples that both carry it reads closer to 1 than the code's own: a thread CPU clock read is a system call, 0.5 to
// 0.7 µs measured on a busy machine, and its cost follows the CPU the thread is on, so the rounds' own empty samples
// match the rounds' figures best (within 30 ns there, where samples taken only beforehand were up to 200 ns off). A
// function too fast to time alone loops itself and the caller divides.
func MinOf(c Clock, rounds int, fns ...func()) []time.Duration {
	if c == ThreadCPU {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
	}
	best := fastest(rounds, 1, func(_ int, fn func(), out []time.Duration) {
		start := c.read()
		fn()
		out[0] = c.read() - start
	}, fns)
	out := make([]time.Duration, len(fns))
	for i := range best {
		out[i] = best[i][0]
	}
	return out
}

// MinOfThread is MinOf on the calling thread's three figures at once, from the same samples (Figure): the wall
// clock, the thread's own time and its CPU time. Each is the fastest sample on that figure, less that figure's own
// cost (the fastest sample on one need not be the fastest on another), and the own time is never under the CPU time.
//
// A sample's own time is its wall clock less the waits for a CPU that other processes filled (ownTime): in a sample in
// which the thread never blocked (no voluntary context switch, getrusage(RUSAGE_THREAD)'s ru_nvcsw unchanged), every
// wait was for a CPU, and the thread's run-queue delay over the sample (the second figure of
// /proc/thread-self/schedstat) comes out, less the CPU time the process's other threads had over it; in a sample in
// which it blocked (a sleep, a lock, a read that waits, a reply from another thread) the wait is the code's, and the
// sample counts whole on the wall clock, waits for a CPU included. Taking the run-queue delay out of a sample that
// blocked would let it hide part of the code's wait: the thread is woken during a sleep (a signal, a runtime
// wake-up), waits for a CPU, and sleeps again, so the delay overlaps the sleep, and the fastest of many samples is the
// one where the most of it did (a 2 ms sleep read 1.3 ms so, 2026-10-17). The other threads' CPU time stays in
// because a wait for work the code hands to another goroutine can be all run-queue delay: where the process has fewer
// CPUs than runnable threads (a cpuset, a small container, a busy machine), even an idle one, the helper's wake-up
// takes the CPU from the thread before it parks, the thread waits in the run queue for the helper's whole run and
// never blocks, and a 500 µs hand-off read 3.7 µs before (2026-10-17). A wait can still hide whole where another
// process fills it: a thread that process preempts just as its goroutine parks is still runnable when the wait ends,
// and a wait that yields its CPU (sched_yield) instead of sleeping never blocks; Judge therefore holds the wall clock
// as well, to WallCeilingFactor times the Limit. A sample reads the process's CPU clock outermost, then the thread's,
// then the wall clock, then the context switches and the run-queue delay innermost, so only waits inside the
// wall-clock interval come out, and the other threads' CPU time is read over a span that holds them. It locks the
// goroutine to its thread: the figures see the work the code does on the calling goroutine, the work it hands to
// others, and every wait that goroutine makes. Where the run-queue delay or the context switches cannot be read (no
// /proc/thread-self/schedstat: a kernel without CONFIG_SCHED_INFO, a sandbox's /proc), every sample counts on the
// wall clock and Figure.RunQueue is false: stricter, never looser.
func MinOfThread(rounds int, fns ...func()) []Figure {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	rq := openRunQueue()
	defer rq.close()
	blocked := make([]int, len(fns))
	best := fastest(rounds, 3, func(i int, fn func(), out []time.Duration) {
		s := threadSample(rq, fn)
		if s.blocked && i >= 0 {
			blocked[i]++
		}
		out[0], out[1], out[2] = s.wall, s.own, s.cpu
	}, fns)
	out := make([]Figure, len(fns))
	for i, b := range best {
		// The own time is never under the CPU time: the thread cannot have waited for less than nothing.
		out[i] = Figure{Wall: b[0], Own: max(b[1], b[2]), CPU: b[2], OnThread: true, RunQueue: rq.ok(),
			Samples: max(rounds, 1), Blocked: blocked[i]}
	}
	return out
}

// sample is one sample's figures on the calling thread: blocked says the thread blocked during it, and own is then
// the wall clock; others is the CPU time the process's other threads had over it.
type sample struct {
	wall, own, cpu, others time.Duration
	blocked                bool
}

// threadSample times fn once on the calling thread, which must be locked to its goroutine, as MinOfThread describes:
// the process's CPU clock outermost, then the thread's, then the wall clock, then the voluntary context switches and
// the run-queue delay (rq) innermost.
func threadSample(rq *runQueue, fn func()) sample {
	p0 := processCPU()
	c0 := ThreadCPU.read()
	w0 := Wall.read()
	v0, vok0 := voluntarySwitches()
	q0 := rq.delay()
	fn()
	q1 := rq.delay()
	v1, vok1 := voluntarySwitches()
	w1 := Wall.read()
	c1 := ThreadCPU.read()
	p1 := processCPU()
	// The process's span holds the thread's, so the thread's work between the two clocks' reads counts as others':
	// under a microsecond more kept (0.8 µs on the reference box), never less.
	s := sample{wall: w1 - w0, cpu: c1 - c0, others: max(p1-p0-(c1-c0), 0)}
	s.blocked = v1 != v0 || !vok0 || !vok1
	s.own = ownTime(s.wall, q1-q0, s.others, s.blocked)
	return s
}

// ownTime is a sample's own time from its wall clock, the run-queue delay over it, the CPU time the process's other
// threads had over it, and whether the thread blocked: the wall clock whole where it blocked, and otherwise the wall
// clock less the delay those threads' work does not account for. On one CPU the other threads' work is all delay of
// the thread's: the work it waits for, which the own time keeps. Where they ran on another CPU at once it was not, and
// keeping it is stricter, never looser: the own time is never over the wall clock.
func ownTime(wall, delay, others time.Duration, blocked bool) time.Duration {
	if blocked {
		return wall
	}
	return max(wall-max(delay-others, 0), 0)
}

// voluntarySwitches is the calling thread's count of voluntary context switches: the times it blocked.
func voluntarySwitches() (int64, bool) {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_THREAD, &ru); err != nil {
		return 0, false
	}
	return ru.Nvcsw, true
}

// fastest is MinOf's statistic over n figures a sample: sample times fn, the i-th of fns (-1 for an empty sample),
// and fills out with its n figures, and best[i][k] is fns[i]'s fastest k-th figure over rounds rotated rounds, less
// the fastest k-th figure of an empty sample taken the same way (readOverheadSamples before the rounds, one in each).
func fastest(rounds, n int, sample func(i int, fn func(), out []time.Duration), fns []func()) [][]time.Duration {
	never := time.Duration(1<<63 - 1)
	took := make([]time.Duration, n)
	overhead := make([]time.Duration, n)
	for k := range overhead {
		overhead[k] = never
	}
	empty := func() {
		sample(-1, emptySample, took)
		for k, d := range took {
			overhead[k] = min(overhead[k], d)
		}
	}
	for range readOverheadSamples {
		empty()
	}
	best := make([][]time.Duration, len(fns))
	for i := range best {
		best[i] = make([]time.Duration, n)
		for k := range best[i] {
			best[i][k] = never
		}
	}
	for r := range max(rounds, 1) {
		empty()
		for j := range fns {
			i := (j + r) % len(fns)
			sample(i, fns[i], took)
			for k, d := range took {
				best[i][k] = min(best[i][k], d)
			}
		}
	}
	for i := range best {
		for k := range best[i] {
			best[i][k] = max(best[i][k]-overhead[k], 0)
		}
	}
	return best
}

// readOverheadSamples is how many empty samples MinOf takes before its rounds, so that a measurement of a few rounds
// has a floor for the clock's cost that no single preempted sample sets.
const readOverheadSamples = 64

// emptySample is what an empty sample times: a call through a variable, as a measured function is called.
var emptySample = func() {}

// runQueue reads the calling thread's run-queue delay: the second figure of /proc/thread-self/schedstat, the
// nanoseconds the thread has spent runnable and waiting for a CPU (Documentation/scheduler/sched-stats.rst), which
// the kernel adds when the thread gets the CPU back. It is opened on the thread it reads, locked to its goroutine.
type runQueue struct {
	fd  int
	buf [64]byte
}

// openRunQueue opens the calling thread's schedstat; on failure every delay reads 0 and ok is false.
func openRunQueue() *runQueue {
	fd, err := syscall.Open("/proc/thread-self/schedstat", syscall.O_RDONLY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return &runQueue{fd: -1}
	}
	q := &runQueue{fd: fd}
	if _, ok := q.read(); !ok {
		q.close()
		return &runQueue{fd: -1}
	}
	return q
}

func (q *runQueue) ok() bool { return q.fd >= 0 }

func (q *runQueue) close() {
	if q.fd >= 0 {
		_ = syscall.Close(q.fd)
		q.fd = -1
	}
}

// delay is the thread's run-queue delay so far, 0 where it cannot be read.
func (q *runQueue) delay() time.Duration {
	d, _ := q.read()
	return d
}

// read parses "<run ns> <run-queue ns> <slices>\n", read again from offset 0 each time.
func (q *runQueue) read() (time.Duration, bool) {
	if q.fd < 0 {
		return 0, false
	}
	n, err := syscall.Pread(q.fd, q.buf[:], 0)
	if err != nil || n <= 0 {
		return 0, false
	}
	b := q.buf[:n]
	i := 0
	for i < len(b) && b[i] != ' ' {
		i++
	}
	i++
	var v int64
	digits := 0
	for ; i < len(b) && b[i] >= '0' && b[i] <= '9'; i++ {
		v = v*10 + int64(b[i]-'0')
		digits++
	}
	if digits == 0 {
		return 0, false
	}
	return time.Duration(v), true
}

// Figure is a measurement a budget is held to. Budget mode's is the wall clock alone (Mode.Measure), as a budget's
// spec writes it. The unit gate's, where the cost is the calling goroutine's, is the thread's own time (MinOfThread):
// the wall clock less the waits for a CPU that other processes filled, where the thread never blocked. CPU time alone
// leaves out every wait the code causes, so a budget held on it would pass a regression that only waits, at any size
// (a copy of ADR 0048 C8's path that slept 20 ms in every command-rule decision did, 2026-10-16), and the wall clock
// alone counts every wait for a CPU another tenant makes, which has no bound on a machine with more runnable threads
// than CPUs.
type Figure struct {
	// Wall is the wall clock: budget mode's figure, and the unit gate's where no thread's own time was taken (a pace
	// across threads and processes).
	Wall time.Duration
	// Own is the thread's own time, the unit gate's figure where OnThread: its work, the work it handed to the
	// process's other threads, and the waits it made itself.
	Own time.Duration
	// CPU is the thread's CPU time, its work alone, printed beside Own so a failure says whether it worked or waited.
	CPU time.Duration
	// OnThread says Own and CPU were taken (MinOfThread); RunQueue says the run-queue delay was read, so that Own
	// is the wall clock less it rather than the wall clock itself.
	OnThread, RunQueue bool
	// Samples is how many samples the figure is the fastest of, and Blocked how many of them blocked and so counted
	// whole on the wall clock (an A/B difference adds both sides').
	Samples, Blocked int
}

// Sub is f less g on each figure, never below zero: what the A side of an A/B measurement adds to the B side.
func (f Figure) Sub(g Figure) Figure {
	return Figure{Wall: max(f.Wall-g.Wall, 0), Own: max(f.Own-g.Own, 0), CPU: max(f.CPU-g.CPU, 0),
		OnThread: f.OnThread && g.OnThread, RunQueue: f.RunQueue && g.RunQueue, Samples: f.Samples + g.Samples,
		Blocked: f.Blocked + g.Blocked}
}

// Div is f shared out over n: a batch's figure per call.
func (f Figure) Div(n int) Figure {
	d := time.Duration(n)
	f.Wall, f.Own, f.CPU = f.Wall/d, f.Own/d, f.CPU/d
	return f
}

// Over is f's ratio to g on each figure: the code's cost against a fixed workload's.
func (f Figure) Over(g Figure) Ratio {
	r := Ratio{Wall: float64(f.Wall) / float64(max(g.Wall, 1))}
	if f.OnThread && g.OnThread {
		r.Own, r.CPU = float64(f.Own)/float64(max(g.Own, 1)), float64(f.CPU)/float64(max(g.CPU, 1))
		r.OnThread, r.RunQueue = true, f.RunQueue && g.RunQueue
	}
	return r
}

func (f Figure) String() string {
	return f.format(func(d time.Duration) string { return d.String() })
}

// format prints f's figures with each printed by p.
func (f Figure) format(p func(time.Duration) string) string {
	if !f.OnThread {
		return p(f.Wall) + " of wall clock"
	}
	own := "the thread's own time (the wall clock less its run-queue waits other processes filled, where it never " +
		"blocked)"
	if !f.RunQueue {
		own = "the thread's own time (the wall clock: its run-queue waits could not be read)"
	}
	s := fmt.Sprintf("%s of %s, %s of it CPU time; %s of wall clock", p(f.Own), own, p(f.CPU), p(f.Wall))
	if f.Blocked > 0 {
		s += fmt.Sprintf("; %d of %d samples blocked, counted whole on the wall clock", f.Blocked, f.Samples)
	}
	return s
}

// Ratio is a figure over a fixed workload's, measured in the same process, on each of the figures both sides have.
type Ratio struct {
	Wall, Own, CPU     float64
	OnThread, RunQueue bool
}

// Budget is one absolute timing budget: a figure on the reference box with a Target and a Limit, as its spec
// writes them.
type Budget struct {
	// Name is the case, as log lines and failures name it.
	Name string
	// Target is the figure aimed at; over it, budget mode prints TARGET-MISS. Zero is none.
	Target time.Duration
	// Limit is the figure over which budget mode fails.
	Limit time.Duration
	// Spec is where the budget is written, for the messages: "ADR 0048 C8".
	Spec string
	// Added prints the figures as what a change adds ("+12µs"), as an A/B case's are.
	Added bool
}

// Mode is how this run holds its timing budgets: budget mode, or the unit gate.
type Mode struct{ budgets bool }

// TimingMode reads BudgetsEnv: "1" is budget mode, unset or empty the unit gate. Any other value fails t, so that
// a misspelled switch cannot leave a budget run holding only the ceilings.
func TimingMode(t testing.TB) Mode {
	t.Helper()
	switch v := os.Getenv(BudgetsEnv); v {
	case "":
		return Mode{}
	case "1":
		return Mode{budgets: true}
	default:
		t.Fatalf("%s=%q: want 1 (assert the timing budgets) or unset (the unit gate's ceilings)", BudgetsEnv, v)
		return Mode{}
	}
}

// Budgets reports whether this run asserts the budgets themselves.
func (m Mode) Budgets() bool { return m.budgets }

// Measure takes each function's fastest of rounds interleaved rounds as this mode holds a budget's figures: in
// budget mode on the wall clock alone (MinOf), the statistic a budget's spec writes; in the unit gate on the calling
// thread's figures (MinOfThread), for a cost that is the calling goroutine's.
func (m Mode) Measure(rounds int, fns ...func()) []Figure {
	if !m.budgets {
		return MinOfThread(rounds, fns...)
	}
	out := make([]Figure, len(fns))
	for i, d := range MinOf(Wall, rounds, fns...) {
		out[i] = Figure{Wall: d}
	}
	return out
}

// Ceiling is the unit gate's bound for b: CeilingFactor times its Limit.
func (b Budget) Ceiling() time.Duration { return CeilingFactor * b.Limit }

// WallCeiling is the unit gate's bound for the wall clock of a figure held on the thread's own time: WallCeilingFactor
// times b's Limit.
func (b Budget) WallCeiling() time.Duration { return WallCeilingFactor * b.Limit }

// figure prints d as b prints its figures.
func (b Budget) figure(d time.Duration) string {
	if b.Added {
		return "+" + d.String()
	}
	return d.String()
}

// Judge holds f to b. In budget mode f must be the wall clock's alone (else t fails: a budget is a wall-clock figure,
// taken by its spec's statistic); over b's Target it logs TARGET-MISS, and over its Limit it fails t. In the unit
// gate, where f is OnThread, it fails t when f's own time is over b's Ceiling or its wall clock over b's WallCeiling,
// and where it is not (a pace across threads), when its wall clock is over b's Ceiling; it logs every figure and
// where the Limit itself is asserted, and prints no TARGET-MISS, since a figure taken on a busy machine is not the one
// the Target is written in. The budget's figures are never changed.
func (m Mode) Judge(t testing.TB, b Budget, f Figure) {
	t.Helper()
	if m.budgets {
		if f.OnThread {
			t.Fatalf("%s: budget mode measured the thread's own figures; a budget is a wall-clock figure, taken "+
				"alone (%s)", b.Name, b.Spec)
			return
		}
		d := f.Wall
		target := "no target"
		if b.Target > 0 {
			target = "target " + b.figure(b.Target)
		}
		t.Logf("%s: %s (%s, limit %s; %s, budget mode)", b.Name, b.figure(d), target, b.figure(b.Limit), b.Spec)
		if b.Target > 0 && d > b.Target {
			t.Logf("TARGET-MISS: %s %s > %s (%s)", b.Name, b.figure(d), b.figure(b.Target), b.Spec)
		}
		if d > b.Limit {
			t.Errorf("%s: %s over the %s limit (%s)", b.Name, b.figure(d), b.figure(b.Limit), b.Spec)
		}
		return
	}
	got := f.format(b.figure)
	if !f.OnThread {
		t.Logf("%s: %s (unit-gate ceiling %s, %d times the %s limit of %s, which %s=1 asserts)", b.Name, got,
			b.figure(b.Ceiling()), CeilingFactor, b.figure(b.Limit), b.Spec, BudgetsEnv)
		if f.Wall > b.Ceiling() {
			t.Errorf("%s: %s of wall clock, over the unit gate's %s ceiling (%d times the %s limit, %s): the code does "+
				"or waits several times what its budget allows", b.Name, b.figure(f.Wall), b.figure(b.Ceiling()),
				CeilingFactor, b.figure(b.Limit), b.Spec)
		}
		return
	}
	t.Logf("%s: %s (unit-gate ceilings %s of own time and %s of wall clock, %d and %d times the %s limit of %s, which "+
		"%s=1 asserts)", b.Name, got, b.figure(b.Ceiling()), b.figure(b.WallCeiling()), CeilingFactor, WallCeilingFactor,
		b.figure(b.Limit), b.Spec, BudgetsEnv)
	if f.Own > b.Ceiling() {
		t.Errorf("%s: %s of the thread's own time, over the unit gate's %s ceiling (%d times the %s limit, %s): the "+
			"code does or waits several times what its budget allows (%s)", b.Name, b.figure(f.Own),
			b.figure(b.Ceiling()), CeilingFactor, b.figure(b.Limit), b.Spec, got)
	}
	if f.Wall > b.WallCeiling() {
		t.Errorf("%s: %s of wall clock, over the unit gate's %s wall-clock ceiling (%d times the %s limit, %s): even "+
			"the fastest sample took a hundred times what its budget allows (%s)", b.Name, b.figure(f.Wall),
			b.figure(b.WallCeiling()), WallCeilingFactor, b.figure(b.Limit), b.Spec, got)
	}
}

// JudgeRatio holds r, the code's cost over a fixed workload's measured in the same process, to limit as Judge holds
// a Figure: in budget mode (r on the wall clock alone) over limit fails; in the unit gate the ratio of the thread's
// own times over CeilingFactor times it, or of the wall clock over WallCeilingFactor times it, fails (where r is not
// OnThread, its wall-clock ratio over CeilingFactor times it). A fixed workload is a
// yardstick, and a busy machine does not slow the code as it slows the yardstick: under heavy load on the reference
// box Borrow's ratio to two atomic adds read 2.50 where it reads 1.6 to 1.9 quiet, so such a ratio is a figure on a
// machine, like a duration. A ratio of the same code at two sizes ("cost does not grow with the entries") is not one
// of these: both sides slow alike, and those tests hold their bounds in every run.
func (m Mode) JudgeRatio(t testing.TB, name, spec string, r Ratio, limit float64) {
	t.Helper()
	if m.budgets {
		if r.OnThread {
			t.Fatalf("%s: budget mode measured the thread's own figures; a budget is a wall-clock figure, taken "+
				"alone (%s)", name, spec)
			return
		}
		t.Logf("%s: ratio %.2f (limit %.2f; %s, budget mode)", name, r.Wall, limit, spec)
		if r.Wall > limit {
			t.Errorf("%s: ratio %.2f over the %.2f limit (%s)", name, r.Wall, limit, spec)
		}
		return
	}
	ceiling := CeilingFactor * limit
	if !r.OnThread {
		got := fmt.Sprintf("ratio %.2f on the wall clock", r.Wall)
		t.Logf("%s: %s (unit-gate ceiling %.1f, %d times the %.2f limit of %s, which %s=1 asserts)", name, got,
			ceiling, CeilingFactor, limit, spec, BudgetsEnv)
		if r.Wall > ceiling {
			t.Errorf("%s: %s, over the unit gate's %.1f ceiling (%d times the %.2f limit, %s): the code does or waits "+
				"several times what its budget allows", name, got, ceiling, CeilingFactor, limit, spec)
		}
		return
	}
	wallCeiling := WallCeilingFactor * limit
	got := fmt.Sprintf("ratio %.2f of the thread's own times, %.2f of CPU time, %.2f on the wall clock", r.Own, r.CPU,
		r.Wall)
	if !r.RunQueue {
		got += " (run-queue waits not read: the own times are the wall clock)"
	}
	t.Logf("%s: %s (unit-gate ceilings %.1f of own times and %.1f on the wall clock, %d and %d times the %.2f limit of "+
		"%s, which %s=1 asserts)", name, got, ceiling, wallCeiling, CeilingFactor, WallCeilingFactor, limit, spec,
		BudgetsEnv)
	if r.Own > ceiling {
		t.Errorf("%s: %s, over the unit gate's %.1f ceiling of own times (%d times the %.2f limit, %s): the code does "+
			"or waits several times what its budget allows", name, got, ceiling, CeilingFactor, limit, spec)
	}
	if r.Wall > wallCeiling {
		t.Errorf("%s: %s, over the unit gate's %.1f wall-clock ceiling (%d times the %.2f limit, %s)", name, got,
			wallCeiling, WallCeilingFactor, limit, spec)
	}
}
