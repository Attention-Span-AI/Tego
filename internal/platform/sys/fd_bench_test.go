// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"flag"
	"slices"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil"
)

// The lease budget (ADR 0023's 2026-10-05 note, P1–P3 and P9). bench-gate.sh runs Borrow, Hold and
// OwnedOpenClose against the base commit; the pins below hold what it cannot: the allocation counts on every
// runner, and Borrow's cost as a ratio to two atomic adds measured in the same process, which travels between quiet
// machines where a nanosecond figure does not (a busy one moves it too: TestBorrowCostRatio).

// borrowTargetNS is the plan's per-Borrow target (plans/adr0023.md C1). The note withdraws it
// as a budget: one locked add costs 6.0–7.7 ns on the reference box, so no correct two-atomic lease meets it.
// It stays printed, as TARGET-MISS with the measured figure, so the miss is never silent.
const borrowTargetNS = 5

// costRatioCeiling is P1's budget: Borrow on a concrete *FD at most 2.5 × twoAtomicAdds.
const costRatioCeiling = 2.5

var sink atomic.Int64

func nopBorrow(n int) error {
	sink.Store(int64(n))
	return nil
}

// TestBorrowAllocatesNothing is P1's pin: Borrow on a concrete *FD, with a closure that captures a local,
// allocates nothing.
func TestBorrowAllocatesNothing(t *testing.T) {
	f := openNull(t)
	local := 0
	if a := testing.AllocsPerRun(1000, func() {
		_ = f.Borrow(func(n int) error { local += n; return nil })
	}); a != 0 {
		t.Fatalf("Borrow allocates %v per call, want 0", a)
	}
	var st unix.Stat_t
	if a := testing.AllocsPerRun(1000, func() { _ = f.Fstat(&st) }); a != 0 {
		t.Fatalf("Fstat allocates %v per call, want 0", a)
	}
}

// TestHoldAllocatesOne is P2's pin: Hold plus Return is at most one allocation, the Lease.
func TestHoldAllocatesOne(t *testing.T) {
	if testHooks != nil {
		t.Skip("a tegotesthooks build records each holder's PC")
	}
	f := openNull(t)
	if a := testing.AllocsPerRun(1000, func() {
		l, err := f.Hold()
		if err != nil {
			panic(err)
		}
		l.Return()
	}); a > 1 {
		t.Fatalf("Hold+Return allocates %v, want at most 1", a)
	}
}

// TestOwnerIsTwentyFourBytes is P9's size: an owner that escapes is one 24-byte allocation, which P5's B/op
// expectation for the supervisor's per-connect owners (+48–64 B) rests on. The slow path stays out of it.
func TestOwnerIsTwentyFourBytes(t *testing.T) {
	if got := unsafe.Sizeof(FD{}); got != 24 {
		t.Fatalf("sys.FD is %d bytes, want 24", got)
	}
	if a := testing.AllocsPerRun(100, func() {
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			panic(err)
		}
		_ = f.Close()
	}); testHooks == nil && a > 2 {
		t.Fatalf("an owned open and close allocates %v, want at most 2 (the path, the owner)", a)
	}
}

// TestBorrowCostRatio is P1's time pin: Borrow costs at most 2.5 times twoAtomicAdds, measured in this process
// (prototype: ratio 1.6–1.9). Two atomic adds are a fixed workload, and a busy machine does not slow Borrow as it
// slows them (the ratio read 2.50 under heavy load on the reference box), so the pin is held as the timing budgets
// are (docs/BENCHMARKS.md, "Timing budgets in the test suites"): in budget mode (testutil.BudgetsEnv, set by
// scripts/timing-budgets.sh) as P1 writes it, the median of five testing.Benchmark runs of each, against 2.5; in the
// unit gate as the ratio of the fastest of 2000 batches of 1000 calls of each in the thread's own time
// (testutil.MinOfThread), the two interleaved with the side that goes first alternating, against ten times it, and the
// ratio of their wall clocks against a hundred times it. It is skipped under -race, which instruments every atomic,
// and -short.
func TestBorrowCostRatio(t *testing.T) {
	if raceEnabled {
		t.Skip("the race detector instruments every atomic, so the ratio measures it, not the lease")
	}
	if testing.Short() {
		t.Skip("a timing pin; -short skips it")
	}
	mode := testutil.TimingMode(t)
	var borrow, adds float64
	var ratio testutil.Ratio
	if mode.Budgets() {
		// testing.Benchmark runs each for -test.benchtime, 1 s unless set: ten runs of that would put ten seconds
		// into the run, where 100 ms each measures the ratio as steadily.
		if bt := flag.Lookup("test.benchtime"); bt != nil && bt.Value.String() == bt.DefValue {
			if err := flag.Set("test.benchtime", "100ms"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = flag.Set("test.benchtime", bt.DefValue) })
		}
		median := func(fn func(*testing.B)) float64 {
			var ns []float64
			for range 5 {
				r := testing.Benchmark(fn)
				ns = append(ns, float64(r.T.Nanoseconds())/float64(r.N))
			}
			slices.Sort(ns)
			return ns[2]
		}
		borrow, adds = median(BenchmarkBorrow), median(BenchmarkTwoAtomicAdds)
		ratio = testutil.Ratio{Wall: borrow / adds}
	} else {
		f := openNull(t)
		var x atomic.Uint64
		const batch = 1000
		m := testutil.MinOfThread(2000,
			func() {
				for range batch {
					_ = f.Borrow(nopBorrow)
				}
			},
			func() {
				for range batch {
					x.Add(1)
					x.Add(^uint64(0))
				}
			})
		borrow, adds = float64(m[0].Own.Nanoseconds())/batch, float64(m[1].Own.Nanoseconds())/batch
		ratio = m[0].Over(m[1])
		t.Logf("a call, Borrow and twoAtomicAdds: %v and %v", m[0].Div(batch), m[1].Div(batch))
	}
	t.Logf("Borrow %.2f ns/op, twoAtomicAdds %.2f ns/op", borrow, adds)
	if mode.Budgets() && borrow > borrowTargetNS {
		t.Logf("TARGET-MISS: Borrow %.2f ns/op > %d ns (the plan's target, withdrawn as a budget by ADR 0023's "+
			"2026-10-05 note: one locked add is 6.0-7.7 ns on the reference box)", borrow, borrowTargetNS)
	}
	mode.JudgeRatio(t, "Borrow against two atomic adds", "ADR 0023 P1", ratio, costRatioCeiling)
}

// BenchmarkBorrow is P1: one uncontended Borrow on a concrete *FD.
func BenchmarkBorrow(b *testing.B) {
	f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	b.ReportAllocs()
	start := time.Now()
	for b.Loop() {
		_ = f.Borrow(nopBorrow)
	}
	reportTarget(b, start)
}

// reportTarget prints the plan's 5 ns target as TARGET-MISS when the run missed it. A benchmark's log is
// always printed, so the line reaches every benchmark run's output.
func reportTarget(b *testing.B, start time.Time) {
	if b.N < 1_000_000 {
		return // a calibration round, not the measurement
	}
	if ns := float64(time.Since(start).Nanoseconds()) / float64(b.N); ns > borrowTargetNS {
		b.Logf("TARGET-MISS: Borrow %.2f ns/op > %d ns (the plan's target; ADR 0023's 2026-10-05 note budgets "+
			"the ratio to two atomic adds instead, TestBorrowCostRatio)", ns, borrowTargetNS)
	}
}

// BenchmarkHold is P2: Hold plus Return, the per-loop-lifetime lease.
func BenchmarkHold(b *testing.B) {
	f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	b.ReportAllocs()
	for b.Loop() {
		l, err := f.Hold()
		if err != nil {
			b.Fatal(err)
		}
		l.Return()
	}
}

// BenchmarkBorrowParallel is P3, recorded: Borrow from GOMAXPROCS goroutines on one FD, the cost of
// contention that P4 keeps off every per-event path.
func BenchmarkBorrowParallel(b *testing.B) {
	f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
	if err != nil {
		b.Fatal(err)
	}
	defer f.Close()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = f.Borrow(nopBorrow)
		}
	})
}

// BenchmarkTwoAtomicAdds is the calibration TestBorrowCostRatio divides by: the two locked adds a lease needs
// at the least.
func BenchmarkTwoAtomicAdds(b *testing.B) {
	var x atomic.Uint64
	for b.Loop() {
		x.Add(1)
		x.Add(^uint64(0))
	}
}

// BenchmarkOwnedOpenClose is P9: open and close of /dev/null through an owner, against BenchmarkRawOpenClose.
func BenchmarkOwnedOpenClose(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		f, err := Own(unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0))
		if err != nil {
			b.Fatal(err)
		}
		_ = f.Close()
	}
}

// BenchmarkRawOpenClose is P9's reference: the same open and close on a bare number.
func BenchmarkRawOpenClose(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		n, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			b.Fatal(err)
		}
		_ = unix.Close(n)
	}
}
