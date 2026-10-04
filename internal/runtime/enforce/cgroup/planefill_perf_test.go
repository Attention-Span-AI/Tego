// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/testutil"
)

// planFillBudget1000 is the ceiling on the plan half of Prepare's fill at 1000 real rows on the host's own
// filesystem (enforce-plane §10; the guest perf suite budgets the whole phase, `fill.rows1000.ms`). The plan is the
// part that grows with the rows: one fstat, one lstat and one fdinfo read each.
const planFillBudget1000 = 200 * time.Millisecond

// fillRows makes n files under a temp directory, holds each open O_PATH, and returns the plane rows for them and the
// held-descriptor lookup planPlaneFill takes.
func fillRows(tb testing.TB, n int) (*decide.PlaneRows, heldFD) {
	tb.Helper()
	dir := tb.TempDir()
	rows := &decide.PlaneRows{}
	fds := map[string]int{}
	for i := 0; i < n; i++ {
		p := filepath.Join(dir, fmt.Sprintf("g%05d", i))
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			tb.Fatal(err)
		}
		fd, err := unix.Open(p, unix.O_PATH|unix.O_CLOEXEC, 0)
		if err != nil {
			tb.Fatal(err)
		}
		tb.Cleanup(func() { _ = unix.Close(fd) })
		fds[p] = fd
		rows.FS = append(rows.FS, decide.PlaneRow{Path: p, Kind: decide.PlaneReadDeny})
	}
	return rows, func(path string) (int, bool) { fd, ok := fds[path]; return fd, ok }
}

// TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows fails when the plan's cost per row grows past the budget: the
// 0.5 ms a row qa-perf measured for the whole fill (3,800 rows: 2.3 s) would fail it; the plan alone is 20 to 30 us a row.
// In budget mode (testutil.BudgetsEnv, set by scripts/timing-budgets.sh) the figure is one plan on the wall clock,
// held to the budget; in the unit gate it is the fastest of five plans in the thread's own time
// (testutil.MinOfThread: the plan runs on the calling goroutine), held to testutil.CeilingFactor times it, its wall
// clock to testutil.WallCeilingFactor times it (docs/BENCHMARKS.md, "Timing budgets in the test suites").
func TestPlanPlaneFillStaysUnderItsBudgetAt1000Rows(t *testing.T) {
	mode := testutil.TimingMode(t)
	rows, held := fillRows(t, 1000)
	rounds := 5
	if mode.Budgets() {
		rounds = 1
	}
	var plan *planeFillPlan
	var err error
	m := mode.Measure(rounds, func() { plan, err = planPlaneFill(rows, 1, 1, held, hostIdentity{}) })
	if err != nil {
		t.Fatalf("planPlaneFill: %v", err)
	}
	if len(plan.Entries) != 1000 {
		t.Fatalf("%d entries, want 1000", len(plan.Entries))
	}
	t.Logf("planPlaneFill at 1000 rows: %v; a row: %v", m[0], m[0].Div(1000))
	mode.Judge(t, testutil.Budget{Name: "planPlaneFill at 1000 rows", Limit: planFillBudget1000, Spec: "enforce-plane §10"},
		m[0])
}

// BenchmarkPlanPlaneFill is the plan's cost at 1, 1000 and one row under the cap, per row count.
func BenchmarkPlanPlaneFill(b *testing.B) {
	for _, n := range []int{1, 1000, decide.PlaneRowsMax - 1} {
		b.Run(fmt.Sprintf("rows=%d", n), func(b *testing.B) {
			rows, held := fillRows(b, n)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := planPlaneFill(rows, 1, 1, held, hostIdentity{}); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
