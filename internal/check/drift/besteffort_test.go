// SPDX-License-Identifier: Apache-2.0

package drift

import (
	"slices"
	"testing"
)

// TestDriftReportsBestEffortCells is ADR 0041 D7's drift half: run_start's best_effort, the gate cells a run
// decided on copied syscall facts and never counted as enforced, is carried on the run's report and, over an
// aggregate, as the union of its runs' cells in a fixed order. It is reported, never counted as drift.
func TestDriftReportsBestEffortCells(t *testing.T) {
	report := func(cells ...string) *Report {
		start := runStartLine()
		if cells != nil {
			start["best_effort"] = cells
		}
		rep, err := Compute(readerOver(t, modelLedger(start, runEndLine())), modelTable())
		if err != nil {
			t.Fatalf("compute: %v", err)
		}
		return rep
	}
	one := report("gate.fs.read/open", "gate.exec")
	if want := []string{"gate.fs.read/open", "gate.exec"}; !slices.Equal(one.BestEffort, want) || one.Drifted() {
		t.Fatalf("best effort %v (drifted %t), want %v and no drift", one.BestEffort, one.Drifted(), want)
	}
	if none := report(); len(none.BestEffort) != 0 {
		t.Fatalf("a run with no cell reports %v", none.BestEffort)
	}
	agg, err := Aggregate([]*Report{one, report("gate.exec", "gate.net/unix-datagram"), report()})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"gate.exec", "gate.fs.read/open", "gate.net/unix-datagram"}; !slices.Equal(agg.BestEffort, want) {
		t.Fatalf("aggregate best effort %v, want the union %v", agg.BestEffort, want)
	}
}
