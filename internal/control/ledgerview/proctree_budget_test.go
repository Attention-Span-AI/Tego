// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"math/rand/v2"
	"runtime"
	"testing"
	"time"
)

// budgetTreeRun writes one run of procs processes shaped like a busy agent's: a random recursive tree (each process
// is started by an earlier one, seeded), then a chain of chain processes each started by the one before (a build
// that nests shells), each process with its own command, two lines of work and, every seventh, a refused exec. The
// lines are the ones xrun writes for the other tree tests.
func budgetTreeRun(t testing.TB, procs, chain int) *Run {
	t.Helper()
	rng := rand.New(rand.NewPCG(5, uint64(procs))) //nolint:gosec // a seeded fixture
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-tree04")
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"launcher_pid":100,"launcher_start_ns":5`)
	x.exec(200, 6, "100/5", false, "codex")
	pid := func(i int) string { return fmt.Sprintf("%d/7", 1001+i) }
	total := procs + chain
	for i := range total {
		p := "200/6" // codex starts the first process, and the first of the chain
		switch {
		case i > procs:
			p = pid(i - 1)
		case i > 0 && i < procs:
			p = pid(rng.IntN(i))
		}
		x.exec(1001+i, 7, p, i%7 == 3, "git", "status", "--porcelain", fmt.Sprintf("path/%d", i))
		x.add(1001+i, `"kind":"fs","source":"seccomp","rule":"fs.read[/]","verdict":"allow","authority":"rule","op":"open","flags":0,"path":"/repo/.git/HEAD"`)
		x.add(1001+i, `"kind":"net","source":"seccomp","rule":"net[tcp://example.com:443]","verdict":"allow","authority":"rule","dst":"93.184.216.34:443","host":"example.com","proto":"tcp"`)
	}
	return x.write(t)
}

// coldTree is what a new version of a run costs the Processes page: its line index and its tree, built from scratch,
// and every command masked, as the page shows a few hundred of them.
func coldTree(r *Run) (*ProcTree, uint64) {
	evs := r.AllEvents()
	var tr *ProcTree
	_, allocs := allocated(func() {
		x := buildLineIndex(r.ID, evs)
		tr = buildProcTree(r.ID, evs, x)
		walk(tr.Root, func(n *ProcNode) { n.Command() })
	})
	return tr, allocs
}

// TestProcessTreeBudget is LG-P5's acceptance (c), by construction. The tree of the biggest run of a ledger, cold per
// version, was to build in under 30 ms for the 350,000-line ledger's biggest run. Time on a shared runner proves
// nothing, so this holds what makes it true, counted exactly:
//
//   - Building the tree costs a bounded number of allocations per line (the index reads exec_id and
//     parent_exec_id straight from the line, execIDs, instead of decoding it).
//   - It is linear: eight times the lines cost no more than eight times the allocations (and some slack), on a
//     run that is a random tree with a deep chain in it. A step that grew with processes times lines or with a
//     chain's depth squared would fail here, on any machine.
//   - The tree it builds is the run's: every process once, its lines and refusals counted.
//
// The one wall-clock bound is a hang guard, which says nothing about the budget: the biggest run the store holds
// builds in well under a minute.
func TestProcessTreeBudget(t *testing.T) {
	const perLine, growth = 4.25, 1.25 // allocations a line may cost, and the slack over a linear step
	small := budgetTreeRun(t, 500, 50)
	big := budgetTreeRun(t, 4000, 400)
	for _, c := range []struct {
		name  string
		r     *Run
		procs int
	}{{"small", small, 550}, {"big", big, 4400}} {
		// The run's window must hold every line, or the tree is of a part of the fixture.
		if want := 3*c.procs + 2; c.r.Lines != want || len(c.r.AllEvents()) != want {
			t.Fatalf("%s: %d lines, %d in the window, want %d", c.name, c.r.Lines, len(c.r.AllEvents()), want)
		}
	}
	// Whatever the first build costs in memo setup, the later takes cost the same: the figure is the second take's.
	coldTree(small)
	smallTree, smallAllocs := coldTree(small)
	coldTree(big)
	start := time.Now()
	bigTree, bigAllocs := coldTree(big)
	if d := time.Since(start); d > time.Minute {
		t.Errorf("the tree of %d lines took %v: a hang", big.Lines, d)
	}
	t.Logf("small: %d lines, %d processes, %d allocations (%.2f a line); big: %d lines, %d processes, %d allocations (%.2f a line)",
		small.Lines, smallTree.Procs, smallAllocs, float64(smallAllocs)/float64(small.Lines),
		big.Lines, bigTree.Procs, bigAllocs, float64(bigAllocs)/float64(big.Lines))

	if smallTree.Procs != 552 || bigTree.Procs != 4402 { // and codex, and the launcher
		t.Errorf("processes %d and %d, want 552 and 4402", smallTree.Procs, bigTree.Procs)
	}
	nodes, refused, wantRefused := 0, 0, 0
	walk(bigTree.Root, func(n *ProcNode) {
		nodes++
		if n.Refused {
			refused++
		}
	})
	for i := range 4400 {
		if i%7 == 3 {
			wantRefused++
		}
	}
	if nodes != bigTree.Procs {
		t.Errorf("%d nodes for %d processes", nodes, bigTree.Procs)
	}
	if refused != wantRefused {
		t.Errorf("%d refused processes, want %d", refused, wantRefused)
	}
	if bigTree.Lines+bigTree.NoPID != big.Lines {
		t.Errorf("tree lines %d + %d without a pid, run %d", bigTree.Lines, bigTree.NoPID, big.Lines)
	}
	if per := float64(bigAllocs) / float64(big.Lines); per > perLine {
		t.Errorf("%.2f allocations a line, budget %.2f", per, perLine)
	}
	if lim := float64(smallAllocs) * float64(big.Lines) / float64(small.Lines) * growth; float64(bigAllocs) > lim {
		t.Errorf("%d allocations for %d lines, %d for %d: more than linear (budget %.0f)", bigAllocs, big.Lines, smallAllocs, small.Lines, lim)
	}
	runtime.KeepAlive(bigTree)
}
