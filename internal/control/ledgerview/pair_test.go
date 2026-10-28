// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"fmt"
	"testing"
	"time"
)

// pairLine is a ledger line with an explicit pid and monotonic clock, as a refused action and its mirror share them.
func pairLine(run string, seq int, mono uint64, pid int, kind, extra string) string {
	t0 := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC).Add(time.Duration(seq) * time.Millisecond)
	return fmt.Sprintf(`{"v":1,"seq":%d,"id":"%064x","prev":"","ts":"%s","mono_ns":%d,"run":"%s","agent":"a","pid":%d,"tid":%d,"cgroup":1,"kind":"%s","source":"supervisor",%s}`+"\n",
		seq, seq+1, t0.Format(time.RFC3339Nano), mono, run, pid, pid, kind, extra)
}

// TestFoldPairs: a refused action and the kind=refused line that mirrors it count once, everywhere: the run's
// Refusals, Logs' rows and verdict count, and Similar. A refused line with no action next to it stays a refusal of
// its own, and a refused-kind query still finds the mirrors.
func TestFoldPairs(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0003-pairsx"
	conn := `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:43437"`
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:43437"`
	writeRun(t, root, run,
		pairLine(run, 0, 100, 1, "run_start", `"tier":"landlock","command":["sh"]`),
		pairLine(run, 1, 200, 7, "net", conn),
		pairLine(run, 2, 200, 7, "refused", mirror),
		// A line another writer slipped in between the action and its mirror.
		pairLine(run, 3, 300, 7, "net", conn),
		pairLine(run, 4, 310, 9, "fs", `"verdict":"allow","op":"open","path":"x"`),
		pairLine(run, 5, 300, 7, "refused", mirror),
		// An unpaired refused line: a first write the relay reset, with no action line.
		pairLine(run, 6, 400, 7, "refused", `"rule":"net.ask[x]","reason":"ask-denied","op":"first_write","target":"127.0.0.1:43437"`),
		// A refused line a few lines on whose clock is not the action's is not that action's mirror.
		pairLine(run, 7, 500, 7, "net", conn),
		pairLine(run, 8, 510, 9, "fs", `"verdict":"allow","op":"open","path":"y"`),
		pairLine(run, 9, 501, 7, "refused", mirror))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Find(run)
	if r == nil {
		t.Fatal("run not loaded")
	}
	var mirrors []uint64
	for _, e := range r.Events {
		if e.Mirror {
			mirrors = append(mirrors, e.Seq)
		}
	}
	if fmt.Sprint(mirrors) != "[2 5]" {
		t.Errorf("mirrors %v, want [2 5]", mirrors)
	}
	// 3 refused connects (seq 1, 3, 7), the unpaired first write (6) and the refused line that matched no action (9).
	if r.Refusals != 5 {
		t.Errorf("Refusals %d, want 5", r.Refusals)
	}
	pg := s.Query(Filter{Verdicts: []string{"refused"}})
	if pg.Matched != 5 || pg.Counts["refused"] != 5 || pg.Runs != 1 {
		t.Errorf("refused query: matched %d, counted %d, runs %d; want 5, 5, 1", pg.Matched, pg.Counts["refused"], pg.Runs)
	}
	if pg := s.Query(Filter{Kind: "refused"}); pg.Matched != 4 {
		t.Errorf("kind=refused query matched %d, want the 4 refused lines", pg.Matched)
	}
	all := s.Query(Filter{})
	if all.Matched != len(r.Events)-2 {
		t.Errorf("every line: %d, want %d (the two mirrors left out)", all.Matched, len(r.Events)-2)
	}
	sim := FindSimilar(s, &r.Events[1])
	// The three connects and the unpaired refused line to the same destination (the first write names no class).
	if sim.Lines != 4 || sim.Refused != 4 {
		t.Errorf("Similar of the connect: %d lines, %d refused; want 4 and 4", sim.Lines, sim.Refused)
	}
}

// TestFoldInterleavedPairs: two refusals written before either mirror (A1 A2 M1 M2, same rule and reason) still
// count twice, not three or four times: each mirror pairs with the action whose envelope it copies.
func TestFoldInterleavedPairs(t *testing.T) {
	root := t.TempDir()
	const run = "r-aaaa-0004-pairsx"
	conn := `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:43437"`
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:43437"`
	writeRun(t, root, run,
		pairLine(run, 0, 100, 1, "run_start", `"tier":"landlock","command":["sh"]`),
		pairLine(run, 1, 200, 7, "net", conn),
		pairLine(run, 2, 210, 8, "net", conn),
		pairLine(run, 3, 200, 7, "refused", mirror),
		pairLine(run, 4, 210, 8, "refused", mirror))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	r := s.Find(run)
	if r == nil {
		t.Fatal("run not loaded")
	}
	var mirrors []uint64
	for _, e := range r.Events {
		if e.Mirror {
			mirrors = append(mirrors, e.Seq)
		}
	}
	if fmt.Sprint(mirrors) != "[3 4]" || r.Refusals != 2 {
		t.Errorf("mirrors %v, Refusals %d; want [3 4] and 2", mirrors, r.Refusals)
	}
}

// TestLostRunAskNotPending: an open ask of a run that is neither live nor ended is not waiting on anyone; Lost lists
// it, and a live run's open ask is pending.
func TestLostRunAskNotPending(t *testing.T) {
	root := t.TempDir()
	const lost = "r-aaaa-0004-lostxx"
	writeRun(t, root, lost,
		pairLine(lost, 0, 1, 1, "run_start", `"tier":"landlock","command":["sh"]`),
		pairLine(lost, 1, 2, 1, "ask", `"ask_id":"q-1","hold":"open","op":"read","target":"/p/x"`))
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(s.Pending()); n != 0 {
		t.Errorf("a lost run's ask is pending: %d", n)
	}
	if l := s.Lost(); len(l) != 1 || l[0].AskID != "q-1" {
		t.Errorf("Lost = %+v", l)
	}
}

// TestPairsAgreeAcrossAppends: the read model takes a run's lines as they are appended (cache.go), so a mirror can
// come in a later read than its action, and two refusals' mirrors in a read after both. Every mark and count is then
// what one read of the whole file gives, and the Refusals tab lists as many refusals as Run.Refusals counts.
func TestPairsAgreeAcrossAppends(t *testing.T) {
	const run = "r-aaaa-0005-pairsx"
	conn := `"verdict":"refused","rule":"unmatched","reason":"net-not-allowed","proto":"tcp","dst":"127.0.0.1:43437"`
	mirror := `"rule":"unmatched","reason":"net-not-allowed","op":"connect","target":"127.0.0.1:43437"`
	lines := []string{
		pairLine(run, 0, 100, 1, "run_start", `"tier":"landlock","command":["sh"]`),
		pairLine(run, 1, 200, 7, "net", conn),
		pairLine(run, 2, 200, 7, "refused", mirror),
		pairLine(run, 3, 300, 7, "net", conn),
		pairLine(run, 4, 310, 8, "net", conn),
		pairLine(run, 5, 320, 9, "fs", `"verdict":"allow","op":"open","path":"x"`),
		pairLine(run, 6, 300, 7, "refused", mirror),
		pairLine(run, 7, 310, 8, "refused", mirror),
		pairLine(run, 8, 400, 7, "refused", `"rule":"net.ask[x]","reason":"ask-denied","op":"first_write","target":"127.0.0.1:43437"`),
	}
	whole := t.TempDir()
	writeRun(t, whole, run, lines...)
	want, err := LoadRun(whole, run)
	if err != nil {
		t.Fatal(err)
	}
	grown := t.TempDir()
	writeRun(t, grown, run, lines[0])
	for _, l := range lines[1:] {
		if _, err := LoadRun(grown, run); err != nil {
			t.Fatal(err)
		}
		appendLines(t, grown, run, l)
	}
	got, err := LoadRun(grown, run)
	if err != nil {
		t.Fatal(err)
	}
	marks := func(r *Run) string {
		var out []uint64
		for _, e := range r.Events {
			if e.Mirror {
				out = append(out, e.Seq)
			}
		}
		return fmt.Sprint(out)
	}
	if marks(want) != "[2 6 7]" || want.Refusals != 4 {
		t.Fatalf("one read: mirrors %s, Refusals %d; want [2 6 7] and 4", marks(want), want.Refusals)
	}
	if marks(got) != marks(want) || got.Refusals != want.Refusals {
		t.Errorf("read as appended: mirrors %s, Refusals %d; one read: %s, %d", marks(got), got.Refusals, marks(want), want.Refusals)
	}
	listed := 0
	for _, row := range RunRefusals(got) {
		listed += row.Count
	}
	if listed != got.Refusals {
		t.Errorf("the Refusals tab lists %d refusals, Run.Refusals is %d", listed, got.Refusals)
	}
	if a, b := TimelineOf(got, false).Len(), TimelineOf(want, false).Len(); a != b {
		t.Errorf("timeline rows: %d read as appended, %d in one read", a, b)
	}
}
