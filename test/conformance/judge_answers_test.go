// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// cellEvidence is what the kernel runner holds of one cell on one axis once the run is done.
type cellEvidence struct {
	fx   *Fixture
	cell *Cell
	// axis is the run's tier and the plane mode that decides ("" where none does); colTier names compile --test's
	// column the cell is read from.
	axis    NamingAxis
	colTier Tier
	// want is the cell's answer on the axis (Cell.WantOn), its rule substituted; zero for a judged cell.
	want Want
	// floor: tier 1's floor answers the cell on this kernel, not the rules compile --test's column holds.
	floor bool
	// judged: a generated cell the floor does not answer, whose judge is the kernel (ADR 0017 D1).
	judged bool
	// finding: the cell's kernel answer on this axis is a recorded finding, judged by the invariants alone.
	finding bool
	outcome Outcome
	// column is compile --test's row for the cell, nil where the column has none.
	column *compileCell
	// lines are the action's verdict lines (ledgerLines).
	lines []map[string]any
}

// cellJudgement is what the kernel, parity and ledger runners conclude of one cell on one axis.
type cellJudgement struct {
	// Failures are the disagreements, keyed by runner (RunnerKernel, RunnerParity, RunnerLedger).
	Failures map[string]string
	// RuleCompared says the ledger line's rule was held to compile's: a judged cell whose single line has the
	// kernel's verdict, which the column shares. An axis that ran a generated fixture with a column and compared
	// none dropped the check (TestConformanceKernel fails it).
	RuleCompared bool
	// Naming is the known class the line's rule differs from compile's in (naming.go), counted and not failed.
	Naming NamingClass
}

// judgeAnswers judges one cell's answers on one axis: the kernel's against the cell's (a judged cell's answer is the
// kernel's own), the kernel's against compile --test's column (I9), and the ledger's: exactly one verdict line,
// coherent in how it names the plane, with the cell's verdict and rule, and for a judged cell the rule compile's
// column names wherever the column shares the kernel's verdict, but for the known naming classes (ADR 0017's
// 2026-10-19 note). A handwritten cell's ledger rule is its own Want's. The kernel runner (runFixture) only gathers
// the evidence and records the judgement, so every check here is pinned by TestJudgeAnswers.
func judgeAnswers(ev cellEvidence) (j cellJudgement) {
	j.Failures = map[string]string{}
	o, w := ev.outcome, ev.want
	got, isVerdict := o.Verdict()
	switch {
	case !isVerdict:
		j.Failures[RunnerKernel] = fmt.Sprintf("the action failed with errno %d, neither a success nor a refusal", o.Errno)
		if ev.judged {
			return j // no verdict to hold the ledger line to
		}
	case ev.judged:
		// The kernel's answer is the cell's: the ledger holds one line for the action, with the kernel's verdict.
		w = Want{Verdict: got}
	case got != w.Verdict && !ev.finding: // a finding's kernel answer is the finding, which the invariants log
		j.Failures[RunnerKernel] = fmt.Sprintf("the kernel %s (errno %d), the cell wants %s", got, o.Errno, w.Verdict)
	case got == Refused && w.Errno != 0 && o.Errno != w.Errno:
		j.Failures[RunnerKernel] = fmt.Sprintf("the kernel refused with errno %d, the cell wants errno %d", o.Errno, w.Errno)
	}
	if a := ev.column; a != nil && isVerdict && a.Verdict != got && !ev.finding && !ev.floor {
		j.Failures[RunnerParity] = fmt.Sprintf("compile --test's %s column says %s via %q, the kernel %s (errno %d)",
			ev.colTier, a.Verdict, a.Rule, got, o.Errno)
	}
	if w.NoLine {
		return j
	}
	if raceOps[ev.cell.Op] {
		// One action of thousands of attempts (the TOCTOU harness, the argv race): the ledger may hold a line for each,
		// and a refusal's are all refusals. A refused race has at least one refused line of its target wherever its
		// lines are judged. The argv race's are the supervisor's own exec lines on every axis, and it is refused only
		// when the supervisor refused a copy that read the denied word, which writes that refusal's line (ADR 0048
		// (3)). A symlink race's are the kernel recorder's where it answers (the listener, the plane: every tier but
		// landlock), naming the object each open reached. At tier landlock a symlink race's target has none: the
		// supervisor's lines are advisory (ADR 0016 (2)), they name the link the agent spelled with the model's
		// prediction for whatever the link led to when the supervisor resolved it, which the swap can change before
		// the kernel's open, and they go unjudged (ledgerLines leaves them out; the argv race
		// was exempted with them).
		refusedLines := 0
		for _, l := range ev.lines {
			switch fmt.Sprint(l["verdict"]) {
			case Allow:
				if w.Verdict == Refused {
					j.Failures[RunnerLedger] = fmt.Sprintf("an allow line names the race's target: %v via %q (%v)", l["verdict"], l["rule"], l["source"])
				}
			case Refused:
				refusedLines++
			}
		}
		judged := ev.cell.Op == OpRaceArgvExec || ev.axis.Tier != TierLandlock
		if _, has := j.Failures[RunnerLedger]; !has && judged && w.Verdict == Refused && got == Refused && refusedLines == 0 {
			j.Failures[RunnerLedger] = "no refused line names the race's target, though its lines are judged on this axis"
		}
		return j
	}
	var line map[string]any
	if len(ev.lines) > 0 {
		line = ev.lines[0]
	}
	if msg := planeNaming(line, ev.axis.Plane, ev.axis.Tier); msg != "" && len(ev.lines) == 1 {
		j.Failures[RunnerLedger] = msg
		return j
	}
	ledgerRule := fmt.Sprint(line["rule"])
	lineVerdict := w.Verdict
	switch {
	case ev.finding && isVerdict:
		// A finding's kernel answer is not the cell's: its line holds what the kernel answered, whatever rule it names
		// (ADR 0016), so a line that says the cell's verdict for what the kernel did not do still fails.
		lineVerdict, w.Rule = got, ""
	case w.Ledger != "":
		lineVerdict = w.Ledger // a third party's refusal: the line is Tego's own answer (ADR 0016)
	}
	switch {
	case len(ev.lines) == 0:
		j.Failures[RunnerLedger] = "the ledger holds no verdict line for the action"
	case len(ev.lines) > 1:
		j.Failures[RunnerLedger] = fmt.Sprintf("the ledger holds %d verdict lines for one action, want at most one", len(ev.lines))
	case fmt.Sprint(line["verdict"]) != lineVerdict || (w.Rule != "" && ledgerRule != w.Rule):
		j.Failures[RunnerLedger] = fmt.Sprintf("the ledger line is %v via %q (%v), the cell wants %s via %q",
			line["verdict"], line["rule"], line["source"], lineVerdict, w.Rule)
	case ev.judged && ev.column != nil && ev.column.Verdict == got:
		j.RuleCompared = true
		if ledgerRule == ev.column.Rule {
			return j
		}
		if j.Naming = KnownRuleNaming(ev.fx, ev.cell, ev.axis, got, ledgerRule, ev.column.Rule); j.Naming == "" {
			j.Failures[RunnerLedger] = fmt.Sprintf("the ledger line names %q (%v), compile --test's %s column %q: a difference in no known naming class (naming.go)",
				ledgerRule, line["source"], ev.colTier, ev.column.Rule)
		}
	}
	return j
}

// TestJudgeAnswers pins every outcome of the kernel, parity and ledger runners' judgement of one cell, the kernel
// runner's own part being only the gathering of its evidence: above all that a judged grid cell's ledger rule is held
// to compile's, a difference in a known naming class counted and not failed, any
// other one failed.
func TestJudgeAnswers(t *testing.T) {
	grid := map[string]*Fixture{}
	for _, fx := range GenFSGrid() {
		grid[fx.Name] = &fx
	}
	var renameFx *Fixture
	var rename *Cell
	if renameFx = grid["grid-write.none.watch"]; renameFx != nil {
		for i := range renameFx.Cells {
			if renameFx.Cells[i].Name == "rename-across-abc" {
				rename = &renameFx.Cells[i]
			}
		}
	}
	if rename == nil {
		t.Fatal("no cell rename-across-abc in grid-write.none.watch")
	}
	var (
		landlock = NamingAxis{Tier: TierLandlock}
		lsm      = NamingAxis{Tier: TierCgroup, Plane: string(ModeLSM)}
		fmodRet  = NamingAxis{Tier: TierCgroup, Plane: string(ModeFmodRet)}
		allowed  = Outcome{OK: true}
		eacces   = Outcome{Errno: 13}
		eperm    = Outcome{Errno: 1}
		enoent   = Outcome{Errno: 2}
	)
	line := func(verdict, rule string, extra ...string) map[string]any {
		l := map[string]any{"verdict": verdict, "rule": rule, "source": "kernel"}
		for i := 0; i+1 < len(extra); i += 2 {
			l[extra[i]] = extra[i+1]
		}
		return l
	}
	col := func(verdict, rule string) *compileCell { return &compileCell{Verdict: verdict, Rule: rule} }
	// A grid cell the kernel judges: an allowed rename, whose line names the write entry that grants it.
	judged := func(ax NamingAxis, o Outcome, column *compileCell, lines ...map[string]any) cellEvidence {
		return cellEvidence{fx: renameFx, cell: rename, axis: ax, colTier: ax.Tier, judged: true, outcome: o, column: column, lines: lines}
	}
	hand := Fixtures()[0]
	handwritten := func(want Want, o Outcome, column *compileCell, lines ...map[string]any) cellEvidence {
		return cellEvidence{fx: &hand, cell: &hand.Cells[0], axis: landlock, colTier: TierLandlock, want: want, outcome: o, column: column,
			lines: lines}
	}
	raceCell := Cell{Name: "race", Op: OpRaceSymlinkRead, Path: "w/link", Dest: "s/key", Canon: "s/key"}
	race := func(o Outcome, lines ...map[string]any) cellEvidence {
		return cellEvidence{fx: &hand, cell: &raceCell, axis: landlock, colTier: TierLandlock, want: Want{Verdict: Refused}, outcome: o, lines: lines}
	}
	argvRaceCell := Cell{Name: "argv-race", Op: OpRaceArgvExec, Path: "t/race/git", Argv: []string{"git", "push"}}
	argvRace := func(o Outcome, lines ...map[string]any) cellEvidence {
		ev := race(o, lines...)
		ev.cell = &argvRaceCell
		return ev
	}
	listener := NamingAxis{Tier: TierCgroup}
	raceOn := func(ax NamingAxis, o Outcome, lines ...map[string]any) cellEvidence {
		ev := race(o, lines...)
		ev.axis, ev.colTier = ax, ax.Tier
		return ev
	}
	floor := func(ev cellEvidence) cellEvidence { ev.floor = true; return ev }
	finding := func(ev cellEvidence) cellEvidence { ev.finding = true; return ev }
	wantAllow := Want{Verdict: Allow, Rule: "fs.write[./out/]"}
	okLine := line(Allow, "fs.write[./out/]")
	type want map[string]string // runner -> a substring of its failure
	cases := []struct {
		name     string
		ev       cellEvidence
		failures want
		compared bool
		naming   NamingClass
	}{
		// The rule of a judged grid cell, held to compile's.
		{"judged, equal rules", judged(landlock, allowed, col(Allow, "fs.write[./a/]"), line(Allow, "fs.write[./a/]")), nil, true, ""},
		{"judged, a known class", judged(landlock, allowed, col(Allow, "fs.watch[./a/b/c/]"), line(Allow, "fs.write[./a/]")),
			nil, true, NamingRenameNamesGrant},
		{"judged, a difference in no class", judged(landlock, allowed, col(Allow, "fs.watch[./a/b/c/]"), line(Allow, "fs.deny_read[./a/b/]")),
			want{RunnerLedger: "a difference in no known naming class"}, true, ""},
		{"judged, a known class's names at another verdict", judged(landlock, eacces, col(Refused, "fs.watch[./a/b/c/]"), line(Refused, "fs.write[./a/]")),
			want{RunnerLedger: "a difference in no known naming class"}, true, ""},
		{"judged, a known pair of names on the lsm plane", judged(lsm, allowed, col(Allow, "fs.watch[./a/b/c/]"),
			line(Allow, "fs.write[./a/]", "mechanism", "plane", "decision_plane", "lsm")), nil, true, NamingRenameNamesGrant},
		{"judged, a pair in no class on the fmod_ret plane", judged(fmodRet, allowed, col(Allow, "fs.watch[./a/b/c/]"),
			line(Allow, "unmatched", "mechanism", "plane", "decision_plane", "fmod_ret")), want{RunnerLedger: "a difference in no known naming class"}, true, ""},
		// Where the column's verdict is not the kernel's, the parity runner fails the cell and the rule is not compared.
		{"judged, the column's verdict differs", judged(landlock, allowed, col(Refused, "fs.watch[./a/b/c/]"), line(Allow, "fs.write[./a/]")),
			want{RunnerParity: "column says refused"}, false, ""},
		{"judged, no column row", judged(landlock, allowed, nil, line(Allow, "fs.write[./a/]")), nil, false, ""},
		{"judged, neither success nor refusal", judged(landlock, enoent, col(Allow, "fs.write[./a/]")),
			want{RunnerKernel: "errno 2, neither a success nor a refusal"}, false, ""},
		// The line itself, for any cell.
		{"no line", judged(landlock, allowed, col(Allow, "fs.write[./a/]")), want{RunnerLedger: "no verdict line"}, false, ""},
		{"two lines", judged(landlock, allowed, col(Allow, "fs.write[./a/]"), line(Allow, "fs.write[./a/]"), line(Allow, "fs.write[./a/]")),
			want{RunnerLedger: "2 verdict lines"}, false, ""},
		{"the kernel's verdict, the line's another", judged(landlock, allowed, col(Allow, "fs.write[./a/]"), line(Refused, "fs.write[./a/]")),
			want{RunnerLedger: "the cell wants allow"}, false, ""},
		{"a plane line where no plane decides", judged(landlock, allowed, col(Allow, "fs.write[./a/]"),
			line(Allow, "fs.write[./a/]", "mechanism", "plane", "decision_plane", "lsm")), want{RunnerLedger: "no plane deciding"}, false, ""},
		{"another plane's line", judged(lsm, allowed, col(Allow, "fs.write[./a/]"),
			line(Allow, "fs.write[./a/]", "mechanism", "plane", "decision_plane", "fmod_ret")), want{RunnerLedger: "under plane mode lsm"}, false, ""},
		// A handwritten cell: the kernel held to its Want, the column's verdict to the kernel's, the line to its Want.
		{"handwritten, all agree", handwritten(wantAllow, allowed, col(Allow, "fs.watch[./out/]"), okLine), nil, false, ""},
		{"handwritten, the kernel refuses", handwritten(wantAllow, eacces, col(Allow, "fs.write[./out/]"), line(Refused, "fs.write[./out/]")),
			want{RunnerKernel: "the kernel refused (errno 13), the cell wants allow", RunnerParity: "column says allow",
				RunnerLedger: "the cell wants allow"}, false, ""},
		// A finding's kernel answer is the finding, and its line holds what the kernel answered (ADR 0016), any rule.
		{"handwritten, a finding's refusal", finding(handwritten(wantAllow, eacces, col(Allow, "fs.write[./out/]"), line(Refused, "unmatched"))),
			nil, false, ""},
		{"handwritten, a finding's allow", finding(handwritten(Want{Verdict: Refused, Rule: "fs.deny_read[./s/]"}, allowed, nil, line(Allow, "unmatched"))),
			nil, false, ""},
		{"handwritten, a finding's line says the cell's verdict", finding(handwritten(Want{Verdict: Refused, Rule: "fs.deny_read[./s/]"}, allowed, nil,
			line(Refused, "fs.deny_read[./s/]"))), want{RunnerLedger: "the cell wants allow"}, false, ""},
		{"handwritten, the floor's answer", floor(handwritten(Want{Verdict: Refused}, eacces, col(Allow, "fs.write[./out/]"), line(Refused, "fs.write[./out/]"))),
			nil, false, ""},
		{"handwritten, the wanted errno", handwritten(Want{Verdict: Refused, Errno: 1}, eperm, nil, line(Refused, "")), nil, false, ""},
		{"handwritten, another errno", handwritten(Want{Verdict: Refused, Errno: 1}, eacces, nil, line(Refused, "")),
			want{RunnerKernel: "errno 13, the cell wants errno 1"}, false, ""},
		{"handwritten, neither success nor refusal", handwritten(wantAllow, enoent, nil, okLine),
			want{RunnerKernel: "neither a success nor a refusal"}, false, ""},
		{"handwritten, another rule", handwritten(wantAllow, allowed, nil, line(Allow, "fs.write[./w/]")),
			want{RunnerLedger: `the cell wants allow via "fs.write[./out/]"`}, false, ""},
		{"handwritten, rule unchecked", handwritten(Want{Verdict: Allow}, allowed, nil, line(Allow, "fs.write[./w/]")), nil, false, ""},
		{"handwritten, no line wanted", handwritten(Want{Verdict: Allow, NoLine: true}, allowed, nil), nil, false, ""},
		// A race cell is thousands of opens: its target's lines may be many, and none may be an allow. At tier landlock
		// they may be none: the supervisor's advisory lines name the link it resolved, not the target (ADR 0016 (2)).
		// Where the kernel's own recorder answers (the listener, the plane), a refusal has at least one refused line.
		// The argv race's lines are the supervisor's own exec refusals on every axis, tier landlock's included.
		{"race, no line", race(eacces), nil, false, ""},
		{"argv race, no line", argvRace(eacces), want{RunnerLedger: "no refused line names the race's target"}, false, ""},
		{"argv race, the supervisor's refusal", argvRace(eacces, line(Refused, "exec.deny[git push]")), nil, false, ""},
		{"argv race, an allow of the denied word", argvRace(eacces, line(Refused, "exec.deny[git push]"), line(Allow, "exec.allow[git]")),
			want{RunnerLedger: "an allow line names the race's target"}, false, ""},
		{"race, no line on the listener", raceOn(listener, eacces), want{RunnerLedger: "no refused line names the race's target"}, false, ""},
		{"race, no line on the plane", raceOn(lsm, eacces), want{RunnerLedger: "no refused line names the race's target"}, false, ""},
		{"race, the listener's refusals", raceOn(listener, eacces, line(Refused, "fs.deny_read[./s/]")), nil, false, ""},
		{"race, an allow of the target on the plane", raceOn(fmodRet, eacces, line(Refused, "fs.deny_read[./s/]"), line(Allow, "fs.write[./w/]")),
			want{RunnerLedger: "an allow line names the race's target"}, false, ""},
		{"race, many refusals", race(eacces, line(Refused, "fs.deny_read[./s/]"), line(Refused, "fs.deny_read[./s/]")), nil, false, ""},
		{"race, an allow of the target", race(eacces, line(Refused, "fs.deny_read[./s/]"), line(Allow, "fs.write[./w/]")),
			want{RunnerLedger: "an allow line names the race's target"}, false, ""},
		{"race, the kernel let a byte through", race(allowed), want{RunnerKernel: "the kernel allow"}, false, ""},
	}
	for _, tc := range cases {
		j := judgeAnswers(tc.ev)
		if !slices.Equal(slices.Sorted(maps.Keys(j.Failures)), slices.Sorted(maps.Keys(tc.failures))) {
			t.Errorf("%s: failures %q, want runners %v", tc.name, j.Failures, slices.Sorted(maps.Keys(tc.failures)))
		}
		for runner, sub := range tc.failures {
			if !strings.Contains(j.Failures[runner], sub) {
				t.Errorf("%s: %s failure %q, want one containing %q", tc.name, runner, j.Failures[runner], sub)
			}
		}
		if j.RuleCompared != tc.compared || j.Naming != tc.naming {
			t.Errorf("%s: compared %v, naming %q, want %v, %q", tc.name, j.RuleCompared, j.Naming, tc.compared, tc.naming)
		}
	}
}
