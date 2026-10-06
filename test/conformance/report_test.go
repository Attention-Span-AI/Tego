// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestAxisBudget: ADR 0017's budget per axis, at most 600 runs and 180 s, and 10 s for tier landlock; each miss is a
// TARGET-MISS line with its number, and an axis on budget has none.
func TestAxisBudget(t *testing.T) {
	cases := []struct {
		label Tier
		runs  int
		wall  time.Duration
		want  []string
	}{
		{TierLandlock, 7, 700 * time.Millisecond, nil},
		{TierLandlock, 7, 10*time.Second + time.Millisecond, []string{"TARGET-MISS AXIS landlock wall=10.0s, budget 10s"}},
		{"cgroup@lsm", 7, 179 * time.Second, nil},
		{"cgroup@lsm", 601, 181 * time.Second, []string{"TARGET-MISS AXIS cgroup@lsm runs=601, budget 600", "TARGET-MISS AXIS cgroup@lsm wall=181.0s, budget 180s"}},
		{TierBPFLSM, 600, 180 * time.Second, nil},
	}
	for _, tc := range cases {
		r := NewAxisReport(tc.label)
		r.Runs, r.Wall = tc.runs, tc.wall
		got := r.BudgetMisses()
		if len(got) != len(tc.want) {
			t.Errorf("%s runs=%d wall=%v: %q, want %q", tc.label, tc.runs, tc.wall, got, tc.want)
			continue
		}
		for i := range got {
			if !strings.HasPrefix(got[i], tc.want[i]) {
				t.Errorf("%s: %q, want it to start %q", tc.label, got[i], tc.want[i])
			}
		}
	}
}

// TestUncomparedGenerated: the axis fails the rule check only for a generated fixture that ran and compared no rule;
// a fixture the -run or -skip filter left out (no report) does not count.
func TestUncomparedGenerated(t *testing.T) {
	names := []string{"denywrite", "grid-none.none.none"}
	hasColumn := func(name string) bool { return name == "grid-none.none.none" }
	ran := NewAxisReport(TierLandlock)
	for _, tc := range []struct {
		why      string
		reports  []*AxisReport
		compared int
		want     string
	}{
		{"narrowed to the handwritten fixture: the generated one never ran", []*AxisReport{ran, nil}, 0, ""},
		{"no fixture ran", []*AxisReport{nil, nil}, 0, ""},
		{"the generated fixture ran and compared no rule", []*AxisReport{nil, ran}, 0, "grid-none.none.none"},
		{"both ran and none compared", []*AxisReport{ran, ran}, 0, "grid-none.none.none"},
		{"the generated fixture ran and compared rules", []*AxisReport{ran, ran}, 3, ""},
	} {
		axis := NewAxisReport(TierLandlock)
		axis.RulesCompared = tc.compared
		if got := axis.UncomparedGenerated(names, tc.reports, hasColumn); got != tc.want {
			t.Errorf("%s: UncomparedGenerated = %q, want %q", tc.why, got, tc.want)
		}
	}
}

// TestAxisReportMergeAndRows: an axis' report sums its fixtures' runs and keeps every finding, and its rows are
// JSON lines carrying the machine.
func TestAxisReportMergeAndRows(t *testing.T) {
	m := Machine{Kernel: [2]int{6, 17}, ABI: 7, Arch: "amd64", BPFLSM: true, Row: "ubuntu-25.10"}
	axis := NewAxisReport("cgroup@lsm")
	for _, cell := range []string{"fs/a", "fs/b"} {
		f := NewAxisReport("cgroup@lsm")
		f.Runs = 1
		f.Failures[FailureKey(RunnerLedger, cell, "cgroup@lsm")] = "x"
		f.Ran[RunnerLedger+"|cgroup@lsm"] = true
		f.FailOpens = append(f.FailOpens, cell)
		f.Rows = append(f.Rows, NewReportRow(m, "cgroup@lsm", cell))
		f.Namings[NamingRefusalNamesWatch] = 2
		f.Namings[NamingPlaneRename] = 1
		f.RulesCompared = 5
		axis.Merge(f)
	}
	if axis.Runs != 2 || len(axis.Failures) != 2 || len(axis.FailOpens) != 2 || len(axis.Rows) != 2 || !axis.Ran[RunnerLedger+"|cgroup@lsm"] {
		t.Errorf("merged report: %+v", axis)
	}
	// The rules compared and the known naming classes among them are summed and close the summary line, in class order.
	if want := "rules-compared=10 namings=plane-rename:2,refusal-names-watch:4"; !strings.HasSuffix(axis.Line(), want) {
		t.Errorf("summary line %q, want it to end %q", axis.Line(), want)
	}
	// The console form a guest reports with (TEGO_CONFORMANCE_REPORT=-): each row on its own line after the prefix.
	var console bytes.Buffer
	if err := axis.WriteRows(&console, ReportRowPrefix); err != nil {
		t.Fatal(err)
	}
	for _, l := range strings.Split(strings.TrimSpace(console.String()), "\n") {
		rest, ok := strings.CutPrefix(l, ReportRowPrefix)
		if !ok || !json.Valid([]byte(rest)) {
			t.Errorf("console row %q: want %q and a JSON object", l, ReportRowPrefix)
		}
	}
	var buf bytes.Buffer
	if err := axis.WriteRows(&buf, ""); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("%d lines, want 2: %s", len(lines), buf.String())
	}
	var row map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &row); err != nil {
		t.Fatal(err)
	}
	for k, want := range map[string]any{"row": "ubuntu-25.10", "kernel": "6.17", "abi": float64(7), "arch": "amd64", "boot": "lsm-bpf",
		"axis": "cgroup@lsm", "cell": "fs/a"} {
		if row[k] != want {
			t.Errorf("row[%s] = %v, want %v", k, row[k], want)
		}
	}
	for _, k := range []string{"kernel_verdict", "errno", "ledger", "compile", "effect"} {
		if _, ok := row[k]; !ok {
			t.Errorf("the row has no %s: %s", k, lines[0])
		}
	}
	if b := NewReportRow(Machine{}, TierLandlock, "x").Boot; b != "default-lsm" {
		t.Errorf("boot without bpf: %q", b)
	}
}

// TestAxisReportJudgements counts every judgement a cell can draw, so the kernel runner logs a generated cell's line
// exactly when the cell added one: a failure, fail-open, effect, problem or finding; rows and runs are none.
func TestAxisReportJudgements(t *testing.T) {
	r := NewAxisReport(TierLandlock)
	if n := r.Judgements(); n != 0 {
		t.Fatalf("an empty report has %d judgements", n)
	}
	r.Runs++
	r.Rows = append(r.Rows, ReportRow{})
	r.Ran[RunnerKernel+"|landlock"] = true
	if n := r.Judgements(); n != 0 {
		t.Fatalf("runs, rows and ran are no judgements: %d", n)
	}
	r.Failures[FailureKey(RunnerKernel, "fsgrid/x", TierLandlock)] = "x"
	r.FailOpens = append(r.FailOpens, "x")
	r.Effects = append(r.Effects, "x")
	r.Problems = append(r.Problems, "x")
	r.Findings = append(r.Findings, "x")
	if n := r.Judgements(); n != 5 {
		t.Fatalf("one of each kind: %d judgements, want 5", n)
	}
}
