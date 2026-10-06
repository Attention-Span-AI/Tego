// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"time"
)

// The kernel runner's per-axis report (ADR 0017): what one axis' runs found, kept apart from the test that prints
// it, so that the judge's classes are data. Baselinable disagreements are failures, keyed for the ratchet; fail-opens
// (an invariant or an effect the kernel let through), effect failures (a success the tree does not show) and
// problems (a capability that disagrees with the oracle, a finding that is fixed) fail the test and are never
// baselined; findings are logged. A report line per cell goes to $TEGO_CONFORMANCE_REPORT when it is set, and each
// axis' runs and wall time are held to the budget.

// ReportEnv names a file the kernel runner appends one JSON line per cell and axis to (ReportRow). "-" prints each
// row to the test's standard output instead, after ReportRowPrefix: a KVM guest's console is the only way out of it
// (test/vm/root-suites.sh passes the variable through).
const ReportEnv = "TEGO_CONFORMANCE_REPORT"

// ReportRowPrefix starts each row's line under TEGO_CONFORMANCE_REPORT=-, so a reader of the console finds them.
const ReportRowPrefix = "CONFORMANCE-ROW "

// BudgetEnv set to "strict" fails an axis over its budget; otherwise a miss is printed, TARGET-MISS, and the test
// goes on. Nothing in CI sets it yet: a guest run sets it by hand (root-suites.sh passes it through), and the
// conformance guest job and vm-matrix will set it (ADR 0017: tier 1 under 10 s, at most 600 runs and under 3
// minutes per row and mode).
const BudgetEnv = "TEGO_CONFORMANCE_BUDGET"

// The budget per axis.
const (
	BudgetRuns         = 600
	BudgetWall         = 180 * time.Second
	BudgetLandlockWall = 10 * time.Second
)

// ReportRow is one cell on one axis, as a JSON line: the machine (the matrix row, the kernel's major.minor, the
// Landlock ABI, the architecture and the boot, lsm-bpf or default-lsm), the axis, the cell, and what each check saw.
type ReportRow struct {
	Row           string `json:"row"`
	Kernel        string `json:"kernel"`
	ABI           int    `json:"abi"`
	Arch          string `json:"arch"`
	Boot          string `json:"boot"`
	Axis          string `json:"axis"`
	Cell          string `json:"cell"`
	KernelVerdict string `json:"kernel_verdict"`
	Errno         int    `json:"errno"`
	Ledger        string `json:"ledger"`
	// Compile is compile --test's answer for the axis' column where the runner asks it (tier bpflsm, runner parity).
	Compile string `json:"compile"`
	// Effect is the effect judge's class, with its detail where it found something.
	Effect string `json:"effect"`
	// Naming is the known naming class (naming.go) of a generated cell whose ledger rule differs from compile's.
	Naming NamingClass `json:"naming,omitempty"`
}

// NewReportRow fills a row's machine fields.
func NewReportRow(m Machine, axis Tier, cell string) ReportRow {
	boot := "default-lsm"
	if m.BPFLSM {
		boot = "lsm-bpf"
	}
	return ReportRow{Row: m.Row, Kernel: fmt.Sprintf("%d.%d", m.Kernel[0], m.Kernel[1]), ABI: m.ABI, Arch: m.Arch, Boot: boot,
		Axis: string(axis), Cell: cell}
}

// AxisReport is what an axis' runs, or one fixture's, found.
type AxisReport struct {
	Label Tier
	// Failures are the baselinable disagreements, keyed as Ratchet reads them; Ran the (runner, label) pairs that
	// ran, keyed "runner|label".
	Failures map[string]string
	Ran      map[string]bool
	// FailOpens, Effects and Problems fail the test and are never baselined; Findings are logged.
	FailOpens, Effects, Problems, Findings []string
	// Namings counts the generated cells whose ledger rule differs from compile's in a known class (naming.go).
	Namings map[NamingClass]int
	// RulesCompared counts the generated cells whose ledger rule was held to compile's: an axis that ran a generated
	// fixture with a column and compared none skipped the check (TestConformanceKernel fails it).
	RulesCompared int
	Runs          int
	Wall          time.Duration
	Rows          []ReportRow
}

// JudgeFailOpens holds one action's outcome on the axis label, whose invariants are tier inv's, to the invariants
// (from the contract alone; a fail-open is never baselined) and to the effect judge (a refusal that left its effect is
// a fail-open on every axis, the listener's included: effects.go). It runs for every action the axis ran, whether or
// not the cell asks anything of the axis (Cell.Unasked). finding says the cell's Finding is at inv: a violation there
// is a finding, and none is a problem (the finding is fixed).
func (r *AxisReport) JudgeFailOpens(fx *Fixture, c *Cell, label, inv Tier, o Outcome, eff Effect) (finding bool) {
	id := fx.ID(c)
	finding = c.Finding != "" && c.FindingAt == inv
	if v := Invariant(fx.Model, c, inv, o); v != "" {
		if finding {
			r.Findings = append(r.Findings, fmt.Sprintf("%s at %s: %s (%s)", id, label, v, c.Finding))
		} else {
			r.FailOpens = append(r.FailOpens, fmt.Sprintf("%s at %s: %s (kernel errno %d)", id, label, v, o.Errno))
		}
	} else if finding {
		r.Problems = append(r.Problems, fmt.Sprintf("%s at %s no longer breaks an invariant: the finding is fixed, remove the cell's Finding", id, label))
	}
	switch eff.Class {
	case EffectFailOpen:
		r.FailOpens = append(r.FailOpens, fmt.Sprintf("%s at %s: effect: %s", id, label, eff.Detail))
	case EffectMissing:
		r.Effects = append(r.Effects, fmt.Sprintf("%s at %s: %s", id, label, eff.Detail))
	case EffectNone, EffectHeld: // nothing to report
	}
	return finding
}

// NewAxisReport is an empty report for the axis label.
func NewAxisReport(label Tier) *AxisReport {
	return &AxisReport{Label: label, Failures: map[string]string{}, Ran: map[string]bool{}, Namings: map[NamingClass]int{}}
}

// Merge adds a fixture's report to the axis'. Wall is the axis' own, measured around its runs, and is not summed.
func (r *AxisReport) Merge(f *AxisReport) {
	maps.Copy(r.Failures, f.Failures)
	maps.Copy(r.Ran, f.Ran)
	r.FailOpens = append(r.FailOpens, f.FailOpens...)
	r.Effects = append(r.Effects, f.Effects...)
	r.Problems = append(r.Problems, f.Problems...)
	r.Findings = append(r.Findings, f.Findings...)
	for k, n := range f.Namings {
		r.Namings[k] += n
	}
	r.RulesCompared += f.RulesCompared
	r.Runs += f.Runs
	r.Rows = append(r.Rows, f.Rows...)
}

// UncomparedGenerated names the first fixture that ran on the axis (its report is not nil) with compile --test's
// column (hasColumn) when the axis held no ledger rule to a column, and is "" otherwise. names and reports are the
// axis' fixtures in order. A fixture that -run or -skip filtered out has no report and does not count: a run
// narrowed to handwritten fixtures compares no rule and passes.
func (r *AxisReport) UncomparedGenerated(names []string, reports []*AxisReport, hasColumn func(string) bool) string {
	if r.RulesCompared != 0 {
		return ""
	}
	for i, name := range names {
		if reports[i] != nil && hasColumn(name) {
			return name
		}
	}
	return ""
}

// Judgements counts what the report holds against its cells: failures, fail-opens, effects, problems and findings.
// A cell that changed it drew a judgement (the kernel runner logs such a generated cell's line).
func (r *AxisReport) Judgements() int {
	return len(r.Failures) + len(r.FailOpens) + len(r.Effects) + len(r.Problems) + len(r.Findings)
}

// BudgetMisses names each budget the axis missed, each line starting TARGET-MISS with its number: more than
// BudgetRuns runs, more than BudgetWall, and for tier landlock more than BudgetLandlockWall.
func (r *AxisReport) BudgetMisses() []string {
	var out []string
	if r.Runs > BudgetRuns {
		out = append(out, fmt.Sprintf("TARGET-MISS AXIS %s runs=%d, budget %d runs per axis (ADR 0017)", r.Label, r.Runs, BudgetRuns))
	}
	limit := BudgetWall
	if r.Label == TierLandlock {
		limit = BudgetLandlockWall
	}
	if r.Wall > limit {
		out = append(out, fmt.Sprintf("TARGET-MISS AXIS %s wall=%.1fs, budget %.0fs (ADR 0017)", r.Label, r.Wall.Seconds(), limit.Seconds()))
	}
	return out
}

// Line is the axis' summary line, ending with the count of generated cells whose ledger rule was held to compile's
// and the count of each known naming class among them, in class order.
func (r *AxisReport) Line() string {
	var namings []string
	for _, k := range slices.Sorted(maps.Keys(r.Namings)) {
		namings = append(namings, fmt.Sprintf("%s:%d", k, r.Namings[k]))
	}
	return fmt.Sprintf("AXIS %s runs=%d wall=%.1fs fail-opens=%d effects=%d problems=%d findings=%d disagreements=%d rules-compared=%d namings=%s",
		r.Label, r.Runs, r.Wall.Seconds(), len(r.FailOpens), len(r.Effects), len(r.Problems), len(r.Findings), len(r.Failures),
		r.RulesCompared, strings.Join(namings, ","))
}

// WriteRows writes the report's rows as JSON lines, each after prefix.
func (r *AxisReport) WriteRows(w io.Writer, prefix string) error {
	for _, row := range r.Rows {
		b, err := json.Marshal(row)
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(w, "%s%s\n", prefix, b); err != nil {
			return err
		}
	}
	return nil
}
