// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Report never reorders and always has 28 lines (R23; ADR 0048 appended the 21st, ADR 0041 D7 the
// 22nd to 26th, ADR 0018 PR 2 the 27th, ADR 0070 the 28th).
// identity-config.md R23 (never reorders, index-comparable) and R26 (the ask row is reported like any other).
func TestSetReport(t *testing.T) {
	var nilSet Set
	lines := nilSet.Report()
	if len(lines) != 31 || len(allCapabilities) != 31 {
		t.Fatalf("len = %d", len(lines))
	}
	for i, l := range lines {
		if l.Capability != allCapabilities[i] || l.Present || l.Detail != "" {
			t.Errorf("line %d = %+v", i, l)
		}
	}
	s := Set{CapAsk: true, CapFileWriteDeny: true}
	got := s.Report()
	for i := range got {
		if got[i].Capability != lines[i].Capability {
			t.Fatal("order differs between sets")
		}
		if got[i].Present != s.Has(got[i].Capability) {
			t.Errorf("%s present=%v", got[i].Capability, got[i].Present)
		}
	}
	detailed := Matrix(TierLandlock).ReportFor(TierLandlock)
	for _, l := range detailed {
		if l.Detail == "" {
			t.Errorf("%s: empty detail", l.Capability)
		}
	}
}

func TestSetHelpers(t *testing.T) {
	m := Matrix(TierLandlock)
	m[CapAsk] = false // a fresh copy: the table must be unaffected
	if !Matrix(TierLandlock).Has(CapAsk) {
		t.Error("Matrix returned shared state")
	}
	if got := Matrix(TierObserve); len(got) != 0 || got == nil {
		t.Errorf("observe matrix = %v", got)
	}
	if Matrix(Tier("quantum")).Has(CapAsk) {
		t.Error("unknown tier provides a capability")
	}
	c := m.Clone()
	c[CapAsk] = true
	if m.Has(CapAsk) {
		t.Error("Clone shares storage")
	}
	if Set(nil).Clone() != nil {
		t.Error("Clone(nil) != nil")
	}
	for _, c := range AllCapabilities() {
		if !c.Valid() || c.Title() == string(c) {
			t.Errorf("%s: valid=%v title=%q", c, c.Valid(), c.Title())
		}
	}
	if Capability("nope").Valid() || Capability("nope").Title() != "nope" {
		t.Error("unknown capability")
	}
}

func TestFormatReport(t *testing.T) {
	out := FormatReport(Matrix(TierLandlock).ReportFor(TierLandlock))
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(lines) != 31 {
		t.Fatalf("%d lines:\n%s", len(lines), out)
	}
	if !strings.HasPrefix(lines[0], "deny file write outside contract") || !strings.Contains(lines[0], "  yes  yes (EACCES)") {
		t.Errorf("first line %q", lines[0])
	}
	if !strings.Contains(lines[5], "  no   best-effort") {
		t.Errorf("udp line %q", lines[5])
	}
	var b strings.Builder
	if err := WriteMatrix(&b); err != nil {
		t.Fatal(err)
	}
	table := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	if len(table) != 32 || !strings.HasPrefix(table[0], "capability") || !strings.Contains(table[0], "landlock  cgroup    bpflsm") {
		t.Errorf("matrix table:\n%s", b.String())
	}
	if !strings.HasSuffix(table[16], "no        yes       yes") {
		t.Errorf("namespace sandbox row %q", table[16])
	}
	// The abstract-scope row is ABI-gated in every column, so the static matrix claims it nowhere; a run
	// records it from the Landlock ABI it had (agent-contract R19, enforce-landlock R19).
	if !strings.HasPrefix(table[17], "abstract unix names bound outside the run refused") ||
		!strings.HasSuffix(table[17], "no        no        no") {
		t.Errorf("abstract-scope row %q", table[17])
	}
	if !strings.HasPrefix(table[18], "deny chmod") || !strings.HasSuffix(table[18], "no        no        no") {
		t.Errorf("last row %q", table[18])
	}
	if !strings.HasPrefix(table[19], "TCP destination admission in-kernel") || !strings.HasSuffix(table[19], "no        yes       yes") {
		t.Errorf("TCP admission row %q", table[19])
	}
	if !strings.HasPrefix(table[20], "Unix destination admission in-kernel") || !strings.HasSuffix(table[20], "no        no        no") {
		t.Errorf("conditional Unix row %q", table[20])
	}
}

// TestCompletionRowsOfADR0041 pins ADR 0041 D7's five rows: appended after every earlier row (R23), in D7's order,
// each a statement about whether a tier completes a supervisor decision race-free (outcome A) or decides it on
// copied facts and continues it (outcome D). The gate's fs mutation cell is best effort at every tier (no kernel layer
// evaluates a gate predicate); its exec cell is best effort at tier 1 and, as ADR 0048 (6) amends D1, conditional at
// tiers 2 and 3 on the plane's exec pins, which hold an allowed exec to the image and argv scored; its fs open cell is conditional on the contract's gate.completion:
// held (ADR 0041 Stage B's open deputy), best effort otherwise; its net cell is completed at every
// tier on IP-domain sockets (D6). Protected write targets are race-free only where a decision plane decides them:
// never at tier 1, conditional at tier 2 (a plane mode, not the fanotify listener), always at tier 3. The declared
// write-denial row is not moved by any of it.
func TestCompletionRowsOfADR0041(t *testing.T) {
	want := []Capability{CapGateFSOpenCompletion, CapGateFSMutationCompletion, CapGateExecCompletion,
		CapGateNetCompletion, CapProtectedWriteTargets}
	all := AllCapabilities()
	// D7's rows were appended right after exec.command_argv (row 20); ADR 0018 PR 2's net.socket_families came after.
	tail := all[21 : 21+len(want)]
	for i, c := range want {
		if tail[i] != c {
			t.Fatalf("row %d is %s, want %s (appended after row 20, in D7's order)", 21+i, tail[i], c)
		}
	}
	if all[20] != CapExecCommandArgv {
		t.Errorf("row 20 is %s: an earlier row moved", all[20])
	}
	tiers := []Tier{TierLandlock, TierCgroup, TierBPFLSM}
	for _, tier := range tiers {
		for _, c := range []Capability{CapGateFSMutationCompletion, CapGateExecCompletion} {
			if c == CapGateExecCompletion && tier != TierLandlock {
				if d := MatrixDetail(tier, c); Matrix(tier).Has(c) || !strings.HasPrefix(d, "conditional") ||
					!strings.Contains(d, "exec pins") || !strings.Contains(d, "best-effort") {
					t.Errorf("%s/%s: present %v, cell %q; want conditional on exec pins, else best effort", tier, c,
						Matrix(tier).Has(c), d)
				}
				continue
			}
			if Matrix(tier).Has(c) || !strings.HasPrefix(MatrixDetail(tier, c), "best-effort") {
				t.Errorf("%s/%s: present %v, cell %q; want best effort", tier, c, Matrix(tier).Has(c), MatrixDetail(tier, c))
			}
		}
		if d := MatrixDetail(tier, CapGateFSOpenCompletion); Matrix(tier).Has(CapGateFSOpenCompletion) ||
			!strings.HasPrefix(d, "conditional") || !strings.Contains(d, "gate.completion: held") || !strings.Contains(d, "best-effort") {
			t.Errorf("%s: gate fs open completion %v, cell %q; want conditional on held completion, best effort otherwise",
				tier, Matrix(tier).Has(CapGateFSOpenCompletion), d)
		}
		if !Matrix(tier).Has(CapGateNetCompletion) || !strings.Contains(MatrixDetail(tier, CapGateNetCompletion), "unix") {
			t.Errorf("%s: gate net completion %v, cell %q; want present, naming the unix residuals", tier,
				Matrix(tier).Has(CapGateNetCompletion), MatrixDetail(tier, CapGateNetCompletion))
		}
		if !Matrix(tier).Has(CapFileWriteDeny) {
			t.Errorf("%s: the declared write-denial row is gone", tier)
		}
	}
	for tier, present := range map[Tier]bool{TierLandlock: false, TierCgroup: false, TierBPFLSM: true} {
		if Matrix(tier).Has(CapProtectedWriteTargets) != present {
			t.Errorf("%s: protected write targets present %v, want %v (cell %q)", tier, !present, present,
				MatrixDetail(tier, CapProtectedWriteTargets))
		}
	}
	if !strings.HasPrefix(MatrixDetail(TierCgroup, CapProtectedWriteTargets), "conditional") {
		t.Errorf("cgroup protected write targets %q: want conditional on the plane", MatrixDetail(TierCgroup, CapProtectedWriteTargets))
	}
	if Matrix(TierObserve).Has(CapGateNetCompletion) {
		t.Error("observe completes a gate decision")
	}
}

// TestNameEntryRowOfADR0043 pins ADR 0043 C9's cells of fs.deny_read.created_later, the row ADR 0069 appended
// between fs.deny_read.nested and fs.deny_read.moved (R23: no earlier row moves). A file created after compile at a
// name a deny_read name entry covers is refused at tier 1 by held reads only (ADR 0069), conditionally at tier 2 (a
// plane mode's name check; the fanotify fallback refuses opens and, best effort, mutations) and always at tier 3,
// whose cell names what the check does not reach.
func TestNameEntryRowOfADR0043(t *testing.T) {
	all := AllCapabilities()
	if n := len(all); all[n-3] != CapReadDenyNested || all[n-2] != CapReadDenyCreatedLater || all[n-1] != CapReadDenyMoved {
		t.Fatalf("last rows %v: want fs.deny_read.nested, fs.deny_read.created_later, fs.deny_read.moved", all[n-3:])
	}
	if string(CapReadDenyCreatedLater) != "fs.deny_read.created_later" {
		t.Errorf("row name %q", CapReadDenyCreatedLater)
	}
	for tier, present := range map[Tier]bool{TierLandlock: true, TierCgroup: false, TierBPFLSM: true} {
		if Matrix(tier).Has(CapReadDenyCreatedLater) != present {
			t.Errorf("%s: present %v, want %v (cell %q)", tier, !present, present, MatrixDetail(tier, CapReadDenyCreatedLater))
		}
	}
	if d := MatrixDetail(TierLandlock, CapReadDenyCreatedLater); !strings.Contains(d, "held") {
		t.Errorf("landlock cell %q: want held reads", d)
	}
	if d := MatrixDetail(TierCgroup, CapReadDenyCreatedLater); !strings.HasPrefix(d, "conditional") || !strings.Contains(d, "fanotify fallback") {
		t.Errorf("cgroup cell %q: want conditional on a plane mode, naming the fallback", d)
	}
	d := MatrixDetail(TierBPFLSM, CapReadDenyCreatedLater)
	for _, residual := range []string{"name check", "temporary name", "held descriptor", "symlink", "fs.reads: held"} {
		if !strings.Contains(d, residual) {
			t.Errorf("bpflsm cell %q does not name %q", d, residual)
		}
	}
}

// agent-contract.md E35: no Landlock ABI has a chmod right, tier 1's filter does not notify chmod and tier 2
// has no permission event for it, so no row tiers 1 and 2 provide may claim to deny chmod. Tier 3's path_chmod
// hook refuses a mode change beneath a deny_write target only (enforce-plane R12, TIER3-PLAN T13), not under the
// contract's write rules, so it claims no chmod deny either, and its cell says what it does.
func TestChmodDeniedOnlyAtTier3(t *testing.T) {
	deniesChmod := func(tier Tier) bool {
		for c, ok := range Matrix(tier) {
			if ok && strings.HasPrefix(c.Title(), "deny ") && strings.Contains(c.Title(), "chmod") {
				return true
			}
		}
		return false
	}
	for _, tier := range []Tier{TierLandlock, TierCgroup} {
		if deniesChmod(tier) {
			t.Errorf("%s: the matrix claims a chmod deny the tier cannot enforce", tier)
		}
	}
	if deniesChmod(TierBPFLSM) {
		t.Error("bpflsm: the matrix claims a chmod deny under the write rules, which path_chmod does not make")
	}
	if n := MatrixDetail(TierBPFLSM, CapChmodDeny); !strings.Contains(n, "deny_write") {
		t.Errorf("bpflsm's chmod cell %q does not say it protects deny_write targets", n)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestWriteErrors(t *testing.T) {
	if err := WriteReport(failWriter{}, Set(nil).Report()); err == nil {
		t.Error("WriteReport swallowed the error")
	}
	if err := WriteMatrix(failWriter{}); err == nil {
		t.Error("WriteMatrix swallowed the error")
	}
}

// The in-binary matrix equals a fresh parse of spec/backend/CAPABILITIES.md,
// cell for cell (R22, I9).
// identity-config.md R22 and I9 (the in-binary matrix equals a fresh parse of CAPABILITIES.md, cell for cell; the doc's tools/gen-capmatrix generator does not exist, so there is no generator-output leg).
func TestMatrixGolden(t *testing.T) {
	rows := readMatrixRows(t, filepath.Join("..", "..", "..", "spec", "backend", "CAPABILITIES.md"))
	if len(rows) != len(allCapabilities) {
		t.Fatalf("markdown has %d capability rows, matrix has %d", len(rows), len(allCapabilities))
	}
	columns := []Tier{TierLandlock, TierCgroup, TierBPFLSM}
	// The decision plane row follows "minimum kernel": prose per tier, not a capability.
	dp := readRowAfter(t, filepath.Join("..", "..", "..", "spec", "backend", "CAPABILITIES.md"), "decision plane")
	for j, tier := range columns {
		if got := DecisionPlane(tier); got == "" || got != dp[j] {
			t.Errorf("%s: decision plane %q, markdown %q", tier, got, dp[j])
		}
	}
	for i, row := range rows {
		c := allCapabilities[i]
		if row.title != c.Title() {
			t.Errorf("row %d: markdown title %q, Title() %q", i, row.title, c.Title())
		}
		for j, tier := range columns {
			detail := row.cells[j]
			if got := MatrixDetail(tier, c); got != detail {
				t.Errorf("%s/%s: detail %q, markdown %q", tier, c, got, detail)
			}
			if got, want := Matrix(tier).Has(c), cellPresent(detail); got != want {
				t.Errorf("%s/%s: present %v, markdown cell %q reads as %v", tier, c, got, detail, want)
			}
		}
	}
}

// readRowAfter returns the three tier cells of the table row titled title, which lies after the capability rows.
func readRowAfter(t *testing.T, path, title string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if !strings.HasPrefix(line, "| "+title+" |") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		if len(cells) != 4 {
			t.Fatalf("row %q has %d cells", line, len(cells))
		}
		return cells[1:]
	}
	t.Fatalf("%s has no %q row", path, title)
	return nil
}

type matrixRow struct {
	title string
	cells []string
}

// readMatrixRows parses the capability table: every row after the header until "minimum kernel".
func readMatrixRows(t *testing.T, path string) []matrixRow {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var rows []matrixRow
	inTable := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "| ") {
			continue
		}
		cells := strings.Split(strings.Trim(line, "|"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(cells[i])
		}
		switch {
		case cells[0] == "Capability":
			inTable = true
		case cells[0] == "minimum kernel":
			return rows
		case inTable && !strings.HasPrefix(cells[0], "---"):
			if len(cells) != 4 {
				t.Fatalf("row %q has %d cells", line, len(cells))
			}
			rows = append(rows, matrixRow{title: cells[0], cells: cells[1:]})
		}
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return rows
}

// cellPresent is the reading rule stated on the matrix variable: a cell is present unless it
// starts with "no", "refused", "best-effort", or is gated on an untested Landlock ABI.
func cellPresent(detail string) bool {
	for _, absent := range []string{"no", "refused", "best-effort", "conditional", "Landlock ABI"} {
		if strings.HasPrefix(detail, absent) {
			return false
		}
	}
	return true
}
