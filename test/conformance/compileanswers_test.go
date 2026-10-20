// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"encoding/json"
	"strings"
	"testing"
)

// gridRows is every compile --test row of fx's table, in table order, with fx's cell and tier.
func gridRows(fx *Fixture) (names []string, cells []*Cell, tiers []Tier) {
	for i := range fx.Cells {
		c := &fx.Cells[i]
		if _, ok := compileAction(c); !ok || c.NoCompile != "" {
			continue
		}
		for _, tier := range c.Tiers() {
			names, cells, tiers = append(names, rowName(fx.ID(c), tier)), append(cells, c), append(tiers, tier)
		}
	}
	return names, cells, tiers
}

// reportOf renders a compile --test --json report answering each named row with its verdict.
func reportOf(t *testing.T, names []string, verdict func(i int) string) []byte {
	t.Helper()
	rows := make([]compileRow, 0, len(names))
	for i, n := range names {
		rows = append(rows, compileRow{Name: n, Columns: []compileCell{{Tier: "landlock", Verdict: verdict(i)}}})
	}
	b, err := json.Marshal(map[string]any{"v": 1, "rows": rows})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// TestAnswersOfRefusesAnIncompleteReport: every reader of compile --test (the compile runner, the over-grant feed of
// generated cells, the kernel runner's column) reads it through answersOf, so a report that drops a row, answers
// one with something other than allow or refused, or answers a row the table never asked, fails the test there
// instead of leaving that cell's compile checks unasked (a generated cell's missing row used to
// skip its over-grant and its kernel-vs-column checks in silence).
func TestAnswersOfRefusesAnIncompleteReport(t *testing.T) {
	fx := GenFSGrid()[0]
	table := compileTable(&env{project: "/p"}, &fx)
	names, _, _ := gridRows(&fx)
	if len(names) == 0 {
		t.Fatal("the grid fixture has no compile rows")
	}
	allow := func(int) string { return Allow }
	got, err := answersOf(table, reportOf(t, names, allow))
	if err != nil || len(got) != len(names) {
		t.Fatalf("a complete report: %d answers, %v; want %d answers", len(got), err, len(names))
	}
	for name, report := range map[string][]byte{
		"no rows":         reportOf(t, nil, allow),
		"a row dropped":   reportOf(t, names[1:], allow),
		"an error answer": reportOf(t, names, func(i int) string { return map[bool]string{true: "error", false: Refused}[i == 3] }),
		"an empty answer": reportOf(t, names, func(int) string { return "" }),
		"an extra row":    reportOf(t, append(append([]string{}, names...), "nowhere@landlock"), allow),
		"a row twice":     reportOf(t, append(append([]string{}, names...), names[0]), allow),
	} {
		if got, err := answersOf(table, report); err == nil {
			t.Errorf("%s: %d answers and no error, want the report refused", name, len(got))
		}
	}
}

// TestCompileOverGrantsFiresAndFilters: the unprivileged over-grant catcher of generated cells (plan C5) reports an
// allow answer exactly where the cell's invariants refuse the action, and never a refused answer.
func TestCompileOverGrantsFiresAndFilters(t *testing.T) {
	fx := GenFSGrid()[0]
	names, cells, tiers := gridRows(&fx)
	refuses := map[string]bool{}
	for i, n := range names {
		refuses[n] = Invariant(fx.Model, cells[i], tiers[i], Outcome{OK: true}) != ""
	}
	nRefuse := 0
	for _, r := range refuses {
		if r {
			nRefuse++
		}
	}
	if nRefuse == 0 || nRefuse == len(names) {
		t.Fatalf("%d of %d rows' invariants refuse an allow: the fixture cannot show both firing and filtering", nRefuse, len(names))
	}
	answer := func(verdict func(n string) string) map[string]compileCell {
		m := map[string]compileCell{}
		for _, n := range names {
			m[n] = compileCell{Verdict: verdict(n)}
		}
		return m
	}
	over := compileOverGrants(&fx, answer(func(string) string { return Allow }))
	if len(over) != nRefuse {
		t.Errorf("every row allowed: %d over-grants, want %d", len(over), nRefuse)
	}
	for _, o := range over {
		n := strings.Replace(strings.SplitN(o, ":", 2)[0], " at ", "@", 1)
		if !refuses[n] {
			t.Errorf("over-grant %q names a row whose invariants allow the action", o)
		}
	}
	if over := compileOverGrants(&fx, answer(func(string) string { return Refused })); len(over) != 0 {
		t.Errorf("every row refused: %d over-grants, want none: %q", len(over), over[0])
	}
	// An allow only where the invariants allow it is the healthy tree: nothing to report.
	if over := compileOverGrants(&fx, answer(func(n string) string {
		if refuses[n] {
			return Refused
		}
		return Allow
	})); len(over) != 0 {
		t.Errorf("allowed only where the invariants allow: %d over-grants, want none: %q", len(over), over[0])
	}
}
