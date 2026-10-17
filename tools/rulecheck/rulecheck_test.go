// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const fixtureA = `# a
## 5. Business rules

**R1 — First.** Parts: (a) one, (b) two.

- **R2.** Second, with a run-in rule. **R2b**: the run-in half. **R3** is a reference, not a definition.

**R-cap** a named rule.

**Changes.**
- 2026-09-24, R1: **R9 — not a definition** here, it is history.

## 6. Edge cases

1. **E1** bold case.
2. A numbered case, which is E2.
E3 (new). An inline case.

## 8. Invariants

I1. Inline invariant. I2. Another in the same paragraph.

## 9. Conventions
**R40 — outside §5, not a rule**
`

// TestParseDocForms pins every definition form the P0 specs use.
func TestParseDocForms(t *testing.T) {
	d := ParseDoc("a.md", fixtureA)
	var ids []string
	for id := range d.Rules {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	want := "E1 E2 E3 I1 I2 R-cap R1 R2 R2b"
	if got := strings.Join(ids, " "); got != want {
		t.Fatalf("ids = %s, want %s", got, want)
	}
	if r := d.Rules["R1"]; !r.Parts["a"] || !r.Parts["b"] || r.Parts["c"] {
		t.Fatalf("R1 parts = %v, want a and b", r.Parts)
	}
	if len(d.Dups) != 0 {
		t.Fatalf("dups = %v", d.Dups)
	}
}

// TestCheckFindings pins the three failing checks: a duplicate, a part that does not exist (locally and across
// documents), and an ID a named document does not define; and that a good reference passes.
func TestCheckFindings(t *testing.T) {
	a := ParseDoc("a.md", fixtureA+"\n## 5. Business rules\n\n**R1 — again.**\n")
	b := ParseDoc("b.md", `# b
## 5. Business rules

**R1 —** cites a.md R1 (b), a.md R1 (z), a R2b, a.md §6 case 2, a.md §6 case 7, a.md I9, and R1 (q) is local.
`)
	docs := map[string]*Doc{"a.md": a, "b.md": b}
	var got []string
	for _, f := range Check(docs, map[string]string{"x.md": "see b.md R7"}) {
		got = append(got, f.String())
	}
	want := []string{
		"a.md is defined 2 times",
		`"a.md R1 (z)": a.md R1 has no part (z)`,
		`"a.md §6 case 7" names E7`,
		`"a.md I9" names I9`,
		"R1 (q): R1 has no part (q)",
		`"b.md R7" names R7`,
		"a.md:6: R3 names no rule this document defines",
		"a.md:24: R40 names no rule this document defines",
	}
	joined := strings.Join(got, "\n")
	for _, w := range want {
		if !strings.Contains(strings.ReplaceAll(joined, "R1 is defined", "a.md is defined"), w) {
			t.Errorf("missing finding %q in:\n%s", w, joined)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d findings, want %d:\n%s", len(got), len(want), joined)
	}
}

// TestUntested pins the report: a rule is tested when its body names an existing test function, or a test file
// names both its document and its ID.
func TestUntested(t *testing.T) {
	d := ParseDoc("a.md", fixtureA)
	tests := map[string]string{
		"x_test.go": "package x\n\nfunc TestNamed(t *testing.T) {}\n// a.md R2\n",
	}
	d.Rules["R1"].Body += " TestNamed"
	u := Untested(map[string]*Doc{"a.md": d}, tests)["a.md"]
	for _, id := range u {
		if id == "R1" || id == "R2" {
			t.Errorf("%s reported untested", id)
		}
	}
	if len(u) != len(d.Rules)-2 {
		t.Errorf("untested = %v", u)
	}
}

// TestRepositoryPasses runs the check over this repository's own specs, as precommit and CI do.
func TestRepositoryPasses(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "p0")); err != nil {
		t.Skip("no docs/p0 here")
	}
	docs, extra, _, _, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) < 9 {
		t.Fatalf("read %d specs, want the nine component specs", len(docs))
	}
	for _, f := range Check(docs, extra) {
		t.Error(f)
	}
}

// TestCheckUnnamedAndQuotedRefs: a bare ID in a document is that document's own rule, and a document named as a
// Markdown link or in backquotes still names the ID after it; each fails when the rule does not exist. An ID
// named with another source (FEATURES.md E13, supervisor R1) and history in a Changes list are not checked here.
func TestCheckUnnamedAndQuotedRefs(t *testing.T) {
	sup := ParseDoc("supervisor.md", "# s\n## 5. Business rules\n\n**R1 —** a rule.\n")
	a := ParseDoc("a.md", `# a
## 5. Business rules

**R1 —** a rule, which R1 names again, and R999 does not exist.
**R2 —** cites [the supervisor](supervisor.md) R998 and `+"`supervisor.md`"+` R997, and
[x](supervisor.md#5-business-rules) R996; [x](supervisor.md) R1 and `+"`supervisor.md`"+` R1 exist.
**R3 —** FEATURES.md E13, SEMANTICS §1 R7 and supervisor R1 are others'; ADR 0030 (4) is no rule.

**Changes.**
- 2026-09-24, R42: removed.
`)
	docs := map[string]*Doc{"a.md": a, "supervisor.md": sup}
	var got []string
	for _, f := range Check(docs, nil) {
		got = append(got, f.String())
	}
	joined := strings.Join(got, "\n")
	for _, w := range []string{"R999", "R998", "R997", "R996"} {
		if !strings.Contains(joined, w) {
			t.Errorf("no finding for %s in:\n%s", w, joined)
		}
	}
	if len(got) != 4 {
		t.Errorf("%d findings, want 4:\n%s", len(got), joined)
	}
}

// TestUntestedStrict pins -strict: an ID counts in a Test or Fuzz function's doc comment or a t.Run name, and
// not in a file-level comment, a helper's comment or a function body's prose.
func TestUntestedStrict(t *testing.T) {
	d := ParseDoc("a.md", fixtureA)
	tests := map[string]string{
		"x_test.go": "package x\n\n// a.md R3 at file level.\n\n" +
			"// TestDoc covers R1.\nfunc TestDoc(t *testing.T) {\n\t// R4 in the body\n\tt.Run(\"R2 named\", func(t *testing.T) {})\n}\n\n" +
			"// helper cites R5.\nfunc helper() {}\n",
	}
	got := map[string]bool{}
	for _, id := range UntestedStrict(map[string]*Doc{"a.md": d}, tests)["a.md"] {
		got[id] = true
	}
	for _, id := range []string{"R1", "R2"} {
		if _, ok := d.Rules[id]; ok && got[id] {
			t.Errorf("%s reported uncovered though a Test cites it", id)
		}
	}
	for _, id := range []string{"R3", "R4", "R5"} {
		if _, ok := d.Rules[id]; ok && !got[id] {
			t.Errorf("%s reported covered by text that is no Test's doc comment or t.Run name", id)
		}
	}
}

// TestWithdrawnRulesLeaveTheCounts pins the "(withdrawn)" heading marker: the rule stays defined, so a
// reference to it resolves, but neither coverage count includes it.
func TestWithdrawnRulesLeaveTheCounts(t *testing.T) {
	text := "# w\n## 6. Edge cases\n\n1. **E1** live.\n2. *(withdrawn) 2026-09-24.* gone.\n3. **E3 (withdrawn).** also gone.\n"
	d := ParseDoc("w.md", text)
	if len(d.Rules) != 3 || d.Live() != 1 {
		t.Fatalf("rules %d live %d, want 3 and 1", len(d.Rules), d.Live())
	}
	if d.Rules["E1"].Withdrawn || !d.Rules["E2"].Withdrawn || !d.Rules["E3"].Withdrawn {
		t.Errorf("withdrawn flags wrong: %+v", d.Rules)
	}
	docs := map[string]*Doc{"w.md": d}
	if u := Untested(docs, nil)["w.md"]; len(u) != 1 || u[0] != "E1" {
		t.Errorf("untested = %v, want [E1]", u)
	}
	if u := UntestedStrict(docs, nil)["w.md"]; len(u) != 1 || u[0] != "E1" {
		t.Errorf("strict untested = %v, want [E1]", u)
	}
}

// TestCheckCitedTests: a backquoted test name no function declares fails; a prefix with `*` needs one match; a
// line saying the test was renamed is history.
func TestCheckCitedTests(t *testing.T) {
	tests := map[string]string{"x_test.go": "package x\n\nfunc TestReal(t *testing.T) {}\nfunc FuzzReal(f *testing.F) {}\nfunc TestCachePart(t *testing.T) {}\n"}
	texts := map[string]string{
		"a.md": "ok `TestReal` and `FuzzReal` and `TestCache*`\nbad `TestGone` here\nbad prefix `TestNothing*`\n`TestOld` was renamed\nR12 holds because `TestOldName` was written to pin it\nthe tests were `TestGone2`\n",
	}
	got := CheckCitedTests(texts, tests)
	if len(got) != 4 || got[0].Line != 2 || got[1].Line != 3 || got[2].Line != 5 || got[3].Line != 6 {
		t.Errorf("findings = %v", got)
	}
}

// TestMidSectionChangesList: a rule defined after a Changes list in the same section is still a rule, and the
// list's own text stays history.
func TestMidSectionChangesList(t *testing.T) {
	d := ParseDoc("a.md", `# a
## 8. Invariants

**I10.** Ten. (a) one.

**Changes.**
- 2026-09-24, I10: reworded; **I99** is history, (z) too.
  continued line.

**I11.** Eleven.

**I12.** Twelve, which I12 names.

## 9. Conventions
`)
	for _, id := range []string{"I10", "I11", "I12"} {
		if d.Rules[id] == nil {
			t.Errorf("%s not parsed; have %v", id, d.Rules)
		}
	}
	if d.Rules["I99"] != nil {
		t.Error("I99 in the Changes list was parsed")
	}
	if r := d.Rules["I10"]; r != nil && (r.Parts["z"] || strings.Contains(r.Body, "reworded")) {
		t.Errorf("I10 swallowed the Changes list: %q", r.Body)
	}
	if f := Check(map[string]*Doc{"a.md": d}, nil); len(f) != 0 {
		t.Errorf("findings: %v", f)
	}
}
