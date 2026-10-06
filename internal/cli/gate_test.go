// SPDX-License-Identifier: Apache-2.0
package cli

import (
	"encoding/json"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestCompileGateEffectiveTextJSONAndScoredRows(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "gate.yaml")
	rows := filepath.Join(dir, "rows.yaml")
	if e := os.WriteFile(contract, []byte("version: 0\nname: gate-test\ncommand: [true]\ntier: landlock\nexec:\n  allow: [true]\ngate:\n  rules:\n    - exec matches true: 90\n"), 0600); e != nil {
		t.Fatal(e)
	}
	code, out, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK || !strings.Contains(out, "gate.rules[0]") || !strings.Contains(out, "90") {
		t.Fatalf("effective text%d %s %s", code, out, errs)
	}
	code, out, errs = run(t, "compile", contract, "--offline", "--json")
	var tbl Table
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &tbl) != nil || tbl.Gate == nil || tbl.Gate.Allow != 50 || len(tbl.Gate.Rules) != 1 {
		t.Fatalf("effective json%d %s %s", code, out, errs)
	}
	if e := os.WriteFile(rows, []byte("version: 0\ntests:\n - action: exec\n   argv: [true]\n   expect: refused\n   rule: gate.rules[0]\n"), 0600); e != nil {
		t.Fatal(e)
	}
	code, out, errs = run(t, "compile", contract, "--test", rows, "--tier", "landlock", "--offline", "--json")
	var rep TestReport
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Rows) != 1 || len(rep.Rows[0].Columns) != 1 {
		t.Fatalf("gate row%d %s %s", code, out, errs)
	}
	got := rep.Rows[0].Columns[0]
	if got.Score == nil || *got.Score != 90 || got.GateRule != "gate.rules[0]" || got.GateFacts != "test_row" {
		t.Fatalf("hypothetical scored cell%+v", got)
	}
}

// TestCompileTestGateBoundariesAndSum is the gate's thresholds as compile --test answers them (ADR
// 0007): with {allow: 50, ask: 80}, 49 allows, exactly 50 asks, 80 asks, 81 refuses; and the scores of
// the rules a read matches sum (30+20 = 50 asks where a highest-rule reading, 30, would allow), saturating at 100.
// The effective program prints the same bands.
func TestCompileTestGateBoundariesAndSum(t *testing.T) {
	dir := t.TempDir()
	contract := filepath.Join(dir, "gate.yaml")
	rows := filepath.Join(dir, "rows.yaml")
	src := "version: 0\nname: gate-bounds\ncommand: [true]\ntier: landlock\nexec:\n  allow: [true]\ngate:\n  rules:\n" +
		"    - fs.read matches \"*.b49\": 49\n    - fs.read matches \"*.b50\": 50\n    - fs.read matches \"*.b51\": 51\n" +
		"    - fs.read matches \"*.b80\": 80\n    - fs.read matches \"*.b81\": 81\n" +
		"    - fs.read matches \"*.env\": 30\n    - fs.read matches \"prod*\": 20\n    - fs.read matches \"*.der\": 60\n    - fs.read matches \"cert*\": 60\n" +
		"  thresholds: {allow: 50, ask: 80}\n"
	if e := os.WriteFile(contract, []byte(src), 0600); e != nil {
		t.Fatal(e)
	}
	code, out, errs := run(t, "compile", contract, "--offline")
	if code != identity.ExitOK || !strings.Contains(out, "gate      allow <50, ask 50..80, refused >80 (scores sum, saturating at 100;") {
		t.Fatalf("effective text%d %s %s", code, out, errs)
	}
	cases := []struct {
		name, expect string
		score        int
	}{
		{"x.b49", "allow", 49}, {"x.b50", "ask", 50}, {"x.b51", "ask", 51}, {"x.b80", "ask", 80}, {"x.b81", "refused", 81},
		{"x.env", "allow", 30}, {"prod.env", "ask", 50}, {"cert.der", "refused", 100}, {"other.txt", "allow", 0},
	}
	table := "version: 0\ntests:\n"
	for _, c := range cases {
		table += " - action: fs.read\n   path: " + filepath.Join(dir, c.name) + "\n   expect: " + c.expect + "\n"
	}
	if e := os.WriteFile(rows, []byte(table), 0600); e != nil {
		t.Fatal(e)
	}
	code, out, errs = run(t, "compile", contract, "--test", rows, "--tier", "landlock", "--offline", "--json")
	var rep TestReport
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Rows) != len(cases) {
		t.Fatalf("gate rows%d %s %s", code, out, errs)
	}
	for i, c := range cases {
		row := rep.Rows[i]
		if !row.Pass || len(row.Columns) != 1 {
			t.Errorf("%s: %+v", c.name, row)
			continue
		}
		got := row.Columns[0]
		if got.Score == nil || *got.Score != c.score || got.Verdict != c.expect {
			t.Errorf("%s: cell %+v, want score %d verdict %s", c.name, got, c.score, c.expect)
		}
	}
}

// TestCompileTestGateSumsReadAndWriteOfAMoveSource through compile --test: a rename's
// source leaves its name, so the read and the write predicates score it as one action and their scores sum (ADR
// 0007, 2026-10-20). Under `fs.read matches "*.env": 30` and `fs.write outside worktree: 30` with {allow: 50, ask:
// 80}, renaming out/prod.env away (both ends outside the worktree) scores 30+30 = 60 and asks, which a rename cannot
// complete, so it is refused; the stronger of the two kinds alone (30) allowed it. A rename is one action over both
// its ends, each rule counted once: renaming work/prod.env out of the worktree sums the
// source's read rule and the destination's write rule, 60, where the stronger end alone allowed it at 30; the write
// rule matching both ends counts once, and a destination that only receives the matching name reads nothing.
func TestCompileTestGateSumsReadAndWriteOfAMoveSource(t *testing.T) {
	dir, out := t.TempDir(), t.TempDir()
	src := "version: 0\nname: gate-sum-kinds\ncommand: [true]\ntier: landlock\nfs:\n  write: [./work, " + strconv.Quote(out) + "]\n" +
		"exec:\n  allow: [true]\ngate:\n  rules:\n    - fs.read matches \"*.env\": 30\n    - fs.write outside worktree: 30\n" +
		"  thresholds: {allow: 50, ask: 80}\n"
	cases := []struct {
		from, to, expect string
		score            int
	}{
		{filepath.Join(out, "prod.env"), filepath.Join(out, "notes"), "refused", 60},
		{filepath.Join(out, "notes"), filepath.Join(out, "prod.env"), "allow", 30},
		{filepath.Join(dir, "work", "prod.env"), filepath.Join(out, "notes"), "refused", 60},
		{filepath.Join(dir, "work", "notes"), filepath.Join(out, "notes"), "allow", 30},
		{filepath.Join(dir, "work", "prod.env"), filepath.Join(dir, "work", "notes"), "allow", 30},
	}
	table := "version: 0\ntests:\n"
	for _, c := range cases {
		table += " - action: fs.rename\n   path: " + c.from + "\n   dest: " + c.to + "\n   expect: " + c.expect + "\n"
	}
	for name, body := range map[string]string{"agent.yaml": src, "rows.yaml": table} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Chdir(dir)
	t.Setenv("TEGO_CONFIG", "")
	code, stdout, errs := run(t, "compile", "agent.yaml", "--test", "rows.yaml", "--tier", "landlock", "--offline", "--json")
	var rep TestReport
	if code != identity.ExitOK || json.Unmarshal([]byte(stdout), &rep) != nil || len(rep.Rows) != len(cases) {
		t.Fatalf("gate rows%d %s %s", code, stdout, errs)
	}
	for i, c := range cases {
		row := rep.Rows[i]
		if !row.Pass || len(row.Columns) != 1 {
			t.Errorf("%s -> %s: %+v", c.from, c.to, row)
			continue
		}
		if got := row.Columns[0]; got.Score == nil || *got.Score != c.score || got.Verdict != c.expect {
			t.Errorf("%s -> %s: cell %+v, want score %d verdict %s", c.from, c.to, got, c.score, c.expect)
		}
	}
}

// TestCompileTestGateScoresAMovedDirectoryOfAReadPattern through compile --test: a rename
// of a directory renames every file beneath it, so `mv work/secrets work/public` under `fs.read matches
// "work/secrets/*": 90` is scored 90 and refused, as a read of work/secrets/key is; it was allowed at 0, and a read of
// work/public/key then scored 0 and read the secret. A sibling directory's move and a destination that only receives
// the name stay unscored, and a name-only pattern scores no directory's move. Only a directory has paths beneath it:
// a row's object is one when it exists as one or the row says `dir: true`, as for ADR
// 0043's coverage question, and a regular file's move is matched by its own name, so under `fs.read matches
// "work/*.d/.env"` the move of a regular file work/notes.d is allowed where every move the component matched was
// refused.
func TestCompileTestGateScoresAMovedDirectoryOfAReadPattern(t *testing.T) {
	dir := t.TempDir()
	src := "version: 0\nname: gate-move-dir\ncommand: [true]\ntier: landlock\nfs:\n  write: [./work]\n" +
		"exec:\n  allow: [true]\ngate:\n  rules:\n    - fs.read matches \"work/secrets/*\": 90\n    - fs.read matches \"*.env\": 90\n" +
		"    - fs.read matches \"work/*.d/.env\": 90\n  thresholds: {allow: 50, ask: 80}\n"
	w := func(p string) string { return filepath.Join(dir, "work", p) }
	if e := os.MkdirAll(w("conf.d"), 0o755); e != nil {
		t.Fatal(e)
	}
	cases := []struct {
		action, from, to, expect string
		score                    int
		dir                      bool
	}{
		{"fs.read", w("secrets/key"), "", "refused", 90, false},
		{"fs.rename", w("secrets"), w("public"), "refused", 90, true},
		{"fs.rename", w("other"), w("public"), "allow", 0, true},
		{"fs.rename", w("other"), w("secrets"), "allow", 0, true},
		{"fs.rename", w("conf"), w("public"), "allow", 0, true},
		// A regular file named as the pattern's directory has nothing beneath it.
		{"fs.rename", w("secrets"), w("public"), "allow", 0, false},
		// Under a wildcard directory component: a regular file the component matches has nothing beneath it, and a
		// directory found on disk is one without the row saying so.
		{"fs.rename", w("notes.d"), w("notes.bak"), "allow", 0, false},
		{"fs.rename", w("conf.d"), w("old.d"), "refused", 90, false},
	}
	table := "version: 0\ntests:\n"
	for _, c := range cases {
		table += " - action: " + c.action + "\n   path: " + c.from + "\n"
		if c.to != "" {
			table += "   dest: " + c.to + "\n"
		}
		if c.dir {
			table += "   dir: true\n"
		}
		table += "   expect: " + c.expect + "\n"
	}
	for name, body := range map[string]string{"agent.yaml": src, "rows.yaml": table} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Chdir(dir)
	t.Setenv("TEGO_CONFIG", "")
	code, stdout, errs := run(t, "compile", "agent.yaml", "--test", "rows.yaml", "--tier", "landlock", "--offline", "--json")
	var rep TestReport
	if code != identity.ExitOK || json.Unmarshal([]byte(stdout), &rep) != nil || len(rep.Rows) != len(cases) {
		t.Fatalf("gate rows %d %s %s", code, stdout, errs)
	}
	for i, c := range cases {
		row := rep.Rows[i]
		if !row.Pass || len(row.Columns) != 1 {
			t.Errorf("%s %s -> %s: %+v", c.action, c.from, c.to, row)
			continue
		}
		if got := row.Columns[0]; got.Score == nil || *got.Score != c.score || got.Verdict != c.expect {
			t.Errorf("%s %s -> %s: cell %+v, want score %d verdict %s", c.action, c.from, c.to, got, c.score, c.expect)
		}
	}
}

// TestCompileRefusesAReadPatternNoCleanPathMatches through the CLI: `fs.read matches
// "./work/secrets/*"`, spelled as the contract's own `fs.write: [./work]` is, compiled with no warning and never fired,
// and the compile --test row reading work/secrets/key answered "allow via unmatched". Compile now refuses it and
// names the clean spelling, under which the row is refused by the rule.
func TestCompileRefusesAReadPatternNoCleanPathMatches(t *testing.T) {
	dir := t.TempDir()
	contract := func(pattern string) string {
		return "version: 0\nname: gate-clean\ncommand: [true]\ntier: landlock\nfs:\n  write: [./work]\nexec:\n  allow: [true]\n" +
			"gate:\n  rules:\n    - fs.read matches \"" + pattern + "\": 90\n  thresholds: {allow: 50, ask: 80}\n"
	}
	rows := "version: 0\ntests:\n - action: fs.read\n   path: " + filepath.Join(dir, "work", "secrets", "key") + "\n   expect: refused\n"
	for name, body := range map[string]string{"unclean.yaml": contract("./work/secrets/*"), "clean.yaml": contract("work/secrets/*"), "rows.yaml": rows} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte(body), 0600); e != nil {
			t.Fatal(e)
		}
	}
	t.Chdir(dir)
	t.Setenv("TEGO_CONFIG", "")
	code, out, errs := run(t, "compile", "unclean.yaml", "--offline")
	if code == identity.ExitOK || !strings.Contains(out+errs, `write "work/secrets/*"`) {
		t.Fatalf("compile of ./work/secrets/*: %d %s %s; want a refusal naming work/secrets/*", code, out, errs)
	}
	// The predicate is right, so the fix line speaks of the argument.
	if strings.Contains(out+errs, "gate predicates") || !strings.Contains(out+errs, "rewrite the argument") {
		t.Fatalf("compile of ./work/secrets/*: %s %s; want the fix to rewrite the argument, not the predicate", out, errs)
	}
	code, out, errs = run(t, "compile", "clean.yaml", "--test", "rows.yaml", "--tier", "landlock", "--offline", "--json")
	var rep TestReport
	if code != identity.ExitOK || json.Unmarshal([]byte(out), &rep) != nil || len(rep.Rows) != 1 || !rep.Rows[0].Pass {
		t.Fatalf("compile --test of work/secrets/*: %d %s %s", code, out, errs)
	}
	if got := rep.Rows[0].Columns[0]; got.Score == nil || *got.Score != 90 || got.GateRule != "gate.rules[0]" {
		t.Fatalf("read of work/secrets/key: %+v, want gate.rules[0] at 90", got)
	}
}
