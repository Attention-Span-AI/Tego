// SPDX-License-Identifier: Apache-2.0

package rulesview

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestRuleSourceNamesTheContractLine: a rule a line names is found with the sentence, the rules file and the line it
// is written on, and its enforcement in words; asking again compiles nothing; a change to the run's copy builds the
// view again; a rule key the contract does not hold is not found.
func TestRuleSourceNamesTheContractLine(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000010-rsrc01")
	f.add(`"kind":"fs","source":"landlock","rule":"fs.write[./out/]","verdict":"allow","op":"write","path":"/x/out/a"`)
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	o := Options{Machine: f.m}
	before := ruleBuilds.Load()
	ro, ok := RuleSource(ctx, f.root, f.run, "fs.write[./out/]", o)
	if !ok {
		t.Fatal("fs.write[./out/] not found")
	}
	if want := lineOf(t, sourceText, "- ./out/"); ro.File != f.source || ro.Line != want || ro.Positions != PositionsSource {
		t.Errorf("at %s:%d (%s), want %s:%d in the rules file", ro.File, ro.Line, ro.Positions, f.source, want)
	}
	if ro.Sentence == "" || !strings.Contains(ro.Sentence, "./out/") || ro.StateWords != "enforced" || ro.Group == "" {
		t.Errorf("origin %+v", ro)
	}
	if git, ok := RuleSource(ctx, f.root, f.run, "exec[git]", o); !ok || git.Line != lineOf(t, sourceText, "allow: [sh, git]") {
		t.Errorf("exec[git]: %+v, %v", git, ok)
	}
	if _, ok := RuleSource(ctx, f.root, f.run, "fs.write[./nowhere/]", o); ok {
		t.Error("a rule the contract does not hold was found")
	}
	if _, ok := RuleSource(ctx, f.root, f.run, "unmatched", o); ok {
		t.Error("unmatched names no contract line, but was found")
	}
	if n := ruleBuilds.Load() - before; n != 1 {
		t.Errorf("%d views built for four lookups of one run, want 1", n)
	}

	// A new mtime on the run's copy is a new version of what the view reads.
	later := time.Now().Add(time.Minute)
	if err := os.Chtimes(filepath.Join(f.dir, "contract.yaml"), later, later); err != nil {
		t.Fatal(err)
	}
	if _, ok := RuleSource(ctx, f.root, f.run, "fs.write[./out/]", o); !ok {
		t.Fatal("not found after the copy was touched")
	}
	if n := ruleBuilds.Load() - before; n != 2 {
		t.Errorf("%d views built after the copy changed, want 2", n)
	}
	if _, ok := RuleSource(ctx, f.root, "not-a-run", "fs.write[./out/]", o); ok {
		t.Error("a malformed run id was looked up")
	}
}

// TestRuleSourceKeepsNoViewOfACancelledRequest: a view built for a request that was cancelled answers that request
// only; the next one builds it again, so a cancelled page load never hides the rules until a file changes.
func TestRuleSourceKeepsNoViewOfACancelledRequest(t *testing.T) {
	f := newFixture(t, "r-aaaaaaaa-0000000000010-rsrc02")
	if err := os.WriteFile(filepath.Join(f.dir, "events.jsonl"), f.lines.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Options{Machine: f.m}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := ruleBuilds.Load()
	_, _ = RuleSource(ctx, f.root, f.run, "fs.write[./out/]", o) // whatever a cancelled build found
	if _, ok := RuleSource(context.Background(), f.root, f.run, "fs.write[./out/]", o); !ok {
		t.Fatal("not found after a cancelled request")
	}
	if _, ok := RuleSource(context.Background(), f.root, f.run, "fs.write[./out/]", o); !ok {
		t.Fatal("not found on the third request")
	}
	if n := ruleBuilds.Load() - before; n != 2 {
		t.Errorf("%d views built, want 2 (the cancelled one is not kept, the next one is)", n)
	}
}
