// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestCheckBareMDNamesFindsPlantedCitations: a bare Markdown name no file of the repository has fails, in prose,
// in a code span and in a Go comment; a name the repository holds, a path, a URL, a fenced block, a longer name,
// the agent instruction files and a name allowed at its own path do not. A name allowed at one path fails at another.
func TestCheckBareMDNamesFindsPlantedCitations(t *testing.T) {
	t.Parallel()
	docs := map[string]string{
		"docs/adr/0048-x.md": "# x\n\nMeasured (NOTES.md Q3, 2026-11-11).\nSee `PLAN.md` and GAPS.md, docs/GAPS.md, out/r.md.\n" +
			"```\nFENCED.md\n```\n[web](https://example.com/WEB.md) ~/scratch/HOME.md $dir/VAR.md x.md.golden CLAUDE.md AGENTS.md\n",
	}
	comments := map[string]map[int]string{
		"pkg/a/a_test.go": {12: "// the nine forms of NOTES.md's Q3", 13: "// TestX is gate.md R2 (%sREADME.md is a format)",
			14: "// measured in report.md and task.md"},
		"tools/deadcodereport/main.go": {85: "// it writes report.md"},
	}
	known := map[string]bool{"GAPS.md": true, "gate.md": true, "README.md": true}
	var lines []string
	for _, f := range CheckBareMDNames(docs, comments, known) {
		lines = append(lines, f.Doc+":"+strconv.Itoa(f.Line)+": "+strings.TrimSuffix(strings.Fields(f.What)[1], ","))
	}
	want := []string{
		"docs/adr/0048-x.md:3: NOTES.md",
		"docs/adr/0048-x.md:4: PLAN.md",
		"pkg/a/a_test.go:12: NOTES.md",
		"pkg/a/a_test.go:14: report.md",
		"pkg/a/a_test.go:14: task.md",
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// TestGoCommentLinesKeepsLineNumbers: a line comment and each line of a block comment are read under their own
// line numbers; string literals are not comments.
func TestGoCommentLinesKeepsLineNumbers(t *testing.T) {
	t.Parallel()
	src := "package p\n\n// one A.md\nvar s = \"B.md\" /* two\nC.md */\n"
	got := goCommentLines([]byte(src))
	if !strings.Contains(got[3], "A.md") || !strings.Contains(got[4], "two") || !strings.Contains(got[5], "C.md") || len(got) != 3 {
		t.Fatalf("comments by line: %v", got)
	}
}

// TestRepositoryCitesOnlyMarkdownFilesItHolds runs the bare-name check over this repository, as the rulecheck
// command in precommit and CI does.
func TestRepositoryCitesOnlyMarkdownFilesItHolds(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "p0")); err != nil {
		t.Skip("no docs/p0 here")
	}
	known, comments, err := loadBareMDInputs(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(known) < 100 || len(comments) < 500 {
		t.Fatalf("read %d Markdown names and %d Go files' comments, want the repository's", len(known), len(comments))
	}
	findings, err := checkBareMDNamesUnder(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}
