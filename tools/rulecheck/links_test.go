// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSlug(t *testing.T) {
	t.Parallel()
	for heading, want := range map[string]string{
		"5. Business rules":                        "5-business-rules",
		"5. Algorithms / rules":                    "5-algorithms--rules",
		"The tier-3 perf suite: `make vm-perf`":    "the-tier-3-perf-suite-make-vm-perf",
		"**R15 — deny_write**":                     "r15--deny_write",
		"See [the spec](spec.md) for §6":           "see-the-spec-for-6",
		"Both boots tier 3 needs: `VM_BOOTS=both`": "both-boots-tier-3-needs-vm_bootsboth",
	} {
		if got := Slug(heading); got != want {
			t.Errorf("Slug(%q) = %q, want %q", heading, got, want)
		}
	}
}

// TestCheckLinksFindsPlantedBreakage: a link to a file that does not exist and an anchor its target does not
// define fail; links that resolve, external links, links in code and a repeated heading's -1 anchor do not.
func TestCheckLinksFindsPlantedBreakage(t *testing.T) {
	t.Parallel()
	docs := map[string]string{
		"docs/adr/0035-x.md": "# x\n\nSee [CAPABILITIES](../CAPABILITIES.md) and [caps](../../spec/backend/CAPABILITIES.md).\n",
		"docs/p0/gate.md": "# Gate\n\n[contract](agent-contract.md#5-algorithms--rules) [ok](agent-contract.md#5-business-rules)\n" +
			"[self](#5-algorithms--rules) [dup](#notes-1) [missing self](#nowhere)\n\n## 5. Algorithms / rules\n\n## Notes\n\n## Notes\n" +
			"\n`[code](nowhere.md)`\n\n```\n[fenced](nowhere.md)\n```\n\n[web](https://example.com/x.md#y) [mail](mailto:a@b)\n" +
			"[ref]: ../nothere.md\n",
		"docs/p0/agent-contract.md": "# Contract\n\n## 5. Business rules\n",
	}
	files := map[string]bool{"spec/backend/CAPABILITIES.md": true}
	for p := range docs {
		files[p] = true
	}
	got := CheckLinks(docs, func(rel string) bool { return files[filepath.ToSlash(rel)] }, func(string) (string, bool) { return "", false })
	want := []string{
		"docs/adr/0035-x.md:3: links ../CAPABILITIES.md, which does not exist",
		"docs/p0/gate.md:3: links agent-contract.md#5-algorithms--rules, but docs/p0/agent-contract.md has no heading or anchor #5-algorithms--rules",
		"docs/p0/gate.md:4: links #nowhere, but docs/p0/gate.md has no heading or anchor #nowhere",
		"docs/p0/gate.md:19: links ../nothere.md, which does not exist",
	}
	var lines []string
	for _, f := range got {
		lines = append(lines, f.String())
	}
	if strings.Join(lines, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(lines, "\n"), strings.Join(want, "\n"))
	}
}

// TestRepositoryLinksResolve runs the link check over this repository, as the rulecheck command in precommit and
// CI does.
func TestRepositoryLinksResolve(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, "docs", "p0")); err != nil {
		t.Skip("no docs/p0 here")
	}
	docs, err := LoadLinked(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(docs) < 50 {
		t.Fatalf("read %d Markdown files, want the repository's documentation", len(docs))
	}
	findings, err := checkLinksUnder(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range findings {
		t.Error(f)
	}
}
