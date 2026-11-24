// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestNoRuleDefinedAfterChangesList: ParseDoc cuts a rules section at its "**Changes.**" list, so a rule
// defined after that marker is never registered.
func TestNoRuleDefinedAfterChangesList(t *testing.T) {
	docs := componentDocsRoot(filepath.Join("..", ".."))
	if docs == "" {
		t.Skip("no component documents here (a tree that keeps frozen copies reads them from its archive folder)")
	}
	files, _ := filepath.Glob(filepath.Join(docs, "docs", "p0", "*.md"))
	if len(files) == 0 {
		t.Fatal("docs/p0 holds no document")
	}
	def := regexp.MustCompile(`^\*\*([REI]\d+)\.\*\*`)
	for _, f := range files {
		data, _ := os.ReadFile(f)
		afterChanges := false
		for i, line := range strings.Split(string(data), "\n") {
			switch {
			case strings.HasPrefix(line, "## "):
				afterChanges = false
			case strings.HasPrefix(line, "**Changes.**"):
				afterChanges = true
			case afterChanges && def.MatchString(line):
				t.Errorf("%s:%d: %s is defined after the Changes list, where rulecheck does not read it", f, i+1, def.FindStringSubmatch(line)[1])
			}
		}
	}
}
