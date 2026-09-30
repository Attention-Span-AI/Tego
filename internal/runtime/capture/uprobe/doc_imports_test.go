// SPDX-License-Identifier: Apache-2.0

package uprobe

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestDocListsEveryTegoImport keeps doc.go's Imports line equal to the tego packages the non-test files
// import, so a TCB-import review reads the truth (ADR 0031).
func TestDocListsEveryTegoImport(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	const mod = "github.com/attention-span-ai/tego/"
	got := map[string]bool{}
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(token.NewFileSet(), f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, im := range af.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			if strings.HasPrefix(p, mod) {
				got[strings.TrimPrefix(p, mod)] = true
			}
		}
	}
	doc, err := os.ReadFile("doc.go")
	if err != nil {
		t.Fatal(err)
	}
	s := string(doc)
	i := strings.Index(s, "// Imports:")
	j := strings.Index(s, "github.com/cilium")
	if i < 0 || j < i {
		t.Fatal("doc.go has no Imports line")
	}
	listed := map[string]bool{}
	for _, w := range strings.FieldsFunc(strings.ReplaceAll(s[i:j], "//", " "), func(r rune) bool { return r == ',' || r == ' ' || r == '\n' }) {
		if strings.Contains(w, "/") {
			listed[w] = true
		}
	}
	var diff []string
	for p := range got {
		if !listed[p] {
			diff = append(diff, "unlisted "+p)
		}
	}
	for p := range listed {
		if !got[p] {
			diff = append(diff, "stale "+p)
		}
	}
	sort.Strings(diff)
	if len(diff) > 0 {
		t.Fatalf("doc.go Imports line disagrees with the code: %v", diff)
	}
}
