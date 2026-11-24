// SPDX-License-Identifier: Apache-2.0

package gaps

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestGapWhysAreSpelledOnce: the whys of the price gaps and of a person's live changes are named once, as constants in
// pkg/spec/record, and every other package takes them from there. A copy of the spelling (a local constant, a map
// key, a case) is a second vocabulary that nothing keeps equal to the first (C175). Test files may spell a why to
// prove the constant says it; the record's own source is where the spelling lives.
func TestGapWhysAreSpelledOnce(t *testing.T) {
	spelled := map[string]bool{
		"no-price-table": true, "price-table-version-mismatch": true, "unpriced-model": true,
		"live-block-added": true, "live-block-removed": true, "live-block-expired": true, "live-unblock-expired": true,
		"live-rule-lifted": true, "live-rule-restored": true, "live-lift-expired": true, "live-lift-refused": true,
		"run-paused": true, "run-resumed": true, "pause-failed": true, "resume-failed": true,
		"mcp-tool-changed": true, "model-route-changed": true,
	}
	root := filepath.Join("..", "..", "..")
	var copies []string
	for _, top := range []string{"internal", "pkg", "cmd"} {
		_ = filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			slash := filepath.ToSlash(path)
			if d.IsDir() {
				if strings.HasSuffix(slash, "/pkg/spec/record") || d.Name() == "testdata" {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			fset := token.NewFileSet()
			f, perr := parser.ParseFile(fset, path, nil, 0)
			if perr != nil {
				t.Errorf("%s: %v", path, perr)
				return nil
			}
			ast.Inspect(f, func(n ast.Node) bool {
				lit, ok := n.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					return true
				}
				if s, err := strconv.Unquote(lit.Value); err == nil && spelled[s] {
					copies = append(copies, fset.Position(lit.Pos()).String()+" "+lit.Value)
				}
				return true
			})
			return nil
		})
	}
	sort.Strings(copies)
	for _, c := range copies {
		t.Errorf("a gap why spelled again outside pkg/spec/record: %s", c)
	}
}
