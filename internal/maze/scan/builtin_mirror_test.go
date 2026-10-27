// SPDX-License-Identifier: Apache-2.0

package scan

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// engineBuiltInDenyRead reads the engine's builtInDenyRead from pkg/spec/agent/compile_fs.go's source. This package
// cannot import pkg/spec/agent (it does not build on macOS, and maze must), so the test reads the list as data.
func engineBuiltInDenyRead(t *testing.T) []string {
	t.Helper()
	src := filepath.Join("..", "..", "..", "pkg", "spec", "agent", "compile_fs.go")
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	var rows []string
	found := false
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok || len(vs.Names) != 1 || vs.Names[0].Name != "builtInDenyRead" || len(vs.Values) != 1 {
			return true
		}
		lit, ok := vs.Values[0].(*ast.CompositeLit)
		if !ok {
			t.Fatalf("builtInDenyRead is no composite literal")
		}
		found = true
		for _, e := range lit.Elts {
			b, ok := e.(*ast.BasicLit)
			if !ok || b.Kind != token.STRING {
				t.Fatalf("builtInDenyRead holds a non-string element %T", e)
			}
			s, err := strconv.Unquote(b.Value)
			if err != nil {
				t.Fatal(err)
			}
			rows = append(rows, s)
		}
		return false
	})
	if !found {
		t.Fatalf("no builtInDenyRead in %s", src)
	}
	return rows
}

// TestBuiltInHomeMirrorsTheEngine holds builtInHome to the engine's builtInDenyRead, row for row and in order (ADR
// 0067's rows were added to the engine and not here, so `maze` called ~/.pypirc a file the engine leaves readable
// and told the user it did not block ~/.codex/auth.json). No row of extraHome, which maze
// reports as needing a rule of its own, may be one the engine already denies.
func TestBuiltInHomeMirrorsTheEngine(t *testing.T) {
	engine := engineBuiltInDenyRead(t)
	if !slices.Equal(builtInHome, engine) {
		for _, r := range engine {
			if !slices.Contains(builtInHome, r) {
				t.Errorf("builtInHome lacks the engine's row %q", r)
			}
		}
		for _, r := range builtInHome {
			if !slices.Contains(engine, r) {
				t.Errorf("builtInHome has %q, which the engine does not deny", r)
			}
		}
		t.Errorf("builtInHome differs from pkg/spec/agent builtInDenyRead (order included)")
	}
	for _, r := range extraHome {
		if slices.Contains(engine, r) {
			t.Errorf("extraHome suggests a rule for %q, which the engine denies with none", r)
		}
	}
}
