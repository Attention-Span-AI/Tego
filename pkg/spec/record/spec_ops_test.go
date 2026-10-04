// SPDX-License-Identifier: Apache-2.0

package record

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestSpecFSOpListMatchesConstants: spec/record/v1/README.md's `fs` op list is the frozen contract an independent
// reader is written from; every FS* op the code writes must be in it, and it lists nothing else.
func TestSpecFSOpListMatchesConstants(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "..", "spec", "record", "v1", "README.md"))
	if err != nil {
		t.Skip("no spec here")
	}
	m := regexp.MustCompile("`fs` carries `op` \\(`([a-z|]+)`").FindSubmatch(b)
	if m == nil {
		t.Fatal("spec has no fs op list")
	}
	listed := map[string]bool{}
	for _, o := range strings.Split(string(m[1]), "|") {
		listed[o] = true
	}
	ops := fsOpConstants(t)
	if len(listed) != len(ops) {
		t.Errorf("spec lists %d ops, code has %d", len(listed), len(ops))
	}
	for _, o := range ops {
		if !listed[o] {
			t.Errorf("spec's fs op list lacks %q", o)
		}
	}
}

// fsOpConstants parses payload.go and returns the value of every op constant in payload.go's FS operation block, so a new op fails the
// test until the spec lists it.
func fsOpConstants(t *testing.T) []string {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "payload.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ops []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		isOps := false // the "FS operation values" block, the one that holds FSOpen
		for _, sp := range gd.Specs {
			if vs := sp.(*ast.ValueSpec); len(vs.Names) > 0 && vs.Names[0].Name == "FSOpen" {
				isOps = true
			}
		}
		if !isOps {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i := range vs.Names {
				if i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					ops = append(ops, strings.Trim(lit.Value, `"`))
				}
			}
		}
	}
	if len(ops) == 0 {
		t.Fatal("no FS* constants found in payload.go")
	}
	return ops
}
