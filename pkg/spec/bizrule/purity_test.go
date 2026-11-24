// SPDX-License-Identifier: Apache-2.0

package bizrule_test

import (
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Like chaincheck's closure test, inspect every production file reached by an
// import. This narrower leaf permits only explicitly pure standard packages;
// aliases, dot imports, goroutines, init hooks and imported callback machinery
// cannot conceal host-dependent decisions.
func TestTheClosureReadsNoClockAndMakesNoIO(t *testing.T) {
	const module = "github.com/attention-span-ai/tego/"
	root, err := filepath.Abs("../../..")
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"bytes": true, "crypto/sha256": true, "encoding/hex": true, "errors": true, "strconv": true, "unicode/utf16": true, "unicode/utf8": true}
	seen := map[string]bool{}
	var visit func(string)
	visit = func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		pkg, err := build.Default.ImportDir(filepath.Join(root, strings.TrimPrefix(path, module)), 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, dep := range pkg.Imports {
			if strings.HasPrefix(dep, module+"pkg/") {
				visit(dep)
			} else if !allowed[dep] {
				t.Errorf("%s imports impure/unreviewed package %s", path, dep)
			}
		}
		for _, name := range append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...) {
			file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(pkg.Dir, name), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				dep, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if imp.Name != nil && (imp.Name.Name == "." || imp.Name.Name == "_") {
					t.Errorf("uncheckable import %s", dep)
				}
			}
			ast.Inspect(file, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.GoStmt:
					t.Error("goroutine in pure closure")
				case *ast.SendStmt, *ast.ChanType, *ast.SelectStmt:
					t.Error("channel in pure closure")
				case *ast.FuncDecl:
					if n.Name.Name == "init" {
						t.Error("init hook in pure closure")
					}
				case *ast.CallExpr:
					if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "panic" && id.Obj == nil {
						t.Error("panic in pure closure")
					}
				}
				return true
			})
		}
	}
	visit(module + "pkg/spec/bizrule")
}
