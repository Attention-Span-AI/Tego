// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strings"
	"testing"
)

// TestPackageDocNamesItsHelpers holds the package doc to the helpers it introduces: each paragraph that opens by
// naming helpers ("X, Y and Z are how ...", "X is ...") names only declarations this package has, a top-level
// name or a Type.Method. A helper renamed or removed leaves no paragraph telling a test author to call it.
func TestPackageDocNamesItsHelpers(t *testing.T) {
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	var pkgDoc string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		if f.Doc != nil && strings.HasPrefix(f.Doc.Text(), "Package ") {
			pkgDoc = f.Doc.Text()
		}
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.FuncDecl:
				if d.Recv == nil {
					declared[d.Name.Name] = true
					continue
				}
				recv := d.Recv.List[0].Type
				if star, ok := recv.(*ast.StarExpr); ok {
					recv = star.X
				}
				if id, ok := recv.(*ast.Ident); ok {
					declared[id.Name+"."+d.Name.Name] = true
				}
			case *ast.GenDecl:
				for _, s := range d.Specs {
					switch s := s.(type) {
					case *ast.TypeSpec:
						declared[s.Name.Name] = true
					case *ast.ValueSpec:
						for _, n := range s.Names {
							declared[n.Name] = true
						}
					}
				}
			}
		}
	}
	if pkgDoc == "" {
		t.Fatal("no package doc found")
	}
	ident := regexp.MustCompile(`^[A-Z]\w*(\.[A-Z]\w*)?$`)
	lead := regexp.MustCompile(`^(.*?) (?:is|are) `)
	checked := 0
	for _, para := range strings.Split(pkgDoc, "\n\n") {
		para = strings.Join(strings.Fields(para), " ")
		m := lead.FindStringSubmatch(para)
		if m == nil {
			continue
		}
		names := strings.FieldsFunc(strings.ReplaceAll(m[1], " and ", ","), func(r rune) bool { return r == ',' })
		all := len(names) > 0
		for i := range names {
			names[i] = strings.TrimSpace(names[i])
			all = all && ident.MatchString(names[i])
		}
		if !all {
			continue // the paragraph does not open by naming helpers
		}
		for _, n := range names {
			checked++
			if !declared[n] {
				t.Errorf("the package doc names %s, which this package does not declare: %q", n, para)
			}
		}
	}
	if checked == 0 {
		t.Fatal("the package doc names no helpers this test could check")
	}
}
