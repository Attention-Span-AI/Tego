// SPDX-License-Identifier: Apache-2.0

package record

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// TestReasonsListEveryReasonConstant holds the closed set to the code: every Reason constant of this package is in
// the reasons list (Valid, Reasons), once, and the list holds nothing else. The word tables are held to Reasons (the
// reason channel's sentences, the dashboard's labels), so a code declared here and left out of the list would be
// refused by Valid and walked by none of their tests. It reads the source, so a constant added there is checked
// without anyone listing it.
func TestReasonsListEveryReasonConstant(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil || len(files) == 0 {
		t.Fatalf("package source: %v (%d files)", err, len(files))
	}
	declared := map[Reason]string{} // code → the constant that declares it
	names := 0
	fset := token.NewFileSet()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, file, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, s := range gd.Specs {
				vs := s.(*ast.ValueSpec)
				for i, n := range vs.Names {
					code, ok := reasonConst(t, vs, i)
					if !ok {
						continue
					}
					names++
					if other, dup := declared[code]; dup {
						t.Errorf("%s and %s both declare %q", other, n.Name, code)
					}
					declared[code] = n.Name
				}
			}
		}
	}
	for code, name := range declared {
		if !code.Valid() {
			t.Errorf("%s = %q is not in the reasons list (validate.go)", name, code)
		}
	}
	for _, code := range reasons {
		if _, ok := declared[code]; !ok {
			t.Errorf("the reasons list holds %q, which no Reason constant declares", code)
		}
	}
	if names != len(reasons) {
		t.Errorf("%d Reason constants, %d codes in the reasons list", names, len(reasons))
	}
}

// reasonConst is the code the i-th name of a const spec declares when that constant is a Reason, written
// `Name Reason = "code"` or `Name = Reason("code")`. A Reason constant whose value is not a string literal fails the
// test: a code is written out where it is declared.
func reasonConst(t *testing.T, vs *ast.ValueSpec, i int) (Reason, bool) {
	t.Helper()
	isReason := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == "Reason"
	}
	var value ast.Expr
	if i < len(vs.Values) {
		value = vs.Values[i]
	}
	switch {
	case vs.Type != nil && isReason(vs.Type):
	case vs.Type == nil && value != nil:
		call, ok := value.(*ast.CallExpr)
		if !ok || !isReason(call.Fun) || len(call.Args) != 1 {
			return "", false
		}
		value = call.Args[0]
	default:
		return "", false
	}
	lit, ok := value.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		t.Errorf("Reason constant %s is not a string literal", vs.Names[i].Name)
		return "", false
	}
	code, err := strconv.Unquote(lit.Value)
	if err != nil {
		t.Fatal(err)
	}
	return Reason(code), true
}
