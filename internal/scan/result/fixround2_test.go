// SPDX-License-Identifier: Apache-2.0

package result

import (
	"bytes"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

const unreadableWarningWant = "Tego cannot tell whether these are agents; any program can make itself unreadable."

func TestUnreadableProgramsWarningInEveryOutput(t *testing.T) {
	s := New(example(t).Finished, 1000, "dev")
	s.Counts.UnreadablePrograms = 1
	s.UnreadableProgramPIDs = []int{99}
	for _, check := range []string{"not-requested", "unreadable-observed", "none-observed-allow-unreadable"} {
		for _, mode := range []string{"short", "verbose", "json"} {
			t.Run(check+"/"+mode, func(t *testing.T) {
				s.Check = check
				var out, footer bytes.Buffer
				if err := Render(&out, &footer, s, mode == "json", mode == "verbose", nil); err != nil {
					t.Fatal(err)
				}
				if !strings.Contains(footer.String(), unreadableWarningWant) {
					t.Fatal("footer omits unreadable agent uncertainty")
				}
				if mode == "json" {
					var wire map[string]any
					if err := json.Unmarshal(out.Bytes(), &wire); err != nil {
						t.Fatal(err)
					}
					if wire["unreadable_programs_warning"] != unreadableWarningWant {
						t.Fatal("JSON omits fixed unreadable agent warning field")
					}
				} else if !strings.Contains(out.String(), unreadableWarningWant) {
					t.Fatal("text omits unreadable agent uncertainty")
				}
			})
		}
	}
}

func TestDecodeRequiresUnreadableProgramsWarning(t *testing.T) {
	s := example(t)
	b, err := Encode(s)
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	if wire["unreadable_programs_warning"] != unreadableWarningWant {
		t.Fatal("valid snapshot lacks the warning field")
	}
	for _, warning := range []any{nil, "", "All programs are classified."} {
		wire["unreadable_programs_warning"] = warning
		bad, err := json.Marshal(wire)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(bad); err == nil {
			t.Fatalf("accepted warning %v", warning)
		}
	}
	delete(wire, "unreadable_programs_warning")
	bad, err := json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(bad); err == nil {
		t.Fatal("accepted missing warning")
	}
}

func TestScanExitCodesAreNamed(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "types.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "ExitCode" {
			continue
		}
		found = true
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			if ret, ok := n.(*ast.ReturnStmt); ok {
				for _, expr := range ret.Results {
					sel, ok := expr.(*ast.SelectorExpr)
					if !ok {
						t.Error("scan exit code must use a named identity constant")
						continue
					}
					pkg, ok := sel.X.(*ast.Ident)
					if !ok || pkg.Name != "identity" || !strings.HasPrefix(sel.Sel.Name, "Exit") {
						t.Error("scan exit code must use a named identity constant")
					}
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("missing scan exit function")
	}
}
