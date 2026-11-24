// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/contracts"
)

// TestContextFreeReadsAreGoverned: a read of a remote service made with no request starts its helper as a governed
// program's caller, so it never takes the slots kept for a person's own checks (contracts.personHelperReserve).
func TestContextFreeReadsAreGoverned(t *testing.T) {
	if !contracts.GovernedCaller(unclassified()) {
		t.Fatal("a context-free read is classified as a person's")
	}
}

// backgroundAllowed are the functions of internal/control/rules and internal/control/web that make a background
// context, with why none is a request's. Anything else that calls context.Background or context.TODO fails the check:
// a request path starts its helpers with r.Context().
var backgroundAllowed = map[string]string{
	"rules.unclassified": "a context-free read: marked as a governed program's caller, so it takes no slot kept for a person",
	"rules.resolvedPath": "reached only where Service.remote() is false: inside the helper (no helper start) or with a test seam",
	"rules.Ref":          "no caller outside tests; requests use RefContext",
	"rules.EditDraft":    "a pure edit of a posted draft: builderChoices starts no helper without a Service",
	"web.Serve":          "the server's own shutdown deadline, after its context ended",
}

func TestNoRequestPathMakesABackgroundContext(t *testing.T) {
	for _, dir := range []string{".", "../web"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, file := range files {
			if strings.HasSuffix(file, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(token.NewFileSet(), file, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok {
					continue
				}
				ast.Inspect(fn, func(n ast.Node) bool {
					call, ok := n.(*ast.CallExpr)
					if !ok {
						return true
					}
					sel, ok := call.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "context" && (sel.Sel.Name == "Background" || sel.Sel.Name == "TODO") {
						if _, ok := backgroundAllowed[f.Name.Name+"."+fn.Name.Name]; !ok {
							t.Errorf("%s: %s.%s makes a background context: a request path passes r.Context()", filepath.Base(file), f.Name.Name, fn.Name.Name)
						}
					}
					return true
				})
			}
		}
	}
}
