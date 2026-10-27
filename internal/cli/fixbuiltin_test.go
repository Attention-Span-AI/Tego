// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// builtinProfileName is a built-in profile's name as a diagnostic's text would write it.
var builtinProfileName = regexp.MustCompile(`\btego/[a-z0-9][a-z0-9._-]*(/[a-z0-9][a-z0-9._-]*)*`)

// TestFixesNameOnlyRegisteredBuiltinProfiles: a diagnostic's fix that tells the author to extend a built-in profile
// names one this binary resolves (secret-env's fix said "extend tego/no-secrets", and a contract that did so failed
// extends-not-found, since no built-in profile was registered then). Every string literal passed to a fix
// in the compiler and the CLI is read from the source, and each
// tego/ name in it must resolve through profileSources, the one place built-in sources are registered.
func TestFixesNameOnlyRegisteredBuiltinProfiles(t *testing.T) {
	src := profileSources(config.Builtin())
	checked := 0
	for _, dir := range []string{filepath.Join("..", "..", "pkg", "spec", "agent"), "."} {
		ents, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ents {
			name := e.Name()
			if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				continue
			}
			path := filepath.Join(dir, name)
			f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(f, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok || !isFixCall(call) {
					return true
				}
				ast.Inspect(call, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					s, err := strconv.Unquote(lit.Value)
					if err != nil {
						return true
					}
					checked++
					for _, p := range builtinProfileName.FindAllString(s, -1) {
						if _, _, err := src.Resolve(p); err != nil {
							t.Errorf("%s: a fix names the built-in profile %s, which this binary does not resolve: %v", path, p, err)
						}
					}
					return true
				})
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("no fix text found; the scan is not reading the compiler's source")
	}
}

// isFixCall reports whether call is a diagnostic's fix: fix(...) or <x>.fix(...) / <x>.Fix(...).
func isFixCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name == "fix"
	case *ast.SelectorExpr:
		return fn.Sel.Name == "fix" || fn.Sel.Name == "Fix"
	}
	return false
}
