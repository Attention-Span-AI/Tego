// SPDX-License-Identifier: Apache-2.0

package contracttest

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type syntheticFixture struct {
	Count int    `json:"count"`
	Why   string `json:"why"`
}

// This gate distinguishes executable-contract fixtures from intentional raw
// kernel/query/fault inputs. Moving a literal behind a new constructor would not
// establish compiler parity: common runtime fixtures must actually call Build.
// New or changed raw fixtures require an explicit, reviewed disposition.
func TestRuntimeFixturesAreCompiledOrExplicitSyntheticInputs(t *testing.T) {
	root, err := repositoryRoot()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "internal/testutil/contracttest/testdata/synthetic-fixtures.json"))
	if err != nil {
		t.Fatal(err)
	}
	var allowed map[string]map[string]syntheticFixture
	if err := json.Unmarshal(data, &allowed); err != nil {
		t.Fatal(err)
	}
	seen := make(map[string]map[string]int)
	common := map[string]string{
		"internal/runtime/observe/recorder_test.go":             "newFixture",
		"internal/runtime/enforce/cgroup/backend_test.go":       "newFixture",
		"internal/runtime/supervisor/fallback_mutation_test.go": "TestFallbackMutationConverges",
	}
	for _, directory := range []string{"internal/runtime/observe", "internal/runtime/enforce/cgroup", "internal/runtime/supervisor"} {
		paths, err := filepath.Glob(filepath.Join(root, directory, "*_test.go"))
		if err != nil || len(paths) == 0 {
			t.Fatalf("fixture inventory %s: %v", directory, err)
		}
		for _, path := range paths {
			relative, err := filepath.Rel(root, path)
			if err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			aliases := map[string]bool{}
			for _, imp := range file.Imports {
				name, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				if name == "github.com/attention-span-ai/tego/pkg/spec/agent" {
					alias := "agent"
					if imp.Name != nil {
						alias = imp.Name.Name
					}
					aliases[alias] = true
				}
			}
			for _, declaration := range file.Decls {
				function := "<package>"
				if fn, ok := declaration.(*ast.FuncDecl); ok {
					function = fn.Name.Name
				}
				literals, compiles := 0, 0
				ast.Inspect(declaration, func(node ast.Node) bool {
					if literal, ok := node.(*ast.CompositeLit); ok && ruleTableType(literal.Type, aliases) {
						literals++
					}
					if call, ok := node.(*ast.CallExpr); ok {
						if selector, ok := call.Fun.(*ast.SelectorExpr); ok {
							if object, ok := selector.X.(*ast.Ident); ok && object.Name == "contracttest" && (selector.Sel.Name == "Build" || selector.Sel.Name == "BuildAt") {
								compiles++
							}
						}
					}
					return true
				})
				if want, ok := common[relative]; ok && function == want {
					if compiles == 0 || literals != 0 {
						t.Errorf("%s/%s: want real compiler fixture without raw table; build calls=%d literals=%d", relative, function, compiles, literals)
					}
					delete(common, relative)
				}
				if literals == 0 {
					continue
				}
				if seen[relative] == nil {
					seen[relative] = map[string]int{}
				}
				seen[relative][function] += literals
			}
		}
	}
	if len(common) != 0 {
		t.Errorf("missing compiled fixture owners: %v", common)
	}
	for path, functions := range seen {
		for function, count := range functions {
			entry, ok := allowed[path][function]
			if !ok || entry.Count != count || strings.TrimSpace(entry.Why) == "" {
				t.Errorf("unclassified/changed raw fixture %s/%s: %d literals; disposition=%+v", path, function, count, entry)
			}
		}
	}
	for path, functions := range allowed {
		for function, entry := range functions {
			if entry.Count <= 0 || seen[path][function] != entry.Count {
				t.Errorf("stale fixture disposition %s/%s: %+v", path, function, entry)
			}
		}
	}
}

func ruleTableType(expression ast.Expr, aliases map[string]bool) bool {
	if selector, ok := expression.(*ast.SelectorExpr); ok {
		object, ok := selector.X.(*ast.Ident)
		return ok && aliases[object.Name] && selector.Sel.Name == "RuleTable"
	}
	identifier, ok := expression.(*ast.Ident)
	return ok && aliases["."] && identifier.Name == "RuleTable"
}

func repositoryRoot() (string, error) {
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if module, err := os.ReadFile(filepath.Join(path, "go.mod")); err == nil && strings.Contains(string(module), "module github.com/attention-span-ai/tego\n") {
			return path, nil
		}
		parent := filepath.Dir(path)
		if parent == path {
			return "", os.ErrNotExist
		}
		path = parent
	}
}
