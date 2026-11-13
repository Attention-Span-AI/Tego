// SPDX-License-Identifier: Apache-2.0

package chaincheck_test

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

// TestTheClosureReadsNoClockAndMakesNoIO follows production imports, including backend and
// rfc3339, instead of maintaining a partial list of directories. Selectors are resolved through
// each file's imports so an alias cannot conceal a clock or I/O call. Standard-library operations
// that can consult host state are refused too: time.Parse can initialize time.Local even though
// its result appears to depend only on the timestamp (ADR 0146).
func TestTheClosureReadsNoClockAndMakesNoIO(t *testing.T) {
	const module = "github.com/attention-span-ai/tego/"
	root, err := filepath.Abs(filepath.Join("..", "..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	packages := make(map[string]*build.Package)
	var visit func(string)
	visit = func(importPath string) {
		if _, seen := packages[importPath]; seen {
			return
		}
		dir := filepath.Join(root, filepath.FromSlash(strings.TrimPrefix(importPath, module)))
		pkg, err := build.Default.ImportDir(dir, 0)
		if err != nil {
			t.Fatalf("resolve %s: %v", importPath, err)
		}
		packages[importPath] = pkg
		for _, dep := range pkg.Imports {
			if strings.HasPrefix(dep, module) {
				visit(dep)
				continue
			}
			if dep == "C" || strings.Contains(strings.Split(dep, "/")[0], ".") {
				t.Errorf("%s imports non-standard dependency %s", importPath, dep)
			}
		}
	}
	visit(module + "pkg/spec/record/chaincheck")
	for _, required := range []string{"pkg/spec/record", "pkg/spec/identity", "pkg/spec/backend", "pkg/spec/rfc3339"} {
		if packages[module+required] == nil {
			t.Errorf("dependency closure did not include %s", required)
		}
	}
	for importPath, pkg := range packages {
		for _, name := range append(append([]string{}, pkg.GoFiles...), pkg.CgoFiles...) {
			filename := filepath.Join(pkg.Dir, name)
			file, err := parser.ParseFile(token.NewFileSet(), filename, nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			imports := make(map[string]string)
			for _, spec := range file.Imports {
				path, err := strconv.Unquote(spec.Path.Value)
				if err != nil {
					t.Fatal(err)
				}
				var local string
				if spec.Name != nil {
					local = spec.Name.Name
				} else if dep := packages[path]; dep != nil {
					local = dep.Name
				} else {
					dep, err := build.Default.Import(path, pkg.Dir, 0)
					if err != nil {
						t.Fatalf("%s: resolve %s: %v", filename, path, err)
					}
					local = dep.Name
				}
				if local == "." || local == "_" {
					t.Errorf("%s: %s import cannot be checked for purity", filename, path)
				}
				imports[local] = path
			}
			ast.Inspect(file, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
						if ident, ok := sel.X.(*ast.Ident); ok && ident.Obj == nil && imports[ident.Name] == "time" && sel.Sel.Name == "ParseInLocation" {
							utc := false
							if len(call.Args) == 3 {
								if loc, ok := call.Args[2].(*ast.SelectorExpr); ok && loc.Sel.Name == "UTC" {
									if ident, ok := loc.X.(*ast.Ident); ok && ident.Obj == nil && imports[ident.Name] == "time" {
										utc = true
									}
								}
							}
							if !utc {
								t.Errorf("%s: time.ParseInLocation must use time.UTC", filename)
							}
						}
					}
				}
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Obj != nil {
					return true
				}
				path := imports[ident.Name]
				member := sel.Sel.Name
				forbidden := false
				switch path {
				case "time":
					switch member {
					case "Now", "Since", "Until", "Sleep", "After", "AfterFunc", "Tick", "NewTicker", "NewTimer",
						"Parse", "Local", "LoadLocation":
						forbidden = true
					}
				case "os", "os/exec", "sync", "sync/atomic", "crypto/rand", "math/rand", "math/rand/v2", "log":
					forbidden = true
				case "syscall":
					// The identity leaf names signal and wait-status types and constants, but
					// must not invoke system calls or retain one in a function variable.
					forbidden = member != "Signal" && member != "WaitStatus" && !strings.HasPrefix(member, "SIG")
				case "fmt":
					forbidden = member == "Print" || member == "Printf" || member == "Println"
				case "net":
					forbidden = member != "SplitHostPort"
				default:
					forbidden = strings.HasPrefix(path, "golang.org/x/sys/") || strings.HasPrefix(path, "net/")
				}
				if forbidden {
					t.Errorf("%s (%s) refers to %s.%s", filename, importPath, path, member)
				}
				return true
			})
		}
	}
}
