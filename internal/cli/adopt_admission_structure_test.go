// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// TestAdoptionAdmissionChecksStayInTable pins calls in preparation and its
// reachable helpers as a tripwire for checks added outside the admission table.
// The guard covers direct static calls within this package; a check reached
// through an interface value, a function value or another package is not covered
// by the guard and is covered by review.
func TestAdoptionAdmissionChecksStayInTable(t *testing.T) {
	data, err := os.ReadFile("testdata/adopt-admission-calls.json")
	if err != nil {
		t.Fatal(err)
	}
	var inventory map[string]map[string][]string
	if err := json.Unmarshal(data, &inventory); err != nil {
		t.Fatal(err)
	}
	seenRoots := make(map[string]bool)
	for _, dir := range []string{".", filepath.Join("..", "runtime")} {
		fset := token.NewFileSet()
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		// Deliberately inspect all production source files across build tags.
		// The guard follows syntax and never type-checks a selected build.
		packages := make(map[string][]*ast.File)
		for _, entry := range entries {
			if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
				continue
			}
			file, err := parser.ParseFile(fset, filepath.Join(dir, entry.Name()), nil, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			packages[file.Name.Name] = append(packages[file.Name.Name], file)
		}
		for name, files := range packages {
			for _, file := range files {
				for _, decl := range file.Decls {
					if fn, ok := decl.(*ast.FuncDecl); ok {
						if _, root := admissionRootCalls(fset, fn); root {
							seenRoots[fn.Name.Name] = true
						}
					}
				}
			}
			for _, failure := range admissionPackageFailures(fset, files, inventory[name]) {
				t.Error(failure)
			}
		}
	}
	for name := range admissionOutsideCalls {
		if !seenRoots[name] {
			t.Errorf("monitored preparation function %s disappeared; review the admission call graph", name)
		}
	}
}

// TestAdoptionAdmissionStructureRejectsNestedChecks exercises cross-file and
// transitive helper discovery, including the reviewer's createScope example.
func TestAdoptionAdmissionStructureRejectsNestedChecks(t *testing.T) {
	for _, invocation := range []string{"scopeResources", "(scopeResources)", "scopeResources[int]", "scopeResources[int, string]"} {
		for _, nested := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/nested=%v", invocation, nested), func(t *testing.T) {
				fset := token.NewFileSet()
				sources := []string{
					"package runtime; func prepare() { a.createScope() }",
					"package runtime; func createScope() error { " + invocation + "(); return nil }",
					"package runtime; func scopeResources() error { createScope(); return nil }",
				}
				inventory := map[string][]string{"helper1.go:createScope": {invocation}, "helper2.go:scopeResources": {"createScope"}}
				parse := func() []*ast.File {
					t.Helper()
					var files []*ast.File
					for i, source := range sources {
						file, err := parser.ParseFile(fset, fmt.Sprintf("helper%d.go", i), source, parser.SkipObjectResolution)
						if err != nil {
							t.Fatal(err)
						}
						files = append(files, file)
					}
					return files
				}
				if failures := admissionPackageFailures(fset, parse(), inventory); len(failures) != 0 {
					t.Fatalf("reviewed cyclic helper graph refused: %v", failures)
				}
				refusal := "if err := newlyAddedAdmissionCheck(); err != nil { return err }; return nil"
				if nested {
					sources[2] = "package runtime; func scopeResources() error { createScope(); " + refusal + " }"
				} else {
					sources[1] = "package runtime; func createScope() error { " + invocation + "(); " + refusal + " }"
				}
				failures := admissionPackageFailures(fset, parse(), inventory)
				if !strings.Contains(strings.Join(failures, "\n"), "newlyAddedAdmissionCheck") {
					t.Fatalf("nested preparation check escaped: %v", failures)
				}
			})
		}
	}
}

func TestAdoptionAdmissionStructureRejectsNewDirectChecks(t *testing.T) {
	for _, tc := range []struct {
		function string
		body     string
	}{
		{"prepareAdmission", "newlyAddedAdmissionCheck()"},
		{"prepareAdmission", "a.checkTreeTasks()"},
		{"prepareAdmission", "check := a.checkTreeTasks; _ = check"},
		{"runAdopt", "newlyAddedAdmissionCheck()"},
		{"identifyForAdoption", "newlyAddedAdmissionCheck()"},
		{"adoptionRules", "newlyAddedAdmissionCheck()"},
		{"pinnedOwner", "newlyAddedAdmissionCheck()"},
		{"adoptOwners", "newlyAddedAdmissionCheck()"},
		{"cmdAdopt", "newlyAddedAdmissionCheck()"},
	} {
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, "injected.go", "package cli; func "+tc.function+"() { "+tc.body+" }", parser.SkipObjectResolution)
		if err != nil {
			t.Fatal(err)
		}
		if failures := admissionStructureFailures(fset, file); len(failures) == 0 {
			t.Errorf("new direct preparation check escaped %s: %s", tc.function, tc.body)
		}
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "table.go", `package cli
func prepareAdmission() {
 a.deps.Admission.Add(admission.Check{Name: "new check", Rechecked: true, Run: func() error { return newlyAddedAdmissionCheck() }})
}`, parser.SkipObjectResolution)
	if err != nil {
		t.Fatal(err)
	}
	if failures := admissionStructureFailures(fset, file); len(failures) != 0 {
		t.Fatalf("table-owned admission check refused: %v", failures)
	}
}

// These are lifecycle, diagnostics and table operations, not permission to call
// arbitrary admission helpers. Every other call in these functions belongs in a
// named Check.Run. prepare's two post-migration assertions retain their existing
// separate purpose and are allowed only after a.move, never before it.
var admissionOutsideCalls = map[string][]string{
	// Identification is a preflight whose same rules are passed as
	// AdoptSpec.Recheck and run by the table's root-identity entry. Pin its
	// composition and command entry too, so a new earlier check cannot escape.
	"cmdAdopt": {
		"fs.IntVar", "fs.StringVar", "fs.BoolVar", "fs.Func", "strconv.ParseUint", "fmt.Errorf",
		"append", "int", "fs.NArg", "message", "flagGiven", "len", "parseRecordMode", "err.Error",
		"adoptPrivileged", "runAdoptRelease", "runAdopt", "sudoSelf",
	},
	"runAdopt": {
		"adoptProc", "time.Now", "identifyForAdoption", "loadMachine", "writeConfigDiagnostics",
		"configRefused", "makeOwnDirs", "adoptPrepare", "t.Owner", "a.cleanup", "fmt.Fprint",
		"adoptNotice", "adoptLimitsNotice", "watchExit", "exits.stop", "adoptRun", "pinnedOwner",
		"a.keyed", "adoptedLine", "a.deps", "ownLogger", "errors.Is", "message", "err.Error",
		"adoptEndLine", "res.RecordErr.Error", "ledgerRootOf", "writeHint", "shortRun",
	},
	"identifyForAdoption": {
		"adopt.Identify", "errors.Is", "message", "fmt.Sprintf", "fmt.Fprintf", "printableExe",
		"record.Printable", "adoptSelf", "err.Error", "adoptionRules", "adoptOwners", "rules",
		"adopt.IsRefusal", "t.Owner", "adoptInvokingUID",
	},
	"adoptionRules": {"adopt.Check", "owners.Admit"},
	"pinnedOwner":   {"rules", "t.Owner", "fmt.Sprintf"},
	"adoptOwners":   {"append", "adoptInvokingUID"},
	"prepareAdoption": {
		"message", "err.Error", "a.admission.Add", "a.admission.Prepare", "a.cleanup",
	},
	// ADR 0152 refuses unavailable business rules before resources or dependencies
	// can be used. This availability-only preflight cannot admit a process.
	"newAdoption": {
		"rt.BusinessRulesConfigured", "errors.New",
		"fmt.Errorf", "deps.Enforce.Tier", "identity.ParseAgentID", "slog.New", "adopt.NewFS",
		"rt.AtTier", "make", "identified.IsZero", "time.Now", "a.deps.Admission.Add", "a.deps.Admission.Prepare",
	},
	"prepareEnforcement": {
		"splitCgroupPath", "string", "filepath.Join", "r.runQueue", "r.runQueue().Lane",
		"r.deps.Enforce.Prepare", "fmt.Errorf", "r.deps.Enforce.Tier", "r.group.Go", "l.RunListener",
		"kr.BPFHash", "dp.DecisionPlane", "a.prepareAdmission", "a.deps.Admission.Add", "a.deps.Admission.Prepare",
		"t.ReapTarget", "a.store.write", "h.Attach", "h.(api.Armer).Arm",
	},
	"prepareAdmission": {"a.deps.Admission.Add", "a.r.prepareBaselineRecord", "string", "a.r.deps.Enforce.Tier"},
	"finalAdmission":   {"a.deps.Admission.Recheck"},
	"prepare": {
		"a.deps.Admission.Add", "a.deps.Admission.Prepare", "r.openLedger", "openAdoptStore", "store.claim", "a.createScope", "splitCgroupPath",
		"os.Getpid", "r.anchorFile", "string", "store.write", "a.startReaper", "a.prepareEnforcement",
		"a.move", "time.Now", "fmt.Errorf", "a.startWorkers",
	},
}

var admissionHelperNames = []string{
	"compileAdoptionTable", "selectBackend", "CheckBaselineLaunchRecord", "contractCopy", "anchorPath",
	"captureRecordLocations", "recheckOwnerConfiguration", "validateBaselineLaunch", "baselineLaunchRecord",
	"refuseAdjustable", "adoptionLimits", "checkRootAdmission", "checkConfiguration", "ProbeAnchor",
	"checkTreeTasks", "RecheckBaseline", "checkKeyed", "checkKeyedPaths", "recheckPlaneAdmission",
}

func admissionStructureFailures(fset *token.FileSet, file *ast.File) []string {
	return admissionPackageFailures(fset, []*ast.File{file}, nil)
}

// admissionPackageFailures follows call names conservatively: all declarations
// with a matching name are visited, including methods with different receivers.
// Scanning all package files includes helpers declared outside adopt.go.
func admissionPackageFailures(fset *token.FileSet, files []*ast.File, inventory map[string][]string) []string {
	functions := make(map[string][]*ast.FuncDecl)
	imports := make(map[*ast.FuncDecl]map[string]bool)
	var queue []*ast.FuncDecl
	for _, file := range files {
		aliases := make(map[string]bool)
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil {
				panic(err)
			} // ParseFile already validated the import string.
			name := filepath.Base(path)
			if spec.Name != nil {
				name = spec.Name.Name
			}
			aliases[name] = true
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				functions[fn.Name.Name] = append(functions[fn.Name.Name], fn)
				imports[fn] = aliases
				if _, root := admissionRootCalls(fset, fn); root {
					queue = append(queue, fn)
				}
			}
		}
	}
	seen := make(map[*ast.FuncDecl]bool)
	var failures []string
	for len(queue) > 0 {
		fn := queue[0]
		queue = queue[1:]
		if seen[fn] {
			continue
		}
		seen[fn] = true
		// Follow every direct call, even calls in table-owned Run bodies. The latter
		// bodies are excluded only when checking calls outside the table below.
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				name := admissionCalleeName(call.Fun, imports[fn])
				queue = append(queue, functions[name]...)
			}
			return true
		})
		allowed, root := admissionRootCalls(fset, fn)
		if !root {
			key := admissionFunctionKey(fset, fn)
			var found bool
			allowed, found = inventory[key]
			if !found {
				// Include the actual calls to make review of a newly reachable helper easy.
				var calls []string
				ast.Inspect(fn.Body, func(node ast.Node) bool {
					if call, ok := node.(*ast.CallExpr); ok {
						calls = append(calls, admissionExpression(fset, call.Fun))
					}
					return true
				})
				slices.Sort(calls)
				calls = slices.Compact(calls)
				encoded, _ := json.Marshal(calls)
				failures = append(failures, fmt.Sprintf("unreviewed reachable helper %q: %s", key, encoded))
				continue
			}
		}
		failures = append(failures, admissionFunctionFailures(fset, fn, allowed, root)...)
	}
	slices.Sort(failures)
	return failures
}

// Parentheses and generic instantiation retain a direct call's static name.
func admissionCalleeName(expr ast.Expr, imports map[string]bool) string {
	switch callee := expr.(type) {
	case *ast.ParenExpr:
		return admissionCalleeName(callee.X, imports)
	case *ast.IndexExpr:
		return admissionCalleeName(callee.X, imports)
	case *ast.IndexListExpr:
		return admissionCalleeName(callee.X, imports)
	case *ast.Ident:
		return callee.Name
	case *ast.SelectorExpr:
		if qualifier, ok := callee.X.(*ast.Ident); ok && qualifier.Obj == nil && imports[qualifier.Name] {
			return ""
		}
		return callee.Sel.Name
	}
	return ""
}

func admissionRootCalls(fset *token.FileSet, fn *ast.FuncDecl) ([]string, bool) {
	if fn.Recv != nil && admissionExpression(fset, fn.Recv.List[0].Type) != "*adoption" {
		return nil, false
	}
	allowed, root := admissionOutsideCalls[fn.Name.Name]
	return allowed, root
}

func admissionFunctionKey(fset *token.FileSet, fn *ast.FuncDecl) string {
	receiver := ""
	if fn.Recv != nil {
		receiver = admissionExpression(fset, fn.Recv.List[0].Type) + "."
	}
	return filepath.Base(fset.Position(fn.Pos()).Filename) + ":" + receiver + fn.Name.Name
}

func admissionFunctionFailures(fset *token.FileSet, fn *ast.FuncDecl, allowed []string, pinReferences bool) []string {
	var failures []string

	var tableRuns []ast.Node
	var moved token.Pos
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		callee := admissionExpression(fset, call.Fun)
		if callee == "a.move" {
			moved = call.End()
		}
		if callee != "a.admission.Add" && callee != "a.deps.Admission.Add" && callee != "checks.Add" {
			return true
		}
		for _, arg := range call.Args {
			literal, ok := arg.(*ast.CompositeLit)
			if !ok || admissionExpression(fset, literal.Type) != "admission.Check" {
				continue
			}
			for _, element := range literal.Elts {
				field, ok := element.(*ast.KeyValueExpr)
				if ok && admissionExpression(fset, field.Key) == "Run" {
					tableRuns = append(tableRuns, field.Value)
				}
			}
		}
		return true
	})
	ast.Inspect(fn.Body, func(node ast.Node) bool {
		if node == nil {
			return false
		}
		for _, run := range tableRuns {
			if node.Pos() >= run.Pos() && node.End() <= run.End() {
				return false
			}
		}
		// These assertions detect changes after migration. They are not
		// preparation admission and must not become pre-move exceptions.
		postMove := fn.Name.Name == "prepare" && moved != token.NoPos && node.Pos() > moved
		if ident, ok := node.(*ast.Ident); ok && pinReferences && slices.Contains(admissionHelperNames, ident.Name) {
			if !postMove || (ident.Name != "RecheckBaseline" && ident.Name != "checkKeyedPaths") {
				failures = append(failures, fmt.Sprintf("%s: %s references admitting helper %s outside admission.Check.Run", fset.Position(node.Pos()), fn.Name.Name, ident.Name))
			}
		}
		if call, ok := node.(*ast.CallExpr); ok {
			callee := admissionExpression(fset, call.Fun)
			if postMove && (callee == "r.rt.RecheckBaseline" || callee == "a.checkKeyedPaths") {
				return true
			}
			if !slices.Contains(allowed, callee) {
				failures = append(failures, fmt.Sprintf("%s: %s calls %s outside admission.Check.Run; classify new admitting checks in the table", fset.Position(call.Pos()), fn.Name.Name, callee))
			}
		}
		return true
	})
	return failures
}

func admissionExpression(fset *token.FileSet, expr ast.Expr) string {
	var buf bytes.Buffer
	if err := printer.Fprint(&buf, fset, expr); err != nil {
		return "<unprintable expression>"
	}
	return strings.TrimSpace(buf.String())
}
