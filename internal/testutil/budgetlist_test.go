// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bufio"
	"bytes"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// testutilImport is this package's import path, as a budget test imports it.
const testutilImport = "github.com/attention-span-ai/tego/internal/testutil"

// budgetListScript is where budget mode's list of tests lives, from the module root.
const budgetListScript = "scripts/timing-budgets.sh"

// TestTimingBudgetsListsEveryBudgetTest holds scripts/timing-budgets.sh's list to the tree: every test that calls
// testutil.TimingMode is named there, under build tags its file builds with, and every test named there calls it.
// Budget mode is the only run that asserts a budget's Limit and Target as written; a budget test the list leaves
// out would be held to ten times its Limit everywhere, and nothing would say so.
func TestTimingBudgetsListsEveryBudgetTest(t *testing.T) {
	root := moduleRoot(t)
	listed, problems, err := budgetListMismatches(root)
	if err != nil {
		t.Fatal(err)
	}
	if listed == 0 {
		t.Fatalf("%s lists no budget tests: its default_tests block was not found", budgetListScript)
	}
	for _, p := range problems {
		t.Error(p)
	}
}

// TestBudgetListCheckFindsEachMismatch runs the check on a tree made for it: a budget test the list leaves out, one
// listed under tags its file does not build with, a listed test that calls no TimingMode, a TimingMode called
// outside a test function, and a Mode built by hand each fail it, and a tree whose list matches passes.
func TestBudgetListCheckFindsEachMismatch(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	const imp = "import \"" + testutilImport + "\"\n\n"
	write("go.mod", "module example.com/m\n")
	write("a/a_test.go", "package a\n\n"+imp+"func TestA(t *testing.T) { _ = testutil.TimingMode(t) }\n")
	write("b/b_test.go", "//go:build integration\n\npackage b\n\nimport tu \""+testutilImport+"\"\n\n"+
		"func TestB(t *testing.T) { m := tu.TimingMode(t); _ = m }\n")
	write("b/c_test.go", "package b\n\nfunc TestNotABudget(t *testing.T) {}\n")
	write(".hidden/h_test.go", "package h\n\n"+imp+"func TestHidden(t *testing.T) { testutil.TimingMode(t) }\n")
	write("a/testdata/x_test.go", "package x\n\n"+imp+"func TestData(t *testing.T) { testutil.TimingMode(t) }\n")
	write("nested/go.mod", "module example.com/nested\n")
	write("nested/n_test.go", "package n\n\n"+imp+"func TestNested(t *testing.T) { testutil.TimingMode(t) }\n")
	script := func(lines string) {
		write(budgetListScript, "#!/usr/bin/env bash\nset -eu\ndefault_tests='\n"+lines+"'\n\nGO=${GO:-go}\n")
	}

	script("a  -            TestA\nb  integration  TestB\n")
	if n, problems, err := budgetListMismatches(root); err != nil || n != 2 || len(problems) != 0 {
		t.Fatalf("a matching list: %d listed, problems %q, error %v; want 2 and none", n, problems, err)
	}

	write("u/u_test.go", "package u\n\n"+imp+"func TestUnlisted(t *testing.T) { testutil.TimingMode(t) }\n")
	write("v/v_test.go", "package v\n\n"+imp+"func measure(t *testing.T) { testutil.TimingMode(t) }\n"+
		"func TestUsesAHelper(t *testing.T) { measure(t) }\n")
	write("w/w_test.go", "package w\n\n"+imp+"func TestHandMade(t *testing.T) { _ = testutil.Mode{} }\n")
	script("a  -            TestA\nb  -            TestB TestNotABudget\n")
	_, problems, err := budgetListMismatches(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"u TestUnlisted (u/u_test.go) calls testutil.TimingMode and is not in " + budgetListScript,
		"b TestB is listed with tags \"\", under which b/b_test.go does not build",
		"b TestNotABudget is listed in " + budgetListScript + " and calls no testutil.TimingMode",
		"v/v_test.go: measure calls testutil.TimingMode outside a test function",
		"w/w_test.go: TestHandMade builds a testutil.Mode itself",
	} {
		if !slices.ContainsFunc(problems, func(p string) bool { return strings.HasPrefix(p, want) }) {
			t.Errorf("no problem starting %q in %q", want, problems)
		}
	}
	if len(problems) != 5 {
		t.Errorf("%d problems, want 5 (the hidden, testdata and nested-module tests are not the tree's): %q",
			len(problems), problems)
	}
}

// moduleRoot is the directory holding this module's go.mod, above the package directory a test runs in.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's directory")
		}
		dir = parent
	}
}

// budgetListEntry is one test the script lists: the build tags its package's binary is built with.
type budgetListEntry struct{ tags []string }

// budgetTest is one test function that calls testutil.TimingMode, in the files that declare it.
type budgetTest struct{ files []string }

// budgetListMismatches compares the script's list under root with the TimingMode callers of root's _test.go files,
// walked as ./... walks them (no directory starting with . or _, no testdata or vendor, no nested module). It
// returns how many tests the list names and every disagreement, sorted.
func budgetListMismatches(root string) (int, []string, error) {
	listed, err := readBudgetList(filepath.Join(root, filepath.FromSlash(budgetListScript)))
	if err != nil {
		return 0, nil, err
	}
	found, problems, err := findBudgetTests(root)
	if err != nil {
		return 0, nil, err
	}
	for key, bt := range found {
		le, ok := listed[key]
		if !ok {
			problems = append(problems, fmt.Sprintf("%s (%s) calls testutil.TimingMode and is not in %s: its budget "+
				"would be held only to the unit gate's ceiling", key, strings.Join(bt.files, ", "), budgetListScript))
			continue
		}
		if !slices.ContainsFunc(bt.files, func(f string) bool { return buildsWith(root, f, le.tags) }) {
			problems = append(problems, fmt.Sprintf("%s is listed with tags %q, under which %s does not build", key,
				strings.Join(le.tags, ","), strings.Join(bt.files, ", ")))
		}
	}
	for key := range listed {
		if _, ok := found[key]; !ok {
			problems = append(problems, fmt.Sprintf("%s is listed in %s and calls no testutil.TimingMode (or does "+
				"not exist): budget mode would assert nothing for it", key, budgetListScript))
		}
	}
	slices.Sort(problems)
	return len(listed), problems, nil
}

// readBudgetList reads the script's default_tests block: one package directory, its tags ("-" for none) and its
// tests a line. The key of each test is "<package directory> <test>".
func readBudgetList(script string) (map[string]budgetListEntry, error) {
	b, err := os.ReadFile(script)
	if err != nil {
		return nil, err
	}
	listed := map[string]budgetListEntry{}
	in, closed := false, false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if !in {
			in = line == "default_tests='"
			continue
		}
		if line == "'" {
			closed = true
			break
		}
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		if len(f) < 3 {
			return nil, fmt.Errorf("%s: default_tests line %q names no test", script, line)
		}
		var tags []string
		if f[1] != "-" {
			tags = strings.Split(f[1], ",")
		}
		for _, name := range f[2:] {
			key := f[0] + " " + name
			if _, dup := listed[key]; dup {
				return nil, fmt.Errorf("%s: %s is listed twice", script, key)
			}
			listed[key] = budgetListEntry{tags: tags}
		}
	}
	if in && !closed {
		return nil, fmt.Errorf("%s: default_tests is not closed", script)
	}
	return listed, sc.Err()
}

// findBudgetTests parses every _test.go file under root and returns the test functions that refer to
// testutil.TimingMode, keyed "<package directory> <test>", with the problems found on the way: a reference outside a
// test function, which a list of test names cannot reach, and a testutil.Mode built without TimingMode.
func findBudgetTests(root string) (map[string]*budgetTest, []string, error) {
	found := map[string]*budgetTest{}
	var problems []string
	fset := token.NewFileSet()
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if path == root {
				return nil
			}
			name := d.Name()
			if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || name == "testdata" || name == "vendor" {
				return filepath.SkipDir
			}
			if _, err := os.Stat(filepath.Join(path, "go.mod")); err == nil {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, "_test.go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		f, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		local := ""
		for _, imp := range f.Imports {
			if p, _ := strconv.Unquote(imp.Path.Value); p != testutilImport {
				continue
			}
			local = "testutil"
			if imp.Name != nil {
				local = imp.Name.Name
			}
		}
		switch local {
		case "", "_":
			return nil
		case ".":
			problems = append(problems, fmt.Sprintf("%s: dot-imports testutil, which this check cannot follow", rel))
			return nil
		}
		refers := func(n ast.Node, sel string) bool {
			s, ok := n.(*ast.SelectorExpr)
			if !ok || s.Sel.Name != sel {
				return false
			}
			x, ok := s.X.(*ast.Ident)
			return ok && x.Name == local
		}
		for _, decl := range f.Decls {
			name := "a package-level declaration"
			fd, isFunc := decl.(*ast.FuncDecl)
			if isFunc {
				name = fd.Name.Name
			}
			uses := false
			ast.Inspect(decl, func(n ast.Node) bool {
				if refers(n, "TimingMode") {
					uses = true
				}
				if cl, ok := n.(*ast.CompositeLit); ok && cl.Type != nil && refers(cl.Type, "Mode") {
					problems = append(problems, fmt.Sprintf("%s: %s builds a testutil.Mode itself; a Mode comes only "+
						"from testutil.TimingMode, which budget mode can switch", rel, name))
				}
				return true
			})
			if !uses {
				continue
			}
			if !isFunc || fd.Recv != nil || !isTestName(fd.Name.Name) {
				problems = append(problems, fmt.Sprintf("%s: %s calls testutil.TimingMode outside a test function; "+
					"%s runs budget tests by name, so call it in the test itself", rel, name, budgetListScript))
				continue
			}
			key := filepath.ToSlash(filepath.Dir(rel)) + " " + fd.Name.Name
			if found[key] == nil {
				found[key] = &budgetTest{}
			}
			found[key].files = append(found[key].files, rel)
		}
		return nil
	})
	return found, problems, err
}

// isTestName reports whether name is a test function's name: Test, then nothing or a character that is not a lower
// case letter.
func isTestName(name string) bool {
	rest, ok := strings.CutPrefix(name, "Test")
	return ok && (rest == "" || !(rest[0] >= 'a' && rest[0] <= 'z'))
}

// buildsWith reports whether the file rel under root builds as timing-budgets.sh builds its package: on Linux, on
// this machine's architecture, with cgo off and the listed tags.
func buildsWith(root, rel string, tags []string) bool {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", runtime.GOARCH, false
	ctx.BuildTags = tags
	ok, err := ctx.MatchFile(filepath.Join(root, filepath.Dir(filepath.FromSlash(rel))), filepath.Base(rel))
	return err == nil && ok
}
