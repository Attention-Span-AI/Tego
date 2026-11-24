// SPDX-License-Identifier: Apache-2.0

package runscope_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runscope"
	"github.com/attention-span-ai/tego/internal/testutil/answertest"
)

// TestAnswerTableNamesEveryCause: the table every caller's test walks (answertest.Rows) holds every cause this
// package declares, each with words, and permits on outside alone.
func TestAnswerTableNamesEveryCause(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "answer.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	declared := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		v, ok := n.(*ast.ValueSpec)
		if !ok || len(v.Names) != 1 || !strings.HasPrefix(v.Names[0].Name, "Cause") || len(v.Values) != 1 {
			return true
		}
		if lit, ok := v.Values[0].(*ast.BasicLit); ok && lit.Kind == token.STRING {
			s, _ := strconv.Unquote(lit.Value)
			declared[s] = true
		}
		return true
	})
	if len(declared) < 23 {
		t.Fatalf("answer.go declares %d causes; this test no longer reads them all", len(declared))
	}
	seen := map[string]bool{}
	permits := 0
	for _, r := range answertest.Rows() {
		if r.Permits != r.Answer.Outside() {
			t.Errorf("row %q: Permits %v, Outside() %v", r.Name, r.Permits, r.Answer.Outside())
		}
		if r.Permits {
			permits++
			continue
		}
		if got := runscope.Describe(r.Answer).Cause; got != r.Cause {
			t.Errorf("row %q carries cause %q; its answer has %q", r.Name, r.Cause, got)
		}
		if r.Cause != "" {
			seen[string(r.Cause)] = true
			if w := runscope.Why(r.Answer); strings.Contains(w, "gave no reason") {
				t.Errorf("row %q: the cause has no words: %q", r.Name, w)
			}
		}
		if runscope.Why(r.Answer) == "" {
			t.Errorf("row %q: a refusal with no words", r.Name)
		}
	}
	if permits != 1 {
		t.Errorf("%d rows permit; want outside alone", permits)
	}
	for c := range declared {
		if !seen[c] {
			t.Errorf("cause %q is declared and no row of the table carries it", c)
		}
	}
	for c := range seen {
		if !declared[c] {
			t.Errorf("the table carries cause %q, which answer.go does not declare", c)
		}
	}
}

// moduleRoot is the directory that holds go.mod.
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
			t.Fatal("no go.mod above the package")
		}
		dir = parent
	}
}

// TestCallersReadTheAnswerThroughOutside: the two-answer InRun is gone, so no caller compiles against "inside, or
// an error"; and outside this package, the kernel's reads beside it (internal/platform/peer) and the test table, no
// product file names a verdict, reads an answer's description (Describe, Description) or makes an answer from facts
// (Decide, Prove): a caller decides with Answer.Outside, and words a refusal with this package's own functions. A
// third value read as "not inside" at one call site would be a wrong outside, and a description read as "permit" (an
// empty cause) would permit on the zero answer. An answer's fields are unexported (TestAnswerCannotBeForged), so a
// field read of an answer does not compile anywhere else, and the fields of a description come only from Describe,
// which this check confines: together no product file outside the owners reads a verdict or a cause. The diagnostic
// files listed in describes may print a description and decide nothing on it.
func TestCallersReadTheAnswerThroughOutside(t *testing.T) {
	root := moduleRoot(t)
	skip := map[string]bool{".git": true, "archive": true, "node_modules": true, "testdata": true, "rust": true}
	own := map[string]bool{"internal/runscope": true, "internal/platform/peer": true, "internal/testutil/answertest": true}
	describes := map[string]bool{"internal/cli/doctormembership.go": true}
	callers := 0
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skip[d.Name()] && path != root {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		test := strings.HasSuffix(rel, "_test.go")
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return nil // a file of another build or language level; the compiler judges it
		}
		ast.Inspect(f, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.FuncDecl:
				if rel == "internal/runscope/"+filepath.Base(rel) && x.Name.Name == "InRun" {
					t.Errorf("%s declares InRun: the rule has one answer type, read through Outside", rel)
				}
			case *ast.ImportSpec:
				if x.Path.Value == `"github.com/attention-span-ai/tego/internal/runscope"` && x.Name != nil && x.Name.Name != "runscope" {
					t.Errorf("%s imports runscope as %s: this check reads the package by its own name", rel, x.Name.Name)
				}
			case *ast.SelectorExpr:
				owner := own[filepath.ToSlash(filepath.Dir(rel))]
				line := fset.Position(x.Pos()).Line
				pkg, ok := x.X.(*ast.Ident)
				if !ok || pkg.Name != "runscope" {
					return true
				}
				switch x.Sel.Name {
				case "InRun":
					t.Errorf("%s:%d calls runscope.InRun, which no longer exists", rel, line)
				case "Inside", "Unknown", "Outside", "Verdict":
					if !test && !owner {
						t.Errorf("%s:%d names runscope.%s: a caller reads an answer through Outside() alone", rel, line, x.Sel.Name)
					}
				case "Describe", "Description":
					if !test && !owner && !describes[rel] {
						t.Errorf("%s:%d calls runscope.%s: only a diagnostic file may describe an answer, and it decides nothing on it",
							rel, line, x.Sel.Name)
					}
				case "Decide", "Prove", "WithProbeTime":
					if !test && !owner {
						t.Errorf("%s:%d calls runscope.%s: only the kernel's reads (internal/platform/peer) make an answer from facts",
							rel, line, x.Sel.Name)
					}
				case "Answer":
					if !test {
						callers++
					}
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if callers < 5 {
		t.Errorf("only %d product references to runscope.Answer were found: this test no longer sees the callers", callers)
	}
}
