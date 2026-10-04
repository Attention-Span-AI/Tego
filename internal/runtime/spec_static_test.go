// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// launchFamilyFiles parses the non-test Go files of the runtime, launch and cgroup packages: the three
// directories runtime-launch.md specifies. Sub-packages (supervisor, enforce, derive, ...) have their own specs.
func launchFamilyFiles(t *testing.T) map[string]*ast.File {
	t.Helper()
	out := map[string]*ast.File{}
	fset := token.NewFileSet()
	for _, dir := range []string{".", "launch", "cgroup"} {
		paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range paths {
			if strings.HasSuffix(p, "_test.go") {
				continue
			}
			f, err := parser.ParseFile(fset, p, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", p, err)
			}
			out[p] = f
		}
	}
	if len(out) < 10 {
		t.Fatalf("parsed only %d files; the package layout moved", len(out))
	}
	return out
}

// TestRunInstallsNoRecover is runtime-launch.md R14: none of this package family's code calls the builtin
// recover(), so a worker panic propagates and crashes the process; the sweep is the recovery path.
func TestRunInstallsNoRecover(t *testing.T) {
	for p, f := range launchFamilyFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "recover" && id.Obj == nil {
					t.Errorf("%s: calls recover(); R14 says a worker panic is not a runtime condition", p)
				}
			}
			return true
		})
	}
}

// TestRunNeverSelfElevates is runtime-launch.md R3: the launcher never re-execs itself through sudo (or another
// privilege broker) and never reads a privileged_binary; a ceiling above the current credentials is a doctor
// gap. No call in the family passes such a program to os/exec or exec(2), and no string literal names one.
func TestRunNeverSelfElevates(t *testing.T) {
	brokers := map[string]bool{"sudo": true, "pkexec": true, "doas": true, "su": true, "privileged_binary": true}
	for p, f := range launchFamilyFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(lit.Value)
			if err != nil {
				return true
			}
			if brokers[s] || strings.HasSuffix(s, "/sudo") {
				t.Errorf("%s: string literal %q names a privilege broker; R3 says Run never self-elevates", p, s)
			}
			return true
		})
	}
}

// TestRunProducesNeitherTierUnavailableNor213 is runtime-launch.md I10 (invariant 10), the static half: no code in the
// family names exit 213 or the tier-unavailable reason; those belong to cli.run's pre-Run steps. (The other half,
// that this package's own pre-run_start failures are exit 125, is asserted by TestRunUnwindsAfterAFailedPrepare.)
func TestRunProducesNeitherTierUnavailableNor213(t *testing.T) {
	for p, f := range launchFamilyFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.BasicLit)
			if !ok {
				return true
			}
			if lit.Kind == token.INT && lit.Value == "213" {
				t.Errorf("%s: integer literal 213; exit 213 is cli.run's", p)
			}
			if lit.Kind == token.STRING && strings.Contains(lit.Value, "tier-unavailable") {
				t.Errorf("%s: names tier-unavailable; that exit is cli.run's", p)
			}
			return true
		})
	}
}

// TestNothingWritesCgroupProcs is runtime-launch.md I3 (invariant 3), the static half: a child is placed by
// clone3(CLONE_INTO_CGROUP) and never by a later cgroup.procs write, so no code in the family opens or writes a
// cgroup.procs file (it is read, and access(2)-checked for delegation). The dynamic half is
// TestIntegrationLifecycle's clone3 into the run's cgroup.
func TestNothingWritesCgroupProcs(t *testing.T) {
	writers := map[string]bool{"WriteFile": true, "OpenFile": true, "Create": true, "Write": true, "WriteString": true, "Openat": true, "Open": true}
	mentionsProcs := func(e ast.Expr) bool {
		found := false
		ast.Inspect(e, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.Ident:
				if v.Name == "fileProcs" {
					found = true
				}
			case *ast.BasicLit:
				if v.Kind == token.STRING && strings.Contains(v.Value, "cgroup.procs") {
					found = true
				}
			}
			return true
		})
		return found
	}
	for p, f := range launchFamilyFiles(t) {
		ast.Inspect(f, func(n ast.Node) bool {
			c, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := c.Fun.(*ast.SelectorExpr)
			if !ok || !writers[sel.Sel.Name] {
				return true
			}
			for _, a := range c.Args {
				if mentionsProcs(a) {
					t.Errorf("%s: %s opens or writes cgroup.procs; I3 places children with CLONE_INTO_CGROUP only", p, sel.Sel.Name)
				}
			}
			return true
		})
	}
}
