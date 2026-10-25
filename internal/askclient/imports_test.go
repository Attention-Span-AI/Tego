// SPDX-License-Identifier: Apache-2.0

package askclient_test

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const mod = "github.com/attention-span-ai/tego/"

// goListDeps is every package pkg links under tags, from `go list -deps` at the module root.
func goListDeps(t *testing.T, tags, pkg string) []string {
	t.Helper()
	return goList(t, tags, pkg, "{{.ImportPath}}")
}

// goList runs `go list -deps -f format` for pkg under tags at the module root and returns its words.
func goList(t *testing.T, tags, pkg, format string) []string {
	t.Helper()
	cmd := exec.Command("go", "list", "-tags="+tags, "-deps", "-f", format, pkg) // go test puts its own go first on PATH
	cmd.Dir = filepath.Join("..", "..")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list %s: %v: %s", pkg, err, stderr.String())
	}
	return strings.Fields(string(out))
}

// TestEngineClientsImportNoRuntime: the engine's clients of a run — internal/askclient, pkg/spec/askproto and
// internal/runlock — link no internal/runtime package, no decision core, no BPF code and no BPF library, in the plain
// and the shipped (tegobpf) build, since tego-control links them (ADR 0100 (7)). pkg/spec/askproto links the
// standard library alone (Layer 0).
func TestEngineClientsImportNoRuntime(t *testing.T) {
	banned := []string{mod + "internal/runtime", mod + "internal/policy", mod + "internal/bpf", "github.com/cilium/ebpf"}
	for _, tags := range []string{"", "tegobpf"} {
		for _, pkg := range []string{"internal/askclient", "pkg/spec/askproto", "internal/runlock"} {
			deps := goListDeps(t, tags, "./"+pkg)
			if len(deps) == 0 || deps[len(deps)-1] != mod+pkg {
				t.Fatalf("tags %q: go list -deps %s does not end with it: %v", tags, pkg, deps)
			}
			for _, d := range deps {
				for _, b := range banned {
					if d == b || strings.HasPrefix(d, b+"/") {
						t.Errorf("tags %q: %s links %s", tags, pkg, d)
					}
				}
			}
			if pkg == "pkg/spec/askproto" {
				for _, d := range outsideStd(t, tags, "./"+pkg) {
					if d != mod+pkg {
						t.Errorf("tags %q: pkg/spec/askproto links %s, outside the standard library", tags, d)
					}
				}
			}
		}
	}
}

// outsideStd is every package pkg links under tags that go list does not count as the standard library (.Standard).
func outsideStd(t *testing.T, tags, pkg string) []string {
	t.Helper()
	return goList(t, tags, pkg, "{{if not .Standard}}{{.ImportPath}}{{end}}")
}

// TestOutsideStd: the standard-library check takes membership from go list, not from the path's spelling. crypto/rand
// links crypto/internal/entropy/v1.0.0 and the vendored golang.org/x/crypto, both standard though dotted, so a
// Layer-0 package may draw its own nonce or use net; a module package and its module dependencies are outside.
func TestOutsideStd(t *testing.T) {
	for _, pkg := range []string{"crypto/rand", "net"} {
		if got := outsideStd(t, "", pkg); len(got) != 0 {
			t.Errorf("%s: outsideStd = %v, want none", pkg, got)
		}
	}
	got := outsideStd(t, "", "./internal/askclient")
	if !slices.Contains(got, mod+"internal/askclient") || !slices.Contains(got, "golang.org/x/sys/unix") {
		t.Errorf("internal/askclient: outsideStd = %v, want it to hold the package and golang.org/x/sys/unix", got)
	}
	if slices.Contains(got, "net") {
		t.Errorf("internal/askclient: outsideStd holds net: %v", got)
	}
}

// TestLedgerTargetSingleSource: LedgerTarget is the one function that gives a held request's target its ledger
// form. The runtime's ask, answer and first_write refusal lines call it (internal/runtime/ask_lifecycle.go), and
// outside internal/ledger no other non-test file of the module calls ledger.RedactTarget, the projection it applies,
// so tego-control's cards, when they render a target, can only reach that form through it.
func TestLedgerTargetSingleSource(t *testing.T) {
	root := filepath.Join("..", "..")
	calls := map[string]int{} // file -> calls of askclient.LedgerTarget
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel == ".git" || rel == ".claude" || strings.HasPrefix(d.Name(), ".") && rel != "." || d.Name() == "testdata" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.SkipObjectResolution)
		if perr != nil {
			return perr
		}
		names := map[string]string{} // local name -> import path
		for _, im := range f.Imports {
			p, _ := strconv.Unquote(im.Path.Value)
			name := filepath.Base(p)
			if im.Name != nil {
				name = im.Name.Name
			}
			names[name] = p
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			x, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			switch {
			case names[x.Name] == mod+"internal/ledger" && sel.Sel.Name == "RedactTarget" && filepath.ToSlash(rel) != "internal/askclient/target.go":
				t.Errorf("%s calls ledger.RedactTarget: a held request's ledger form is askclient.LedgerTarget's alone", rel)
			case names[x.Name] == mod+"internal/askclient" && sel.Sel.Name == "LedgerTarget":
				calls[filepath.ToSlash(rel)]++
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// The ask line, the answer line and the first_write refusal.
	if n := calls["internal/runtime/ask_lifecycle.go"]; n != 3 {
		t.Errorf("internal/runtime/ask_lifecycle.go calls askclient.LedgerTarget %d times, want 3 (ask, answer, first_write): %v", n, calls)
	}
}
