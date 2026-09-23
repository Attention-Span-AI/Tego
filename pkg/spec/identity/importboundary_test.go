// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// TestPackageImportsStandardLibraryOnly pins I1 and doc.go's own contract ("Imports: standard
// library only. Must not import: any other pkg/spec/* package, anything under internal/.") by
// statically parsing every .go file in this directory and checking its import list.
//
// This is not redundant with CI: .golangci.yml's depguard "spec-is-pure" rule denies pkg/spec
// importing github.com/attention-span-ai/tego/internal, but says nothing about a sibling pkg/spec/* package
// (config, backend, agent, record) — an import of one of those would compile cleanly and pass lint
// silently, contradicting doc.go's stronger "standard library only" and I1's "no cross-imports
// among identity/config/backend/other pkg/spec/*". Verified: temporarily adding an import of
// pkg/spec/backend to paths.go made this test fail with that exact import path named, while
// `go vet` and the rest of the suite stayed green; reverted before finishing.
// identity-config.md I1 (no cross-imports among the spec leaves).
func TestPackageImportsStandardLibraryOnly(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	checked := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		checked++
		for _, imp := range f.Imports {
			path, err := strconv.Unquote(imp.Path.Value)
			if err != nil {
				t.Fatalf("%s: unreadable import literal %s: %v", name, imp.Path.Value, err)
			}
			if !isStdlibImportPath(path) {
				t.Errorf("%s imports %q: pkg/spec/identity must import the standard library only (doc.go, I1)", name, path)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no .go files found in this package directory — test exercised nothing")
	}
}

// isStdlibImportPath reports whether path is a standard-library import: its first path segment (up
// to the first '/') carries no '.', the convention that separates "fmt" or "crypto/sha256" from a
// module path such as "github.com/attention-span-ai/tego/pkg/spec/backend" or "golang.org/x/...", which always
// names a domain in that first segment.
func isStdlibImportPath(path string) bool {
	first := path
	if i := strings.IndexByte(path, '/'); i >= 0 {
		first = path[:i]
	}
	return !strings.Contains(first, ".")
}
