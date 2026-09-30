// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writingOpensWithoutAppend reports, for one Go source, each call that names events.jsonl (EventsFile or the
// literal) and writes to it without O_APPEND: an open whose flags carry O_WRONLY or O_RDWR (or os.O_*) but no
// O_APPEND, and any os.Create or os.WriteFile of it, which cannot append at all. The flags are read as written,
// so a flag hidden behind a variable is reported too, as a writing open the check cannot vouch for.
func writingOpensWithoutAppend(t *testing.T, name string, src any) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, name, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var namesEvents func(e ast.Expr) bool
	namesEvents = func(e ast.Expr) bool {
		switch v := e.(type) {
		case *ast.Ident:
			return v.Name == "EventsFile"
		case *ast.BasicLit:
			return strings.Contains(v.Value, EventsFile)
		case *ast.CallExpr: // filepath.Join(dir, EventsFile)
			if sel, ok := v.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Join" {
				for _, a := range v.Args {
					if namesEvents(a) {
						return true
					}
				}
			}
		}
		return false
	}
	flagNames := func(e ast.Expr) (names []string, opaque bool) {
		ast.Inspect(e, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.SelectorExpr:
				names = append(names, v.Sel.Name)
				return false
			case *ast.Ident:
				names = append(names, v.Name)
			}
			return true
		})
		for _, n := range names {
			if !strings.HasPrefix(n, "O_") && n != "syscall" && n != "os" && n != "unix" {
				opaque = true
			}
		}
		return names, opaque
	}
	var bad []string
	ast.Inspect(f, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		at := -1
		for i, a := range call.Args {
			if namesEvents(a) {
				at = i
				break
			}
		}
		if at < 0 {
			return true
		}
		fn := ""
		switch c := call.Fun.(type) {
		case *ast.SelectorExpr:
			fn = c.Sel.Name
		case *ast.Ident:
			fn = c.Name
		}
		pos := fset.Position(call.Pos()).String()
		switch fn {
		case "Create", "WriteFile":
			bad = append(bad, pos+": "+fn+" of events.jsonl")
			return true
		case "OpenFile", "Openat", "openFileAt", "Open", "openRegular":
		default:
			return true
		}
		if at+1 >= len(call.Args) {
			return true // no flags: os.Open, openRegular read only
		}
		names, opaque := flagNames(call.Args[at+1])
		has := func(s string) bool {
			for _, n := range names {
				if n == s {
					return true
				}
			}
			return false
		}
		writing := has("O_WRONLY") || has("O_RDWR") || opaque
		if writing && !has("O_APPEND") {
			bad = append(bad, pos+": "+fn+" of events.jsonl opened for writing without O_APPEND")
		}
		return true
	})
	return bad
}

// TestEventsFileOpensAppend is record-ledger.md I1's check: every writing open of events.jsonl in this package
// carries O_APPEND, so no write lands anywhere but the end of the file. The truncations resume and cutTornLine
// make are the rule's two named exceptions; this is the open side.
func TestEventsFileOpensAppend(t *testing.T) {
	// The check itself first: it finds a writing open without O_APPEND, and one that cannot append at all.
	const bad = `package ledger
func f(dirfd int, dir string) {
	openFileAt(dirfd, dir, EventsFile, syscall.O_WRONLY, true)
	os.OpenFile(filepath.Join(dir, EventsFile), os.O_RDWR|os.O_CREATE, 0o600)
	os.WriteFile(filepath.Join(dir, "events.jsonl"), nil, 0o600)
	openFileAt(dirfd, dir, EventsFile, syscall.O_WRONLY|syscall.O_APPEND, true)
	openFileAt(dirfd, dir, EventsFile, syscall.O_RDONLY, false)
}
`
	if got := writingOpensWithoutAppend(t, "bad.go", bad); len(got) != 3 {
		t.Fatalf("the check found %d of the 3 non-append writes in its own fixture: %q", len(got), got)
	}

	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, b := range writingOpensWithoutAppend(t, name, src) {
			t.Errorf("I1: %s", b)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no package sources checked")
	}
}
