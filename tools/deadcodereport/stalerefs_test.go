// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"unicode"
)

// The ratchet moves a function only its own package's tests call into that package's test files
// (export_test.go; decide's oracles into rootoracle_test.go). A production comment or a spec that still names
// the moved function describes an API the binary no longer has, and when the moved function carried the only
// description of its production sibling, the sibling is left with none. These
// tests hold both: production code and the docs/p0 specs name the function the binary calls, and a mention of
// the test-only wrapper says it is the tests'.

// repoRoot is the module root, two directories up from this package.
const repoRoot = "../.."

// testOnlyFiles are the test files the ratchet moves functions into.
var testOnlyFiles = map[string]bool{"export_test.go": true, "rootoracle_test.go": true}

// staleRefAllowed are comment words that spell a test-only function's name but do not name it, by
// "<file>: <word>".
var staleRefAllowed = map[string]string{
	"internal/runtime/cgroup/events.go: Missing": `the English "Missing key" opens a sentence`,
}

// pkgDecls is one package directory's declarations: the functions its test-only files declare that no
// production file of the package declares under any name kind, and the production files themselves.
type pkgDecls struct {
	name     string
	testOnly map[string]string // name -> receiver type name, "" for a function
	declared map[string]bool   // every name a production file of the package declares
	prod     []*ast.File
	files    []string
}

func skipDir(rel string) bool {
	switch rel {
	case ".git", ".claude", "vendor", "node_modules":
		return true
	}
	return filepath.Base(rel) == "testdata"
}

// loadDecls parses every package directory under root.
func loadDecls(t *testing.T, root string) (*token.FileSet, map[string]*pkgDecls) {
	t.Helper()
	fset := token.NewFileSet()
	out := map[string]*pkgDecls{}
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		if d.IsDir() {
			if rel != "." && skipDir(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments|parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		if strings.HasSuffix(f.Name.Name, "_test") {
			return nil
		}
		dir := filepath.Dir(rel)
		p := out[dir]
		if p == nil {
			p = &pkgDecls{name: f.Name.Name, testOnly: map[string]string{}}
			out[dir] = p
		}
		base := filepath.Base(path)
		switch {
		case testOnlyFiles[base]:
			for _, decl := range f.Decls {
				if fn, ok := decl.(*ast.FuncDecl); ok {
					p.testOnly[fn.Name.Name] = recvName(fn)
				}
			}
		case !strings.HasSuffix(base, "_test.go"):
			p.prod = append(p.prod, f)
			p.files = append(p.files, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range out {
		declared := map[string]bool{}
		p.declared = declared
		for _, f := range p.prod {
			ast.Inspect(f, func(n ast.Node) bool {
				switch n := n.(type) {
				case *ast.FuncDecl:
					declared[n.Name.Name] = true
				case *ast.TypeSpec:
					declared[n.Name.Name] = true
				case *ast.ValueSpec:
					for _, id := range n.Names {
						declared[id.Name] = true
					}
				case *ast.Field:
					for _, id := range n.Names {
						declared[id.Name] = true
					}
				}
				return true
			})
		}
		for name := range p.testOnly {
			if declared[name] {
				delete(p.testOnly, name)
			}
		}
	}
	return fset, out
}

func recvName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	typ := fn.Recv.List[0].Type
	if s, ok := typ.(*ast.StarExpr); ok {
		typ = s.X
	}
	switch x := typ.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.IndexExpr:
		if id, ok := x.X.(*ast.Ident); ok {
			return id.Name
		}
	}
	return ""
}

func isWordByte(b byte) bool {
	return b == '_' || b >= '0' && b <= '9' || b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

// namesFunction reports whether name, found in line at [i, j), is the function's name rather than a word of
// prose: an identifier with an upper-case letter that is not an acronym, or one written as a call, "(name)",
// or in backticks.
func namesFunction(line, name string, i, j int) bool {
	if i > 0 && (isWordByte(line[i-1]) || line[i-1] == '.') || j < len(line) && isWordByte(line[j]) {
		return false
	}
	if strings.HasPrefix(line[j:], ".go") {
		return false
	}
	before, after := byte(0), byte(0)
	if i > 0 {
		before = line[i-1]
	}
	if j < len(line) {
		after = line[j]
	}
	if after == '(' || before == '`' && after == '`' || before == '(' && after == ')' {
		return true
	}
	upper, lower := false, false
	for _, r := range name {
		upper = upper || unicode.IsUpper(r)
		lower = lower || unicode.IsLower(r)
	}
	return upper && lower
}

// staleMentions finds name in line as namesFunction reads it.
func staleMentions(line, name string) bool {
	for off := 0; ; {
		k := strings.Index(line[off:], name)
		if k < 0 {
			return false
		}
		i := off + k
		if namesFunction(line, name, i, i+len(name)) {
			return true
		}
		off = i + len(name)
	}
}

// TestNoProductionCommentNamesATestOnlyFunction: a production file's comments never name a function that
// only its package's test files declare, unless the line says it is the tests'.
func TestNoProductionCommentNamesATestOnlyFunction(t *testing.T) {
	fset, pkgs := loadDecls(t, repoRoot)
	var bad []string
	for _, p := range pkgs {
		if len(p.testOnly) == 0 {
			continue
		}
		for k, f := range p.prod {
			for _, g := range f.Comments {
				for _, c := range g.List {
					line0 := fset.Position(c.Pos()).Line
					for n, line := range strings.Split(c.Text, "\n") {
						if strings.Contains(strings.ToLower(line), "test") {
							continue
						}
						for name := range p.testOnly {
							key := p.files[k] + ": " + name
							if _, ok := staleRefAllowed[key]; ok || !staleMentions(line, name) {
								continue
							}
							bad = append(bad, p.files[k]+":"+strconv.Itoa(line0+n)+": names "+name+", which only the package's tests declare")
						}
					}
				}
			}
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

// changesEntry matches the first line of a dated Changes entry, whose history keeps the names of its day.
var changesEntry = regexp.MustCompile(`^- \d{4}-\d{2}-\d{2}`)

// TestNoSpecNamesATestOnlyFunction: outside their dated Changes entries, the docs/p0 specs never name a
// test-only function as "<package>.<name>" (or "<receiver type>.<name>" for a method), nor an exported one as
// "`Name`", "`Name(" or "func Name(" when no production package declares that name, unless the line says it
// is the tests'.
func TestNoSpecNamesATestOnlyFunction(t *testing.T) {
	_, pkgs := loadDecls(t, repoRoot)
	declaredAnywhere := map[string]bool{}
	for _, p := range pkgs {
		for name := range p.declared {
			declaredAnywhere[name] = true
		}
	}
	needles := map[string]string{} // what a line must not hold -> the function it names
	for _, p := range pkgs {
		for name, recv := range p.testOnly {
			q := p.name + "." + name
			if recv != "" {
				q = recv + "." + name
			}
			needles[q] = q
			if recv == "" && !declaredAnywhere[name] && unicode.IsUpper(rune(name[0])) && strings.ToUpper(name) != name {
				for _, n := range []string{"`" + name + "`", "`" + name + "(", "func " + name + "("} {
					needles[n] = q
				}
			}
		}
	}
	specs, err := filepath.Glob(filepath.Join(repoRoot, "docs", "p0", "*.md"))
	if err != nil || len(specs) == 0 {
		t.Fatalf("no specs under docs/p0: %v", err)
	}
	var bad []string
	for _, spec := range specs {
		f, err := os.Open(spec)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64<<10), 4<<20)
		inChanges := false
		for n := 1; sc.Scan(); n++ {
			line := sc.Text()
			switch {
			case changesEntry.MatchString(line):
				inChanges = true
			case inChanges && strings.HasPrefix(line, "  "):
			default:
				inChanges = false
			}
			if inChanges || strings.Contains(strings.ToLower(line), "test") {
				continue
			}
			for needle, q := range needles {
				for off := 0; ; {
					k := strings.Index(line[off:], needle)
					if k < 0 {
						break
					}
					i, j := off+k, off+k+len(needle)
					if (i == 0 || !isWordByte(needle[0]) || !isWordByte(line[i-1]) && line[i-1] != '.') &&
						(j == len(line) || !isWordByte(needle[len(needle)-1]) || !isWordByte(line[j])) {
						bad = append(bad, filepath.Base(spec)+":"+strconv.Itoa(n)+": names "+q+" ("+needle+"), which only its package's tests declare")
						break
					}
					off = j
				}
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			t.Fatal(err)
		}
	}
	sort.Strings(bad)
	for _, b := range bad {
		t.Error(b)
	}
}

// TestStaleMentionReading pins what counts as naming a function.
func TestStaleMentionReading(t *testing.T) {
	for _, c := range []struct {
		line, name string
		want       bool
	}{
		{"byTime is AttributeByTime over the run's threads", "AttributeByTime", true},
		{"ErrStale is returned by OpenStopTarget when", "OpenStopTarget", true},
		{"ErrStale is returned by OpenStopTargetFor when", "OpenStopTarget", false},
		{"through readDirBounded, charged", "readDirBounded", true},
		{"through listDir, charged", "readDirBounded", false},
		{"(classifyPath): an unanswered request", "classifyPath", true},
		{"a test re-roots them (withHostSocketProbe).", "withHostSocketProbe", true},
		{"read a `readSmall` result", "readSmall", true},
		{"acquire(carriedOf) takes a slot", "acquire", true},
		{"the slot's next acquire hands out", "acquire", false},
		{"decide.Unenforced is the question", "Unenforced", false},
		{"argv is a JSON array", "JSON", false},
		{"the walk in deputy.go is the deputy's", "deputy", false},
	} {
		if got := staleMentions(c.line, c.name); got != c.want {
			t.Errorf("staleMentions(%q, %q) = %v; want %v", c.line, c.name, got, c.want)
		}
	}
}
