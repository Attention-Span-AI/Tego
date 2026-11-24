// SPDX-License-Identifier: Apache-2.0

// Command rootskips finds the tests that may skip for want of root, read from the Go syntax tree, so a new one that no
// skip list names is found without running a test, as root or not.
//
// Why it exists: scripts/skipgate.sh judges the skips of a run, so a needs-root test that nobody listed in
// test/integration-skips.txt (and, as scripts/check-skiplists.sh asks of a root skip, in test/vm/root-must-pass.txt
// or test/vm/root-skips.txt) was found only when the whole unprivileged integration step ran, about half an hour
// after a merge; it happened twice (TestRootLiveBlockInPlane, TestIntegrationDenyReadSnapshotAtRootTiers). This
// command is the half that needs no run: it names the tests, scripts/check-skiplists.sh holds them to the lists
// with skipgate.sh's own rule.
//
// A pass of this tool is NOT "no unlisted needs-root skip exists". It is a sound over-approximation for the shapes
// named below and blind to the ones named after them: where it cannot tell, it reports the test as a candidate.
//
// Two levels. A top-level test is kind "test" when one of its own statements (not inside a closure or a loop; an if
// chain, a switch and a bare block are read through) skips for a process that is not root:
//
//   - `if <not root> { ... t.Skip*(...) ... }`, with or without an else branch, where <not root> is `os.Geteuid() != 0`
//     (or Getuid, a `> 0`, a negated `== 0`, or an || chain with such a term: an && chain skips only when every term
//     holds), or the same skip in the else branch of an `== 0` test;
//   - a switch clause with such a case expression (`case os.Geteuid() != 0:`), or a `switch os.Geteuid()` clause other
//     than `case 0`, or the default clause beside a root case, whose body skips;
//   - a skip whose message literal says the test needs root or a capability (`needs root`, `needs cap_bpf`,
//     `; run as root`, `root only`, `root tier`) under a condition that is not an `== 0` test;
//   - a call of, or a reference to, a function that does one of these as its own statement or calls such a function (to
//     a fixed point): a plain function of the package (`requireRoot(t)`, `c := newCrossOwner(t, "x")`), a method
//     (`env{}.requireRoot(t)`; any receiver, matched by the method's name alone in the whole tree), or a function of
//     another package of this module that is imported by name, by alias or with a dot (`zzhelp.RequireRoot(t)`),
//     whether the helper is written in a test file or a non-test file.
//
// Every other test whose body, a closure of it included, holds a skip that is or may be for want of root is kind
// "sub": its skips are not at its own statement level (inside a t.Run closure, a closure kept in a variable and passed
// to t.Run, a nested condition, a loop), or the root test is a value this tool follows only loosely. A "sub" test needs
// a list entry for the test or for one of its subtests. A skip is read as possibly for want of root when it is
//
//   - called, or reached through a reference such as `skip := t.Skip`, inside an if, a switch clause or a for whose
//     controlling expression mentions an id call (Geteuid or Getuid), a local variable assigned from one, a package
//     variable initialised from one, or a call of a function that returns a value computed from one (found to a fixed
//     point, in this module); a skip that sits only in the then branch of an `== 0` test (also with && terms) is
//     the root run's skip and is not read;
//   - a call of a function that contains any skip, with such a tainted expression among its arguments or under such a
//     control;
//   - a reference to, or a call of, a helper of the first level, anywhere in the body (conditional, in a closure, or
//     in a loop): the helper skips for a process that is not root whenever it runs, so the test may skip.
//
// Not recognised, so a pass says nothing about them:
//
//   - a skip decided at run time by a probe that is not an id call (mkdir refused, `fanotify_init` or a capability
//     probe refused, a file mode, /proc/self/status read for CapEff): the run's own skip gate holds those;
//   - a root flag kept in a struct field, a map, a channel or an interface value, and a function stored in one of
//     those and called later: only locals, package variables and the functions found by name are followed;
//   - a helper in a package outside this module, or one reached by reflection, a go:generate step or an exec of go test;
//   - an id read through anything but a method or function named Geteuid or Getuid (a reading of /proc, os/user,
//     CapEff, `id -u` through exec);
//   - tests that go test runs but this tool does not name: Fuzz, Benchmark and Example functions, TestMain, and a
//     TestX whose name begins with a lower-case letter after Test (go test does not run it either);
//   - a skip message that says root without one of the phrases above, under a condition that mentions no id;
//   - a method call is matched by its name only, so two methods of one name are one helper (over-reporting, never
//     under-reporting, but a method call through a function value is not a call this tool sees).
//
// Over-reporting: a candidate whose skip is for another reason (a tool is missing, a kernel feature is absent) under
// a condition that also mentions an id is named. It is cleared by a list entry that is true, or by removing the id
// from the condition; this tool never lists a test on its own.
//
// The files are the ones git lists, tracked or untracked but not ignored, that the go tool builds in the named
// build: go/build's own matching of the file name and the //go:build line (release tags go1.N included), for
// linux/amd64 with the given tags. Non-test files are read too, for the helpers they hold.
//
// Usage: go run ./tools/rootskips [-tags a,b] [-cgo] [root]   (root defaults to the working directory)
// Output, one line per test, tab-separated: <package directory> <test> <kind: test or sub> <file:line>
// Exit: 0 (also when nothing is found); 2 on a read or parse error.
//
// Imports: standard library only.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Found is one root-gated test.
type Found struct {
	Dir  string // package directory, relative to the root
	Test string
	Kind string // "test": the test's own statements skip; "sub": a skip elsewhere in its body may
	Pos  string // file:line of the gate
}

func main() {
	tags := flag.String("tags", "", "comma-separated build tags")
	cgo := flag.Bool("cgo", false, "cgo enabled")
	asRoot := flag.Bool("asroot", false, "list the tests that skip when the process IS root (the root run's own skips) instead")
	flag.Parse()
	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}
	var tagList []string
	for _, t := range strings.Split(*tags, ",") {
		if t != "" {
			tagList = append(tagList, t)
		}
	}
	scan := Scan
	if *asRoot {
		scan = ScanAsRoot
	}
	found, err := scan(root, tagList, *cgo)
	if err != nil {
		fmt.Fprintln(os.Stderr, "rootskips:", err)
		os.Exit(2)
	}
	for _, f := range found {
		fmt.Printf("%s\t%s\t%s\t%s\n", f.Dir, f.Test, f.Kind, f.Pos)
	}
}

// listGo lists the checkout's Go files, relative to root with forward slashes.
func listGo(root string) ([]string, error) {
	cmd := exec.Command("git", "-C", root, "ls-files", "-z", "-co", "--exclude-standard", "--", "*.go")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git ls-files: %v: %s", err, strings.TrimSpace(stderr.String()))
	}
	var files []string
	for _, f := range strings.Split(string(out), "\x00") {
		if f != "" {
			files = append(files, filepath.ToSlash(f))
		}
	}
	sort.Strings(files)
	return files, nil
}

// unbuilt is whether the go tool leaves a file out of every package: a directory or file whose name begins with "_"
// or ".", and anything under testdata (go help packages).
func unbuilt(f string) bool {
	for _, e := range strings.Split(f, "/") {
		if strings.HasPrefix(e, "_") || strings.HasPrefix(e, ".") || e == "testdata" {
			return true
		}
	}
	return false
}

// moduleName is the module path of root's go.mod, or "" when there is none (then imports are not followed).
func moduleName(root string) string {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(b), "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "module"); ok && rest != "" && (rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), `"`)
		}
	}
	return ""
}

// srcFile is one parsed file of the build.
type srcFile struct {
	ast     *ast.File
	test    bool              // a _test.go file
	rawImp  []rawImport       // the module imports, before package names are known
	imports map[string]string // local name -> package directory of this module
	dots    []string          // directories imported with a dot
	ext     map[string]bool   // names of packages from outside the module
}

type rawImport struct{ name, dir string }

// fn is one function or method declaration.
type fn struct {
	decl    *ast.FuncDecl
	file    *srcFile
	gid     string // the package the declaration belongs to
	dir     string
	key     string // gid|Name for a function, *|Name for a method
	isTest  bool   // TestX(t *testing.T) of a test file
	results bool

	refs       []string // keys of every identifier and selector in the body
	funcRefs   []string // the refs that name a function or variable of a package, not a method by its name
	skipDirect bool     // a Skip, Skipf or SkipNow selector in the body
	idDirect   bool     // a Geteuid or Getuid selector in the body
}

// world is the build's parsed files and the facts read from them.
type world struct {
	fset   *token.FileSet
	module string
	dirGID map[string]string // package directory -> gid of its non-external package
	gidPkg map[string]string // gid -> package name
	gidDir map[string]string
	funcs  []*fn
	files  []*srcFile
	gidOf  map[*srcFile]string

	scalar  map[string]bool         // keys of functions whose results are all scalars
	takesT  map[string]bool         // keys of methods and of functions with a *testing.T-like parameter
	touch   map[string]bool         // keys of functions returning, and variables holding, a value read from an id
	skipper map[string]bool         // keys of functions that contain a skip, or call one that does
	loose   map[string]bool         // helpers of the loose level
	precise map[string]bool         // helpers of the precise level
	ignored map[string]map[int]bool // file -> lines of a "rootskips:ignore" comment
}

// Scan reads every Go file of root that the build selects and returns its root-gated tests, sorted.
func Scan(root string, tags []string, cgo bool) ([]Found, error) {
	w, err := load(root, tags, cgo)
	if err != nil {
		return nil, err
	}
	w.fixTouch()
	w.fixSkipper()
	w.fixPrecise()
	w.fixLoose()
	return w.classify(), nil
}

// load parses every Go file of root that the build selects and collects its functions.
func load(root string, tags []string, cgo bool) (*world, error) {
	files, err := listGo(root)
	if err != nil {
		return nil, err
	}
	hasTest := false
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			hasTest = true
			break
		}
	}
	if !hasTest {
		return nil, fmt.Errorf("git listed no test file under %s; nothing was read", root)
	}
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = "linux", "amd64", cgo
	// Release tags are the toolchain's own (go1.1 ... go1.N): a file that says //go:build go1.21 is built.
	ctx.BuildTags, ctx.ToolTags, ctx.ReleaseTags = tags, nil, build.Default.ReleaseTags
	ctx.UseAllFiles = false
	w := &world{
		fset:    token.NewFileSet(),
		module:  moduleName(root),
		dirGID:  map[string]string{},
		gidPkg:  map[string]string{},
		gidDir:  map[string]string{},
		gidOf:   map[*srcFile]string{},
		scalar:  map[string]bool{},
		takesT:  map[string]bool{},
		touch:   map[string]bool{},
		skipper: map[string]bool{},
		loose:   map[string]bool{},
		precise: map[string]bool{},
		ignored: map[string]map[int]bool{},
	}
	for _, f := range files {
		if unbuilt(f) {
			continue
		}
		dir := filepath.ToSlash(filepath.Dir(f))
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(f)))
		if err != nil {
			if os.IsNotExist(err) {
				continue // listed but deleted in the working tree
			}
			return nil, err
		}
		ok, err := ctx.MatchFile(filepath.Join(root, filepath.FromSlash(dir)), filepath.Base(f))
		if err != nil {
			return nil, fmt.Errorf("%s: %v", f, err)
		}
		if !ok {
			continue
		}
		file, err := parser.ParseFile(w.fset, f, src, parser.SkipObjectResolution|parser.ParseComments)
		if err != nil {
			return nil, err
		}
		if err := w.readDirectives(file); err != nil {
			return nil, err
		}
		sf := &srcFile{ast: file, test: strings.HasSuffix(f, "_test.go")}
		gid := dir + "|" + file.Name.Name
		w.gidOf[sf] = gid
		w.gidPkg[gid] = file.Name.Name
		w.gidDir[gid] = dir
		if !strings.HasSuffix(file.Name.Name, "_test") {
			w.dirGID[dir] = gid
		}
		w.readImports(sf)
		w.files = append(w.files, sf)
	}
	w.resolveImports()
	w.collect()
	return w, nil
}

// directive is the comment that clears one skip the tool cannot tell from a needs-root skip: it names why.
const directive = "rootskips:ignore"

// readDirectives records the lines of the file's `// rootskips:ignore <reason>` comments. A directive with no reason
// is an error: the tool never takes a silent exemption.
func (w *world) readDirectives(file *ast.File) error {
	for _, cg := range file.Comments {
		for _, c := range cg.List {
			text, ok := strings.CutPrefix(c.Text, "//")
			if !ok {
				continue
			}
			rest, ok := strings.CutPrefix(strings.TrimSpace(text), directive)
			if !ok {
				continue
			}
			pos := w.fset.Position(c.Pos())
			if strings.TrimSpace(rest) == "" {
				return fmt.Errorf("%s:%d: %s needs a reason after it", pos.Filename, pos.Line, directive)
			}
			if w.ignored[pos.Filename] == nil {
				w.ignored[pos.Filename] = map[int]bool{}
			}
			w.ignored[pos.Filename][pos.Line] = true
		}
	}
	return nil
}

// cleared is whether a directive sits on a line of [from, to] or on the line before from.
func (w *world) cleared(from, to token.Pos) bool {
	a, b := w.fset.Position(from), w.fset.Position(to)
	lines := w.ignored[a.Filename]
	for l := a.Line - 1; l <= b.Line; l++ {
		if lines[l] {
			return true
		}
	}
	return false
}

// readImports keeps the imports of the module's own packages.
func (w *world) readImports(sf *srcFile) {
	sf.ext = map[string]bool{}
	for _, imp := range sf.ast.Imports {
		p := strings.Trim(imp.Path.Value, "\"`")
		name := ""
		if imp.Name != nil {
			name = imp.Name.Name
		}
		if name == "_" {
			continue
		}
		var dir string
		switch {
		case w.module != "" && p == w.module:
			dir = "."
		case w.module != "" && strings.HasPrefix(p, w.module+"/"):
			dir = strings.TrimPrefix(p, w.module+"/")
		default:
			// A package of another module (the standard library included): its members are no helper of ours. The name
			// the file calls it by is the alias or, as a guess, the last element (before a /vN suffix).
			if name == "" {
				name = path.Base(p)
				if len(name) > 1 && name[0] == 'v' && strings.Trim(name[1:], "0123456789") == "" {
					name = path.Base(path.Dir(p))
				}
			}
			sf.ext[name] = true
			continue
		}
		sf.rawImp = append(sf.rawImp, rawImport{name, dir})
	}
}

// resolveImports names each import as the file refers to it: its alias, or the imported package's own name.
func (w *world) resolveImports() {
	for _, sf := range w.files {
		sf.imports = map[string]string{}
		for _, ri := range sf.rawImp {
			switch ri.name {
			case ".":
				sf.dots = append(sf.dots, ri.dir)
			case "":
				name := path.Base(ri.dir)
				if gid, ok := w.dirGID[ri.dir]; ok {
					name = w.gidPkg[gid]
				}
				sf.imports[name] = ri.dir
			default:
				sf.imports[ri.name] = ri.dir
			}
		}
	}
}

// collect lists the functions with the facts of their own bodies.
func (w *world) collect() {
	for _, sf := range w.files {
		gid := w.gidOf[sf]
		for _, d := range sf.ast.Decls {
			for _, fd := range funcDecls(d) {
				f := &fn{decl: fd, file: sf, gid: gid, dir: w.gidDir[gid], results: scalarResults(fd)}
				if fd.Recv != nil {
					f.key = "*|" + fd.Name.Name
				} else {
					f.key = gid + "|" + fd.Name.Name
					f.isTest = sf.test && isTest(fd.Name.Name, fd)
				}
				if f.results {
					w.scalar[f.key] = true
				}
				if fd.Recv != nil || takesT(fd) {
					w.takesT[f.key] = true
				}
				w.scanBody(f)
				w.funcs = append(w.funcs, f)
			}
		}
	}
}

// funcDecls is the functions a top-level declaration holds: a func, or each `var name = func(...) {...}`.
func funcDecls(d ast.Decl) []*ast.FuncDecl {
	switch d := d.(type) {
	case *ast.FuncDecl:
		if d.Body != nil {
			return []*ast.FuncDecl{d}
		}
	case *ast.GenDecl:
		var out []*ast.FuncDecl
		if d.Tok != token.VAR {
			return nil
		}
		for _, sp := range d.Specs {
			vs := sp.(*ast.ValueSpec)
			if len(vs.Names) != len(vs.Values) {
				continue
			}
			for i, v := range vs.Values {
				if lit, ok := v.(*ast.FuncLit); ok {
					out = append(out, &ast.FuncDecl{Name: vs.Names[i], Type: lit.Type, Body: lit.Body})
				}
			}
		}
		return out
	}
	return nil
}

// identKeys are the keys an identifier may name in a file of the package gid: a member of the package, or of a
// package imported with a dot.
func (w *world) identKeys(sf *srcFile, gid, name string) []string {
	keys := []string{gid + "|" + name}
	for _, d := range sf.dots {
		if g, ok := w.dirGID[d]; ok {
			keys = append(keys, g+"|"+name)
		}
	}
	return keys
}

// selKeys is the key a selector names: a member of an imported package, or a method (or field) by its name.
func (w *world) selKeys(sf *srcFile, sel *ast.SelectorExpr) []string {
	if id, ok := sel.X.(*ast.Ident); ok {
		if sf.ext[id.Name] {
			return nil
		}
		if dir, ok := sf.imports[id.Name]; ok {
			if g, ok := w.dirGID[dir]; ok {
				return []string{g + "|" + sel.Sel.Name}
			}
			return nil
		}
	}
	return []string{"*|" + sel.Sel.Name}
}

// takesT is whether fd has a parameter of type *testing.T, *testing.B, *testing.F or testing.TB: only such a function
// can skip the test that called it.
func takesT(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil {
		return false
	}
	for _, p := range fd.Type.Params.List {
		t := p.Type
		if star, ok := t.(*ast.StarExpr); ok {
			t = star.X
		}
		switch t := t.(type) {
		case *ast.SelectorExpr:
			if t.Sel.Name == "T" || t.Sel.Name == "B" || t.Sel.Name == "F" || t.Sel.Name == "TB" {
				return true
			}
		case *ast.Ident:
			if t.Name == "TB" {
				return true
			}
		}
	}
	return false
}

// isTestName is whether the function is named like a test, whatever its parameters: not a helper.
func (f *fn) addRefs(keys []string) {
	for _, k := range keys {
		f.refs = append(f.refs, k)
		if !strings.HasPrefix(k, "*|") {
			f.funcRefs = append(f.funcRefs, k)
		}
	}
}

func isTestName(f *fn) bool {
	return f.decl.Recv == nil && f.file.test && strings.HasPrefix(f.decl.Name.Name, "Test")
}

func isSkipName(n string) bool { return n == "Skip" || n == "Skipf" || n == "SkipNow" }

func isIDName(n string) bool { return n == "Geteuid" || n == "Getuid" }

// scanBody reads the references, skip selectors and id selectors of fn's whole body, closures included.
func (w *world) scanBody(f *fn) { w.refsOfX(f, f.decl.Body) }

// refsOfX adds the references inside a node: every identifier and selector, the selector names as members.
func (w *world) refsOfX(f *fn, x ast.Node) {
	ast.Inspect(x, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.SelectorExpr:
			if isSkipName(n.Sel.Name) {
				f.skipDirect = true
			}
			if isIDName(n.Sel.Name) {
				f.idDirect = true
			}
			f.addRefs(w.selKeys(f.file, n))
			w.refsOfX(f, n.X)
			return false
		case *ast.Ident:
			f.addRefs(w.identKeys(f.file, f.gid, n.Name))
		}
		return true
	})
}

// scalarResults is whether every result of fd is a predeclared scalar type (bool or an integer): a
// value such as `isRoot() bool` or `uid() int` can carry an id into a condition, a struct that merely was built
// beside a Geteuid call does not.
func scalarResults(fd *ast.FuncDecl) bool {
	if fd.Type.Results == nil || len(fd.Type.Results.List) == 0 {
		return false
	}
	for _, r := range fd.Type.Results.List {
		id, ok := r.Type.(*ast.Ident)
		if !ok || !scalarTypes[id.Name] {
			return false
		}
	}
	return true
}

var scalarTypes = map[string]bool{
	"bool": true, "int": true, "int8": true, "int16": true, "int32": true, "int64": true, "uint": true, "uint8": true,
	"uint16": true, "uint32": true, "uint64": true, "uintptr": true,
}

// fixTouch finds the functions with a result that is read from an id, and the package variables initialised from one.
func (w *world) fixTouch() {
	for changed := true; changed; {
		changed = false
		for _, f := range w.funcs {
			if f.results && !w.touch[f.key] && (f.idDirect || w.returnsTainted(f)) {
				w.touch[f.key] = true
				changed = true
			}
		}
		for _, sf := range w.files {
			gid := w.gidOf[sf]
			for _, d := range sf.ast.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || (gd.Tok != token.VAR && gd.Tok != token.CONST) {
					continue
				}
				for _, sp := range gd.Specs {
					vs := sp.(*ast.ValueSpec)
					if !w.exprTainted(sf, gid, vs, nil) {
						continue
					}
					for _, nm := range vs.Names {
						k := gid + "|" + nm.Name
						if !w.touch[k] {
							w.touch[k] = true
							changed = true
						}
					}
				}
			}
		}
	}
}

// returnsTainted is whether a return statement of fn (outside its closures) returns a value read from an id.
func (w *world) returnsTainted(f *fn) bool {
	found := false
	ast.Inspect(f.decl.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.ReturnStmt:
			for _, r := range n.Results {
				if w.exprTainted(f.file, f.gid, r, nil) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func anyKey(keys []string, set map[string]bool) bool {
	for _, k := range keys {
		if set[k] {
			return true
		}
	}
	return false
}

// fixSkipper finds the functions that contain a skip, or call a function that does.
func (w *world) fixSkipper() {
	for changed := true; changed; {
		changed = false
		for _, f := range w.funcs {
			if !w.skipper[f.key] && (f.skipDirect || anyKey(f.funcRefs, w.skipper)) {
				w.skipper[f.key] = true
				changed = true
			}
		}
	}
}

// taintEnv is what one function body says of its local names: those assigned from a value read from an id, and of
// those the ones that hold "is root" and "is not root".
type taintEnv struct {
	declared map[string]bool // every name the body declares: a parameter, :=, var, range variable, closure parameter
	tainted  map[string]bool
	rootV    map[string]bool
	nonRootV map[string]bool
}

func (e *taintEnv) has(name string) bool { return e != nil && e.tainted[name] }

// shadows is whether the body declares name itself, so that a package member of that name is not what it means.
func (e *taintEnv) shadows(name string) bool { return e != nil && e.declared[name] }

// exprTainted is whether the node's value is read from an id: it mentions an id selector, a tainted local, a package
// variable or a function whose result is read from an id. An argument of a call counts only through a conversion
// (uint32(os.Getuid())) or a callee whose results are scalars (isPrivileged(os.Geteuid()) bool): cgroup.Detect(euid)
// returns a filesystem and an error, and the error is no root flag.
func (w *world) exprTainted(sf *srcFile, gid string, n ast.Node, local *taintEnv) bool {
	found := false
	ast.Inspect(n, func(m ast.Node) bool {
		if found {
			return false
		}
		switch m := m.(type) {
		case *ast.SelectorExpr:
			if isIDName(m.Sel.Name) || anyKey(w.selKeys(sf, m), w.touch) {
				found = true
				return false
			}
			if w.exprTainted(sf, gid, m.X, local) {
				found = true
			}
			return false
		case *ast.Ident:
			if local.has(m.Name) || !local.shadows(m.Name) && anyKey(w.identKeys(sf, gid, m.Name), w.touch) {
				found = true
			}
		case *ast.CompositeLit:
			return false // a struct or slice holding an id is no id
		case *ast.CallExpr:
			var keys []string
			switch c := m.Fun.(type) {
			case *ast.Ident:
				if scalarTypes[c.Name] {
					return true // a conversion: its operand is its value
				}
				if !local.shadows(c.Name) {
					keys = w.identKeys(sf, gid, c.Name)
				}
			case *ast.SelectorExpr:
				keys = w.selKeys(sf, c)
			}
			if anyKey(keys, w.scalar) {
				for _, a := range m.Args {
					if w.exprTainted(sf, gid, a, local) {
						found = true
					}
				}
			}
			if w.exprTainted(sf, gid, m.Fun, local) {
				found = true
			}
			return false
		}
		return true
	})
	return found
}

// localTaint is the local names of body assigned (or ranged) from a tainted expression, to a fixed point, with the
// polarity of a name assigned from an == 0 test (root) or a != 0 test (not root). It is by name, not by declaration: a
// name reused for another value in the same body is tainted throughout (over-reporting).
func (w *world) localTaint(sf *srcFile, gid string, fd *ast.FuncDecl) *taintEnv {
	body := fd.Body
	env := &taintEnv{declared: declaredNames(fd), tainted: map[string]bool{}, rootV: map[string]bool{}, nonRootV: map[string]bool{}}
	add := func(set map[string]bool, e ast.Expr) bool {
		if id, ok := e.(*ast.Ident); ok && id.Name != "_" && !set[id.Name] {
			set[id.Name] = true
			return true
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		ast.Inspect(body, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.AssignStmt:
				for _, r := range n.Rhs {
					if w.exprTainted(sf, gid, r, env) {
						for _, l := range n.Lhs {
							if add(env.tainted, l) {
								changed = true
							}
						}
						break
					}
				}
				if len(n.Lhs) == 1 && len(n.Rhs) == 1 {
					if w.isRootE(sf, gid, n.Rhs[0], env) && add(env.rootV, n.Lhs[0]) {
						changed = true
					}
					if w.isNotRootE(sf, gid, n.Rhs[0], env) && add(env.nonRootV, n.Lhs[0]) {
						changed = true
					}
				}
			case *ast.ValueSpec:
				if w.exprTainted(sf, gid, n, env) {
					for _, nm := range n.Names {
						if add(env.tainted, nm) {
							changed = true
						}
					}
				}
				if len(n.Names) == 1 && len(n.Values) == 1 {
					if w.isRootE(sf, gid, n.Values[0], env) && add(env.rootV, n.Names[0]) {
						changed = true
					}
					if w.isNotRootE(sf, gid, n.Values[0], env) && add(env.nonRootV, n.Names[0]) {
						changed = true
					}
				}
			case *ast.RangeStmt:
				if w.exprTainted(sf, gid, n.X, env) {
					if n.Key != nil && add(env.tainted, n.Key) {
						changed = true
					}
					if n.Value != nil && add(env.tainted, n.Value) {
						changed = true
					}
				}
			}
			return true
		})
	}
	return env
}

// declaredNames is the names fd declares in its own body: receiver, parameters, results, := and var names, range
// variables and the parameters of its closures. A scope is not told apart from another, so a name declared anywhere
// in the body hides the package member of that name throughout it (for the taint rules only: a call of a helper is
// matched without regard to it).
func declaredNames(fd *ast.FuncDecl) map[string]bool {
	m := map[string]bool{}
	fields := func(fl *ast.FieldList) {
		if fl == nil {
			return
		}
		for _, f := range fl.List {
			for _, n := range f.Names {
				m[n.Name] = true
			}
		}
	}
	fields(fd.Recv)
	fields(fd.Type.Params)
	fields(fd.Type.Results)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			fields(n.Type.Params)
			fields(n.Type.Results)
		case *ast.AssignStmt:
			if n.Tok == token.DEFINE {
				for _, l := range n.Lhs {
					if id, ok := l.(*ast.Ident); ok {
						m[id.Name] = true
					}
				}
			}
		case *ast.ValueSpec:
			for _, nm := range n.Names {
				m[nm.Name] = true
			}
		case *ast.RangeStmt:
			if n.Tok == token.DEFINE {
				for _, e := range []ast.Expr{n.Key, n.Value} {
					if id, ok := e.(*ast.Ident); ok {
						m[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return m
}

// idValue is whether e is a value read from an id: a call of Geteuid or Getuid, or an expression the taint rules
// above read from one.
func (w *world) idValue(sf *srcFile, gid string, e ast.Expr, env *taintEnv) bool {
	return idCall(e) || w.exprTainted(sf, gid, e, env)
}

// isRootE is whether e is true exactly for root: an == 0 test of an id value, a name assigned from one, or the
// negation of a not-root test.
func (w *world) isRootE(sf *srcFile, gid string, e ast.Expr, env *taintEnv) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return w.isRootE(sf, gid, e.X, env)
	case *ast.Ident:
		return env != nil && env.rootV[e.Name]
	case *ast.UnaryExpr:
		return e.Op == token.NOT && w.isNotRootE(sf, gid, e.X, env)
	case *ast.BinaryExpr:
		return e.Op == token.EQL && (isZero(e.Y) && w.idValue(sf, gid, e.X, env) || isZero(e.X) && w.idValue(sf, gid, e.Y, env))
	}
	return false
}

// isNotRootE is whether e is true for every process that is not root: an != 0 or > 0 test of an id value, a name
// assigned from one, a negated root test, or an || chain holding such a term.
func (w *world) isNotRootE(sf *srcFile, gid string, e ast.Expr, env *taintEnv) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return w.isNotRootE(sf, gid, e.X, env)
	case *ast.Ident:
		return env != nil && env.nonRootV[e.Name]
	case *ast.UnaryExpr:
		return e.Op == token.NOT && w.isRootE(sf, gid, e.X, env)
	case *ast.BinaryExpr:
		if e.Op == token.LOR {
			return w.isNotRootE(sf, gid, e.X, env) || w.isNotRootE(sf, gid, e.Y, env)
		}
		if e.Op == token.NEQ || e.Op == token.GTR {
			return isZero(e.Y) && w.idValue(sf, gid, e.X, env) || isZero(e.X) && w.idValue(sf, gid, e.Y, env)
		}
	}
	return false
}

// isRootOnlyE is whether e can be true only for root: a root test, or an && chain holding one.
func (w *world) isRootOnlyE(sf *srcFile, gid string, e ast.Expr, env *taintEnv) bool {
	switch x := e.(type) {
	case *ast.ParenExpr:
		return w.isRootOnlyE(sf, gid, x.X, env)
	case *ast.BinaryExpr:
		if x.Op == token.LAND {
			return w.isRootOnlyE(sf, gid, x.X, env) || w.isRootOnlyE(sf, gid, x.Y, env)
		}
	}
	return w.isRootE(sf, gid, e, env)
}

// ---- the precise level ----

// fixPrecise finds the helpers: functions that skip a process that is not root as one of their own statements, or
// call such a function as one.
func (w *world) fixPrecise() {
	for changed := true; changed; {
		changed = false
		for _, f := range w.funcs {
			if f.isTest || isTestName(f) || w.precise[f.key] || !w.skipper[f.key] {
				continue
			}
			if _, ok := w.gate(f, f.decl.Body.List); ok {
				w.precise[f.key] = true
				changed = true
			}
		}
	}
}

// gate returns the position of the first statement in list that skips the test when the process is not root: an
// if (or an else of an == 0 test, or a switch clause) that skips for a process that is not root, or a statement
// calling a helper. Only the statement's own level counts: a closure is another function, and a call in a nested
// block runs only if that block does (the loose level reads those).
func (w *world) gate(f *fn, list []ast.Stmt) (token.Pos, bool) {
	for _, st := range list {
		switch s := st.(type) {
		case *ast.IfStmt:
			if pos, ok := w.gateIf(f, s); ok {
				return pos, true
			}
		case *ast.SwitchStmt:
			if pos, ok := w.gateSwitch(f, s); ok {
				return pos, true
			}
		case *ast.BlockStmt:
			if pos, ok := w.gate(f, s.List); ok {
				return pos, true
			}
		case *ast.LabeledStmt:
			if pos, ok := w.gate(f, []ast.Stmt{s.Stmt}); ok {
				return pos, true
			}
		case *ast.ExprStmt, *ast.AssignStmt, *ast.DeclStmt, *ast.ReturnStmt:
			if w.callsHelper(f, st) && !w.cleared(st.Pos(), st.End()) {
				return st.Pos(), true
			}
		}
	}
	return token.NoPos, false
}

// gateIf reads one if chain: each condition's then branch, and the else branch of an == 0 test.
func (w *world) gateIf(f *fn, s *ast.IfStmt) (token.Pos, bool) {
	if (notRoot(s.Cond) && skips(s.Body) || !mentionsRootTest(s.Cond) && skipsNeedingRoot(s.Body)) && !w.cleared(s.Pos(), s.Body.End()) {
		return s.Pos(), true
	}
	switch e := s.Else.(type) {
	case *ast.IfStmt:
		if pos, ok := w.gateIf(f, e); ok {
			return pos, true
		}
	case *ast.BlockStmt:
		if isRoot(s.Cond) && skips(e) && !w.cleared(e.Pos(), e.End()) {
			return e.Pos(), true
		}
		if pos, ok := w.gate(f, e.List); ok {
			return pos, true
		}
	}
	return token.NoPos, false
}

// gateSwitch reads a switch: a clause that skips for a process that is not root.
func (w *world) gateSwitch(f *fn, s *ast.SwitchStmt) (token.Pos, bool) {
	taggedID := s.Tag != nil && idCall(s.Tag)
	rootClause := false
	for _, c := range s.Body.List {
		cc := c.(*ast.CaseClause)
		for _, e := range cc.List {
			if taggedID && isZero(e) || s.Tag == nil && isRoot(e) {
				rootClause = true
			}
		}
	}
	for _, c := range s.Body.List {
		cc := c.(*ast.CaseClause)
		notRootClause := false
		for _, e := range cc.List {
			switch {
			case taggedID:
				notRootClause = notRootClause || !isZero(e)
			case s.Tag == nil:
				notRootClause = notRootClause || notRoot(e)
			}
		}
		if cc.List == nil && rootClause { // default beside a root case
			notRootClause = true
		}
		if notRootClause && skipsList(cc.Body) && !w.cleared(cc.Pos(), cc.End()) {
			return cc.Pos(), true
		}
		if pos, ok := w.gate(f, cc.Body); ok {
			return pos, true
		}
	}
	return token.NoPos, false
}

// callsHelper is whether st calls or names a precise helper outside any closure.
func (w *world) callsHelper(f *fn, st ast.Stmt) bool {
	found := false
	ast.Inspect(st, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			var keys []string
			switch c := n.Fun.(type) {
			case *ast.Ident:
				keys = w.identKeys(f.file, f.gid, c.Name)
			case *ast.SelectorExpr:
				keys = w.selKeys(f.file, c)
			}
			if anyKey(keys, w.precise) {
				found = true
			}
		}
		return !found
	})
	return found
}

// ---- the loose level ----

// loosePass walks one function body with the state of its enclosing control flow.
type loosePass struct {
	w     *world
	f     *fn
	local *taintEnv
	pos   token.Pos // the first suspect node
}

func (w *world) newPass(f *fn) *loosePass {
	return &loosePass{w: w, f: f, local: w.localTaint(f.file, f.gid, f.decl)}
}

// fixLoose finds the helpers of the loose level: functions that hold a skip that may be for want of root.
func (w *world) fixLoose() {
	for changed := true; changed; {
		changed = false
		for _, f := range w.funcs {
			if f.isTest || isTestName(f) || w.loose[f.key] || !w.skipper[f.key] {
				continue
			}
			p := w.newPass(f)
			if p.walk(f.decl.Body, false, false); p.pos.IsValid() || w.precise[f.key] {
				w.loose[f.key] = true
				changed = true
			}
		}
	}
}

func (p *loosePass) tainted(n ast.Node) bool {
	return n != nil && p.w.exprTainted(p.f.file, p.f.gid, n, p.local)
}

func (p *loosePass) rootOnly(e ast.Expr) bool {
	return p.w.isRootOnlyE(p.f.file, p.f.gid, e, p.local)
}

func (p *loosePass) notRoot(e ast.Expr) bool {
	return p.w.isNotRootE(p.f.file, p.f.gid, e, p.local)
}

func (p *loosePass) note(pos token.Pos) {
	if !p.pos.IsValid() && !p.w.cleared(pos, pos) {
		p.pos = pos
	}
}

// walk reads n: taint is whether an enclosing control expression is read from an id, exempt whether an enclosing
// branch runs only for root. A suspect node's position is kept in p.pos.
func (p *loosePass) walk(n ast.Node, taint, exempt bool) {
	if n == nil {
		return
	}
	ast.Inspect(n, func(m ast.Node) bool {
		switch m := m.(type) {
		case *ast.IfStmt:
			p.walk(m.Init, taint, exempt)
			ct := p.tainted(m.Cond) || p.tainted(m.Init)
			p.walk(m.Cond, taint, exempt)
			p.walk(m.Body, taint || ct, exempt || p.rootOnly(m.Cond))
			p.walk(m.Else, taint || ct, exempt || p.notRoot(m.Cond))
			return false
		case *ast.SwitchStmt:
			p.walk(m.Init, taint, exempt)
			p.walk(m.Tag, taint, exempt)
			tagID := m.Tag != nil && idCall(m.Tag)
			st := taint || p.tainted(m.Tag) || p.tainted(m.Init)
			for _, c := range m.Body.List {
				cc := c.(*ast.CaseClause)
				ct, rootClause := st, len(cc.List) > 0
				for _, e := range cc.List {
					p.walk(e, taint, exempt)
					ct = ct || p.tainted(e)
					if !(tagID && isZero(e) || m.Tag == nil && p.rootOnly(e)) {
						rootClause = false
					}
				}
				for _, s := range cc.Body {
					p.walk(s, ct, exempt || rootClause)
				}
			}
			return false
		case *ast.ForStmt:
			p.walk(m.Init, taint, exempt)
			p.walk(m.Post, taint, exempt)
			p.walk(m.Cond, taint, exempt)
			p.walk(m.Body, taint || p.tainted(m.Cond), exempt)
			return false
		case *ast.RangeStmt:
			p.walk(m.X, taint, exempt)
			p.walk(m.Body, taint || p.tainted(m.X), exempt)
			return false
		case *ast.CallExpr:
			p.call(m, taint, exempt)
			return true
		case *ast.SelectorExpr:
			p.ref(m, p.w.selKeys(p.f.file, m), m.Sel.Name, taint, exempt)
			p.walk(m.X, taint, exempt)
			return false
		case *ast.Ident:
			p.ref(m, p.w.identKeys(p.f.file, p.f.gid, m.Name), m.Name, taint, exempt)
		}
		return true
	})
}

// call reads a skip with a message that says the test needs root, and a call of a skipping function with an id among
// its arguments.
func (p *loosePass) call(c *ast.CallExpr, taint, exempt bool) {
	if exempt {
		return
	}
	if sel, ok := c.Fun.(*ast.SelectorExpr); ok && isSkipName(sel.Sel.Name) && len(c.Args) > 0 {
		if lit, ok := c.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && needsRoot.MatchString(lit.Value) {
			p.note(c.Pos())
		}
		return
	}
	var keys []string
	switch f := c.Fun.(type) {
	case *ast.Ident:
		keys = p.w.identKeys(p.f.file, p.f.gid, f.Name)
	case *ast.SelectorExpr:
		keys = p.w.selKeys(p.f.file, f)
	}
	if anyKey(keys, p.w.skipper) && anyKey(keys, p.w.takesT) {
		for _, a := range c.Args {
			if p.tainted(a) {
				p.note(c.Pos())
			}
		}
	}
}

// ref reads a name: a skip under a tainted control, a loose helper, or a skipping function under a tainted control.
func (p *loosePass) ref(n ast.Node, keys []string, name string, taint, exempt bool) {
	if exempt {
		return
	}
	switch {
	case isSkipName(name):
		if _, isSel := n.(*ast.SelectorExpr); isSel && taint {
			p.note(n.Pos())
		}
	case anyKey(keys, p.w.loose) || anyKey(keys, p.w.precise):
		p.note(n.Pos())
	case taint && anyKey(keys, p.w.skipper) && anyKey(keys, p.w.takesT):
		p.note(n.Pos())
	}
}

// ---- the root run's own skips ----

// ScanAsRoot is Scan's other half: the tests that skip when the process IS root, so a root run (CI's root-suites job, a
// KVM guest) reports them skipped, and scripts/skipgate.sh refuses a skip no root list names. Scan reads the skips of
// a process that is not root, which the unprivileged steps see; a test that skips for root alone (`if os.Geteuid() == 0
// { t.Skip(...) }`, the usual shape of a test that makes its failure with a mode bit, which root passes) is no
// candidate there, and was found only by a root run: the strict skip gate printed UNLISTED five of them after a
// three-hour guest run.
//
// Kind "test" is a skip at the test's own level, kind "sub" one inside a t.Run closure, the test then named
// Test/sub/... as go test prints it (a space is an underscore; a name that is not a literal is "*"). The shapes read:
// an if whose condition is true only for root (an == 0 test of an id call, a name assigned from one, an && chain
// holding one) with a skip in its then branch, or the else of an if whose condition is true for every non-root process;
// a switch clause on `case 0` of an id, or on a root condition; a call of a helper that does either to a fixed point;
// all of these anywhere in the test, a closure included. Not read: a root flag kept in a struct field, a skip decided
// by a probe that is not an id call (the same list as Scan's), and a skip message that says root under no id test.
// A `// rootskips:ignore <reason>` comment on or before the line clears one.
func ScanAsRoot(root string, tags []string, cgo bool) ([]Found, error) {
	w, err := load(root, tags, cgo)
	if err != nil {
		return nil, err
	}
	w.fixTouch()
	w.fixSkipper()
	helpers := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, f := range w.funcs {
			if f.isTest || isTestName(f) || helpers[f.key] || !w.skipper[f.key] || !w.takesT[f.key] {
				continue
			}
			p := &rootPass{w: w, f: f, helpers: helpers, local: w.localTaint(f.file, f.gid, f.decl)}
			if p.walk(f.decl.Body, nil); len(p.found) > 0 {
				helpers[f.key] = true
				changed = true
			}
		}
	}
	var out []Found
	for _, f := range w.funcs {
		if !f.isTest {
			continue
		}
		p := &rootPass{w: w, f: f, helpers: helpers, local: w.localTaint(f.file, f.gid, f.decl)}
		p.walk(f.decl.Body, nil)
		out = append(out, p.found...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir < out[j].Dir
		}
		return out[i].Test < out[j].Test
	})
	return out, nil
}

// rootPass walks one function body for the skips of a root process.
type rootPass struct {
	w       *world
	f       *fn
	helpers map[string]bool
	local   *taintEnv
	found   []Found
}

func (p *rootPass) note(pos token.Pos, path []string) {
	if p.w.cleared(pos, pos) {
		return
	}
	kind, name := "test", p.f.decl.Name.Name
	if len(path) > 0 {
		kind, name = "sub", name+"/"+strings.Join(path, "/")
	}
	p.found = append(p.found, Found{p.f.dir, name, kind, p.w.pos(pos)})
}

func (p *rootPass) rootOnly(e ast.Expr) bool {
	return p.w.isRootOnlyE(p.f.file, p.f.gid, e, p.local)
}

func (p *rootPass) notRoot(e ast.Expr) bool {
	return p.w.isNotRootE(p.f.file, p.f.gid, e, p.local)
}

// subName is the name go test gives a subtest run with the argument a: a literal, spaces as underscores, else "*".
func subName(a ast.Expr) string {
	if lit, ok := a.(*ast.BasicLit); ok && lit.Kind == token.STRING {
		if s, err := strconv.Unquote(lit.Value); err == nil {
			return strings.ReplaceAll(s, " ", "_")
		}
	}
	return "*"
}

func (p *rootPass) walk(n ast.Node, path []string) {
	if n == nil {
		return
	}
	ast.Inspect(n, func(m ast.Node) bool {
		switch m := m.(type) {
		case *ast.IfStmt:
			if p.rootOnly(m.Cond) && skips(m.Body) && !p.w.cleared(m.Pos(), m.Body.End()) {
				p.note(m.Pos(), path)
			}
			if els, ok := m.Else.(*ast.BlockStmt); ok && p.notRoot(m.Cond) && skips(els) && !p.w.cleared(els.Pos(), els.End()) {
				p.note(els.Pos(), path)
			}
		case *ast.SwitchStmt:
			tagID := m.Tag != nil && idCall(m.Tag)
			for _, c := range m.Body.List {
				cc := c.(*ast.CaseClause)
				for _, e := range cc.List {
					if (tagID && isZero(e) || m.Tag == nil && p.rootOnly(e)) && skipsList(cc.Body) && !p.w.cleared(cc.Pos(), cc.End()) {
						p.note(cc.Pos(), path)
					}
				}
			}
		case *ast.CallExpr:
			if sel, ok := m.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Run" && len(m.Args) == 2 {
				if lit, ok := m.Args[1].(*ast.FuncLit); ok {
					p.walk(m.Args[0], path)
					p.walk(lit.Body, append(path[:len(path):len(path)], subName(m.Args[0])))
					return false
				}
			}
			var keys []string
			switch c := m.Fun.(type) {
			case *ast.Ident:
				keys = p.w.identKeys(p.f.file, p.f.gid, c.Name)
			case *ast.SelectorExpr:
				keys = p.w.selKeys(p.f.file, c)
			}
			if anyKey(keys, p.helpers) && !p.w.cleared(m.Pos(), m.End()) {
				p.note(m.Pos(), path)
			}
		}
		return true
	})
}

// ---- the result ----

// classify names each top-level test: kind test when its own statements skip, sub when a skip deeper in it may.
func (w *world) classify() []Found {
	var out []Found
	for _, f := range w.funcs {
		if !f.isTest {
			continue
		}
		if pos, ok := w.gate(f, f.decl.Body.List); ok {
			out = append(out, Found{f.dir, f.decl.Name.Name, "test", w.pos(pos)})
			continue
		}
		p := w.newPass(f)
		p.walk(f.decl.Body, false, false)
		if p.pos.IsValid() {
			out = append(out, Found{f.dir, f.decl.Name.Name, "sub", w.pos(p.pos)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Dir != out[j].Dir {
			return out[i].Dir < out[j].Dir
		}
		return out[i].Test < out[j].Test
	})
	return out
}

func (w *world) pos(p token.Pos) string {
	position := w.fset.Position(p)
	return fmt.Sprintf("%s:%d", filepath.ToSlash(position.Filename), position.Line)
}

// isTest is whether fd is a top-level test: TestX(t *testing.T).
func isTest(name string, fd *ast.FuncDecl) bool {
	if !strings.HasPrefix(name, "Test") || fd.Type.Params == nil || len(fd.Type.Params.List) != 1 {
		return false
	}
	if rest := strings.TrimPrefix(name, "Test"); rest != "" && rest[0] >= 'a' && rest[0] <= 'z' {
		return false // go test runs TestX only where X does not begin with a lower-case letter
	}
	star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	return ok && sel.Sel.Name == "T"
}

// needsRoot reads a skip message that says the test needs root: the form the capability checks use ("loading the
// tier-2 objects needs cap_bpf ...; run as root"), whose condition is not a user id compare. A message about what
// root can do ("root can take any ids") says the opposite and does not match.
var needsRoot = regexp.MustCompile(`(?i)\bneeds? (root|cap_[a-z_]+)\b|\brequires? root\b|; run as root|\broot only\b|\broot tier\b`)

// skipsNeedingRoot is whether the block calls Skip, Skipf or SkipNow outside any closure with a message literal that
// says the test needs root.
func skipsNeedingRoot(b *ast.BlockStmt) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			return false
		case *ast.CallExpr:
			sel, ok := n.Fun.(*ast.SelectorExpr)
			if ok && (sel.Sel.Name == "Skip" || sel.Sel.Name == "Skipf") && len(n.Args) > 0 {
				if lit, ok := n.Args[0].(*ast.BasicLit); ok && lit.Kind == token.STRING && needsRoot.MatchString(lit.Value) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

// skips is whether the block calls a Skip, Skipf or SkipNow method outside any closure.
func skips(b *ast.BlockStmt) bool {
	return skipsList(b.List)
}

func skipsList(list []ast.Stmt) bool {
	found := false
	for _, st := range list {
		ast.Inspect(st, func(n ast.Node) bool {
			switch n := n.(type) {
			case *ast.FuncLit:
				return false
			case *ast.CallExpr:
				if sel, ok := n.Fun.(*ast.SelectorExpr); ok && isSkipName(sel.Sel.Name) {
					found = true
				}
			}
			return !found
		})
	}
	return found
}

// notRoot is whether e is true for a process that is not root, whatever else it says: a term os.Geteuid() != 0 (or
// Getuid, or > 0), a negated == 0, or an || chain holding one. An && chain is not: it skips only when each term holds.
func notRoot(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return notRoot(e.X)
	case *ast.UnaryExpr:
		if e.Op == token.NOT {
			return isRoot(e.X)
		}
	case *ast.BinaryExpr:
		if e.Op == token.LOR {
			return notRoot(e.X) || notRoot(e.Y)
		}
		if e.Op == token.NEQ || e.Op == token.GTR {
			return idCall(e.X) && isZero(e.Y) || idCall(e.Y) && isZero(e.X)
		}
	}
	return false
}

// mentionsRootTest is whether e holds a term true exactly for root (os.Geteuid() == 0): a skip under it is the root
// run's, whatever its message says of root.
func mentionsRootTest(e ast.Expr) bool {
	found := false
	ast.Inspect(e, func(n ast.Node) bool {
		if x, ok := n.(ast.Expr); ok && isRoot(x) {
			found = true
		}
		return !found
	})
	return found
}

// isRoot is whether e is true exactly for root: os.Geteuid() == 0 (or Getuid), possibly parenthesised.
func isRoot(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return isRoot(e.X)
	case *ast.BinaryExpr:
		return e.Op == token.EQL && (idCall(e.X) && isZero(e.Y) || idCall(e.Y) && isZero(e.X))
	}
	return false
}

// idCall is whether e is a call of a Geteuid or Getuid function (os, unix or syscall).
func idCall(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	return ok && isIDName(sel.Sel.Name)
}

func isZero(e ast.Expr) bool {
	lit, ok := e.(*ast.BasicLit)
	return ok && lit.Kind == token.INT && lit.Value == "0"
}
