// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"go/ast"
	"go/build/constraint"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"
)

// GO-4 is held per package (a directory's test binary): a package whose tests can start a run, a sweep, a gc, a
// reaper or the tego binary, or write tego's state below a tego home (stateWriters), has a TestMain that ends the binary with the exit code of testutil.GuardedMain or
// GuardedLeakCheckMain (callsGuard) in every build that compiles such a test, so the binary fails when the invoking
// user's real ~/.tego or ~/.bash_history changed while it ran. The static rules above and the test build's refusal
// keep a run out of those files; this keeps the package that slipped past both from passing.

// runPackages are the packages, relative to the module, whose own tests run tego in-process (commands, runs,
// sweeps, gc, the chain anchor and the own log) and whose import by a test lets that test do the same.
var runPackages = []string{"internal/runtime", "internal/cli"}

// stateWriters are the packages, relative to the module, that write tego's state below a <tego home> their caller
// names (internal/govlog: the governance ledger at <tego home>/gov, ADR 0100 (5)). A test that names the real one
// writes there, so their own tests and every test that can reach them run under the guard as runPackages' do.
var stateWriters = []string{"internal/govlog"}

// tegoStarters are the helpers a test calls to start the tego binary as a subprocess.
var tegoStarters = map[string]bool{"TegoEnv": true, "writeMachineConfig": true, "writeMachineConfigWith": true}

// goFacts is what GO-4 reads of one Go file.
type goFacts struct {
	rel     string          // slash-separated, relative to the root
	dir     string          // rel's directory: the package
	pkg     string          // the package's import path
	test    bool            // a _test.go file
	cons    constraint.Expr // the //go:build line, nil for none
	never   bool            // its name confines it to another GOOS or GOARCH than linux/amd64
	signal  string          // the first thing in it that starts a run, "" for none
	line    int             // signal's line
	guard   bool            // it declares a TestMain that ends with a guarded run's code (callsGuard)
	imports []modImport     // its imports of the module's own packages
}

// modImport is one import of a package of the module: its directory relative to the root, and the line.
type modImport struct {
	dir  string
	line int
}

// modulePath is the module path root/go.mod declares, or "" when root has no go.mod: GO-4 needs it to know the
// import paths of the packages that run tego, and does not apply without it.
func modulePath(root string) (string, error) {
	b, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		if f := strings.Fields(sc.Text()); len(f) == 2 && f[0] == "module" {
			return strings.Trim(f[1], `"`), nil
		}
	}
	return "", fmt.Errorf("go.mod: no module line")
}

// factsOf reads GO-4's facts from a parsed file.
func factsOf(f *ast.File, fset *token.FileSet, src []byte, rel, mod string) (*goFacts, error) {
	dir := path.Dir(rel)
	gf := &goFacts{rel: rel, dir: dir, pkg: path.Join(mod, dir), test: strings.HasSuffix(rel, "_test.go"), never: otherPlatform(rel)}
	for _, l := range strings.Split(string(src[:fset.Position(f.Package).Offset]), "\n") {
		if constraint.IsGoBuild(l) {
			e, err := constraint.Parse(l)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", rel, err)
			}
			gf.cons = e
		}
	}
	at := func(p token.Pos) int { return fset.Position(p).Line }
	note := func(what string, p token.Pos) {
		if gf.signal == "" || at(p) < gf.line {
			gf.signal, gf.line = what, at(p)
		}
	}
	for _, rp := range runPackages {
		if gf.test && gf.pkg == path.Join(mod, rp) {
			note(rp+"'s own tests run its commands, runs and sweeps in-process", f.Package)
		}
	}
	for _, sw := range stateWriters {
		if gf.test && gf.pkg == path.Join(mod, sw) {
			note(sw+"'s own tests write tego's state below a tego home", f.Package)
		}
	}
	for _, im := range f.Imports {
		p, err := strconv.Unquote(im.Path.Value)
		if err != nil {
			continue
		}
		if rel, ok := strings.CutPrefix(p, mod+"/"); ok {
			gf.imports = append(gf.imports, modImport{rel, at(im.Pos())})
		}
	}
	heads := listsOf(f)
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.BasicLit:
			if n.Kind != token.STRING {
				return true
			}
			s, err := strconv.Unquote(n.Value)
			if err != nil {
				return true
			}
			switch {
			case strings.HasPrefix(s, "TEGO_CONFIG=") || strings.HasPrefix(s, "TEGO_TEST_CHAIN_ANCHOR="):
				note("this file gives a tego subprocess its environment", n.Pos())
			case (s == path.Join(mod, "cmd/tego") || s == "./cmd/tego") && !goBuildExempt[rel]:
				note("this file builds cmd/tego", n.Pos())
			}
		case *ast.CallExpr:
			name := ""
			switch fn := n.Fun.(type) {
			case *ast.Ident:
				name = fn.Name
			case *ast.SelectorExpr:
				name = fn.Sel.Name
			}
			if tegoStarters[name] {
				note("this file calls "+name+", which starts the tego binary", n.Pos())
			}
			if sub, ok := tegoCommand(n); ok {
				note("this file runs the tego binary (tego "+sub+")", n.Pos())
			} else if what, ok := tegoVariadic(n, heads); ok {
				note("this file runs the tego binary ("+what+")", n.Pos())
			}
		case *ast.FuncDecl:
			if gf.test && n.Recv == nil && n.Name.Name == "TestMain" && n.Body != nil && callsGuard(n) {
				gf.guard = true
			}
		}
		return true
	})
	return gf, nil
}

// listsOf maps each name a file assigns (x := ..., x = ..., var x = ...) to the expressions it assigns it, so that
// tegoVariadic can read the first element of an argument list built in a local variable.
func listsOf(f *ast.File) map[string][]ast.Expr {
	lists := map[string][]ast.Expr{}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.AssignStmt:
			if len(n.Lhs) == len(n.Rhs) {
				for i, l := range n.Lhs {
					if id, ok := l.(*ast.Ident); ok && id.Name != "_" {
						lists[id.Name] = append(lists[id.Name], n.Rhs[i])
					}
				}
			}
		case *ast.ValueSpec:
			if len(n.Names) == len(n.Values) {
				for i, id := range n.Names {
					lists[id.Name] = append(lists[id.Name], n.Values[i])
				}
			}
		}
		return true
	})
	return lists
}

// listHeads are the string literals an argument list can start with: the first element of a []string literal, of
// the list an append extends, or of what a name in lists is assigned (any of its assignments, each name followed
// once).
func listHeads(e ast.Expr, lists map[string][]ast.Expr, seen map[string]bool) []string {
	switch e := e.(type) {
	case *ast.ParenExpr:
		return listHeads(e.X, lists, seen)
	case *ast.CompositeLit:
		if len(e.Elts) > 0 {
			if b, ok := e.Elts[0].(*ast.BasicLit); ok && b.Kind == token.STRING {
				if s, err := strconv.Unquote(b.Value); err == nil {
					return []string{s}
				}
			}
		}
	case *ast.CallExpr:
		if id, ok := e.Fun.(*ast.Ident); ok && id.Name == "append" && len(e.Args) > 0 {
			return listHeads(e.Args[0], lists, seen)
		}
	case *ast.Ident:
		if seen[e.Name] {
			return nil
		}
		seen[e.Name] = true
		var out []string
		for _, v := range lists[e.Name] {
			out = append(out, listHeads(v, lists, seen)...)
		}
		return out
	}
	return nil
}

// namesABinary reports whether a program expression is spelled as the tego binary: a name, a field or a pointer
// whose name holds "tego" or ends in "bin" (bin, s.bin, *tegoBin, e.tego).
// namesProduct reports whether an identifier holds the product's name as a word part: tego, Tego or TEGO not followed
// by r or R, so tegoBin, realTego and TEGO_BIN name the binary and category or CATEGORY do not (ADR 0060).
func namesProduct(n string) bool {
	for _, w := range []string{"tego", "Tego", "TEGO"} {
		for rest := n; ; {
			i := strings.Index(rest, w)
			if i < 0 {
				break
			}
			if j := i + len(w); j == len(rest) || (rest[j] != 'r' && rest[j] != 'R') {
				return true
			}
			rest = rest[i+1:]
		}
	}
	return false
}

func namesABinary(e ast.Expr) bool {
	for {
		switch x := e.(type) {
		case *ast.ParenExpr:
			e = x.X
			continue
		case *ast.StarExpr:
			e = x.X
			continue
		case *ast.Ident:
			return namesProduct(x.Name) || strings.HasSuffix(strings.ToLower(x.Name), "bin")
		case *ast.SelectorExpr:
			return namesProduct(x.Sel.Name) || strings.HasSuffix(strings.ToLower(x.Sel.Name), "bin")
		}
		return false
	}
}

// tegoVariadic reports, for GO-4, an exec.Command or exec.CommandContext that passes its arguments as one list
// (exec.Command(bin, args...)) and runs the tego binary: its program is a literal ending in tego, or an expression
// spelled as the binary (namesABinary), or any expression that is not a string literal given a list that starts
// with one of tegoSubcommands (a []string literal, an append to one, or a name of the file assigned one). GO-5,
// which judges the command's Env, follows only the literal subcommand of tegoCommand.
func tegoVariadic(c *ast.CallExpr, lists map[string][]ast.Expr) (string, bool) {
	first := 0
	switch {
	case isSel(c.Fun, "exec", "Command"):
	case isSel(c.Fun, "exec", "CommandContext"):
		first = 1
	default:
		return "", false
	}
	if !c.Ellipsis.IsValid() || len(c.Args) != first+2 {
		return "", false
	}
	prog, literal := c.Args[first], false
	if b, ok := prog.(*ast.BasicLit); ok {
		v, err := strconv.Unquote(b.Value)
		if b.Kind != token.STRING || err != nil || (v != "tego" && !strings.HasSuffix(v, "/tego")) {
			return "", false
		}
		literal = true
	}
	for _, h := range listHeads(c.Args[first+1], lists, map[string]bool{}) {
		if contains(tegoSubcommands, h) {
			return "tego " + h + ", from an argument list", true
		}
	}
	if literal || namesABinary(prog) {
		return "a program spelled as the binary, given an argument list", true
	}
	return "", false
}

// guardedMains are the testutil helpers that run a package's tests under GuardRealTego and return the exit code the
// binary must end with: non-zero when the tests failed or the real ~/.tego or ~/.bash_history changed meanwhile.
var guardedMains = map[string]bool{"GuardedMain": true, "GuardedLeakCheckMain": true, "GuardedStdioLeakCheckMain": true}

// callsGuard reports whether a TestMain ends its binary with the exit code of a guarded run of its tests, in one of
// two shapes of its own top-level statements (never inside a closure or another statement's block):
//
//   - os.Exit(testutil.GuardedMain(m)), or GuardedLeakCheckMain or GuardedStdioLeakCheckMain (the bare names inside
//     testutil);
//   - code := testutil.GuardedMain(m) (or var code = ...), and the first statement after it that can end TestMain
//     is os.Exit(code), with no statement between that assigns code, takes its address, calls os.Exit, panics or
//     returns, at any depth, closures included.
//
// m is used nowhere else in the body, so no test runs before or outside the guard, and no top-level statement before
// the guarded call ends TestMain (a return, os.Exit or panic that would leave it unreachable). A helper mode that
// returns or exits inside an if before it is allowed: that path runs no test. Any other shape is flagged, a
// hand-written check of testutil.GuardRealTego's error included: GO-4 holds one exact shape, which a shape check
// can hold, where each pass over the hand-written checks found another way to exit 0 whatever the tests wrote.
func callsGuard(fn *ast.FuncDecl) bool {
	params := fn.Type.Params.List
	if len(params) != 1 || len(params[0].Names) != 1 || params[0].Names[0].Name == "_" {
		return false
	}
	m := params[0].Names[0].Name
	list := fn.Body.List
	// guarded reports whether e is GuardedMain(m) or GuardedLeakCheckMain(m).
	guarded := func(e ast.Expr) bool {
		c, ok := e.(*ast.CallExpr)
		if !ok || len(c.Args) != 1 || c.Ellipsis.IsValid() {
			return false
		}
		if id, ok := c.Args[0].(*ast.Ident); !ok || id.Name != m {
			return false
		}
		switch f := c.Fun.(type) {
		case *ast.Ident:
			return guardedMains[f.Name]
		case *ast.SelectorExpr:
			_, ok := f.X.(*ast.Ident)
			return ok && guardedMains[f.Sel.Name]
		}
		return false
	}
	// exitArg is the argument of os.Exit when st is the statement os.Exit(x).
	exitArg := func(st ast.Stmt) (ast.Expr, bool) {
		es, ok := st.(*ast.ExprStmt)
		if !ok {
			return nil, false
		}
		c, ok := es.X.(*ast.CallExpr)
		if !ok || !isSel(c.Fun, "os", "Exit") || len(c.Args) != 1 {
			return nil, false
		}
		return c.Args[0], true
	}
	// ends reports whether a top-level statement ends TestMain whatever its state: a return, an os.Exit or a panic.
	ends := func(st ast.Stmt) bool {
		if _, ok := st.(*ast.ReturnStmt); ok {
			return true
		}
		if _, ok := exitArg(st); ok {
			return true
		}
		if es, ok := st.(*ast.ExprStmt); ok {
			if c, ok := es.X.(*ast.CallExpr); ok {
				if id, ok := c.Fun.(*ast.Ident); ok && id.Name == "panic" {
					return true
				}
			}
		}
		return false
	}
	at, held := -1, ""
	for i, st := range list {
		if x, ok := exitArg(st); ok && guarded(x) {
			at = i
			break
		}
		if a, ok := st.(*ast.AssignStmt); ok && len(a.Lhs) == 1 && len(a.Rhs) == 1 && guarded(a.Rhs[0]) {
			if id, ok := a.Lhs[0].(*ast.Ident); ok && id.Name != "_" {
				at, held = i, id.Name
			}
			break
		}
		if d, ok := st.(*ast.DeclStmt); ok {
			if g, ok := d.Decl.(*ast.GenDecl); ok && len(g.Specs) == 1 {
				if v, ok := g.Specs[0].(*ast.ValueSpec); ok && len(v.Names) == 1 && len(v.Values) == 1 && guarded(v.Values[0]) {
					if v.Names[0].Name != "_" {
						at, held = i, v.Names[0].Name
					}
					break
				}
			}
		}
		if ends(st) {
			return false
		}
	}
	if at < 0 {
		return false
	}
	// m appears once in the body: the guarded call's argument.
	uses := 0
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == m {
			uses++
		}
		return true
	})
	if uses != 1 {
		return false
	}
	if held == "" {
		return true
	}
	for _, st := range list[at+1:] {
		if x, ok := exitArg(st); ok {
			id, ok := x.(*ast.Ident)
			return ok && id.Name == held
		}
		if touchesExit(st, held) {
			return false
		}
	}
	return false // TestMain returns, and the testing package exits with m.Run's code, not the guarded one
}

// touchesExit reports whether st, at any depth (closures included), can change name, take its address, call
// os.Exit, panic or return: anything that would let TestMain end with another code than name's.
func touchesExit(st ast.Stmt, name string) bool {
	found := false
	is := func(e ast.Expr) bool {
		id, ok := e.(*ast.Ident)
		return ok && id.Name == name
	}
	ast.Inspect(st, func(n ast.Node) bool {
		if found {
			return false
		}
		switch n := n.(type) {
		case *ast.ReturnStmt:
			found = true
		case *ast.AssignStmt:
			for _, l := range n.Lhs {
				if is(l) {
					found = true
				}
			}
		case *ast.IncDecStmt:
			found = is(n.X)
		case *ast.UnaryExpr:
			found = n.Op == token.AND && is(n.X)
		case *ast.CallExpr:
			if isSel(n.Fun, "os", "Exit") {
				found = true
			}
			if id, ok := n.Fun.(*ast.Ident); ok && id.Name == "panic" {
				found = true
			}
		}
		return !found
	})
	return found
}

// The platform the tree's tests run on: GO-4 evaluates build constraints for linux/amd64 with the gc toolchain.
var (
	knownOS   = strings.Fields("aix android darwin dragonfly freebsd hurd illumos ios js linux nacl netbsd openbsd plan9 solaris wasip1 windows zos")
	knownArch = strings.Fields("386 amd64 arm arm64 loong64 mips mips64 mips64le mipsle ppc64 ppc64le riscv64 s390x sparc64 wasm")
)

// fixedTag is the value a build tag has on that platform whatever the build's -tags say, and whether it has one.
func fixedTag(tag string) (value, fixed bool) {
	switch {
	case tag == "linux" || tag == "unix" || tag == "amd64" || tag == "gc" || strings.HasPrefix(tag, "go1."):
		return true, true
	case tag == "gccgo" || contains(knownOS, tag) || contains(knownArch, tag):
		return false, true
	}
	return false, false
}

func contains(list []string, s string) bool {
	for _, l := range list {
		if l == s {
			return true
		}
	}
	return false
}

// otherPlatform reports whether a file's name (x_darwin.go, x_windows_arm64_test.go) keeps it out of linux/amd64.
func otherPlatform(rel string) bool {
	name := strings.TrimSuffix(strings.TrimSuffix(path.Base(rel), ".go"), "_test")
	parts := strings.Split(name, "_")
	if len(parts) < 2 {
		return false
	}
	last := parts[len(parts)-1]
	if contains(knownArch, last) {
		if last != "amd64" {
			return true
		}
		if len(parts) >= 3 {
			os := parts[len(parts)-2]
			return contains(knownOS, os) && os != "linux"
		}
		return false
	}
	return contains(knownOS, last) && last != "linux"
}

// noteImports gives a file the signal of an import that can run tego in-process or write its state: an import of
// internal/runtime, internal/cli or a stateWriters package, or of a package of the module whose own (non-test) code
// imports one of them, directly or through
// other such packages. A test file that imports such a package, and a non-test file that does (cmd/tego's main.go,
// which a main_test.go can call), both count: checkGuards still asks for a test in the same build. Which packages
// reach them is taken over all their files whatever the build tags, which can only ask for a guard more often.
func noteImports(facts []*goFacts) {
	reach := map[string]string{} // package directory -> the run package it reaches
	for _, rp := range append(slices.Clone(runPackages), stateWriters...) {
		reach[rp] = rp
	}
	for changed := true; changed; {
		changed = false
		for _, f := range facts {
			if f.test || f.never || reach[f.dir] != "" {
				continue
			}
			for _, im := range f.imports {
				if r := reach[im.dir]; r != "" {
					reach[f.dir], changed = r, true
					break
				}
			}
		}
	}
	for _, f := range facts {
		for _, im := range f.imports {
			r := reach[im.dir]
			if r == "" || im.dir == f.dir || (f.signal != "" && f.line <= im.line) {
				continue
			}
			who := "this file"
			if f.test {
				who = "a test here"
			}
			via := ""
			if im.dir != r {
				via = " (through " + r + ")"
			}
			what := ", which can start a run, a sweep or a gc in-process"
			if slices.Contains(stateWriters, r) {
				what = ", which writes tego's state below a tego home"
			}
			f.signal, f.line = who+" imports "+im.dir+via+what, im.line
		}
	}
}

// checkGuards applies GO-4 to every package the facts describe: for each combination of the free build tags its
// files name, a build that compiles a test and a signal compiles a TestMain that calls GuardRealTego.
func checkGuards(facts []*goFacts) []finding {
	noteImports(facts)
	byDir := map[string][]*goFacts{}
	for _, f := range facts {
		if !f.never {
			byDir[f.dir] = append(byDir[f.dir], f)
		}
	}
	var dirs []string
	for d := range byDir {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var out []finding
	for _, d := range dirs {
		files := byDir[d]
		sort.Slice(files, func(i, j int) bool { return files[i].rel < files[j].rel })
		free := map[string]bool{}
		for _, f := range files {
			if f.cons != nil {
				f.cons.Eval(func(tag string) bool {
					if _, fixed := fixedTag(tag); !fixed {
						free[tag] = true
					}
					return false
				})
			}
		}
		var tags []string
		for t := range free {
			tags = append(tags, t)
		}
		sort.Strings(tags)
		if len(tags) > 10 {
			tags = tags[:10] // 1024 builds; no package of the tree names half as many tags
		}
		for set := 0; set < 1<<len(tags); set++ {
			on := map[string]bool{}
			var named []string
			for i, t := range tags {
				if set&(1<<i) != 0 {
					on[t] = true
					named = append(named, t)
				}
			}
			in := func(f *goFacts) bool {
				return f.cons == nil || f.cons.Eval(func(tag string) bool {
					if v, fixed := fixedTag(tag); fixed {
						return v
					}
					return on[tag]
				})
			}
			var test, guard bool
			var sig *goFacts
			for _, f := range files {
				if !in(f) {
					continue
				}
				test = test || f.test
				guard = guard || f.guard
				if f.signal != "" && sig == nil {
					sig = f
				}
			}
			if !test || sig == nil || guard {
				continue
			}
			build := ""
			if len(named) > 0 {
				build = " in the build with -tags " + strings.Join(named, ",")
			}
			out = append(out, finding{sig.rel, sig.line, "GO-4", sig.signal + ", and no TestMain of the package's tests ends with " +
				"os.Exit(testutil.GuardedMain(m)) or GuardedLeakCheckMain (or code := ...; os.Exit(code))" +
				build + ": a test that wrote the invoking user's real ~/.tego or ~/.bash_history would pass"})
			break
		}
	}
	return out
}
