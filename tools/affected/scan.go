// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// treeRead is what marks test code that reads the source tree rather than (only) importing the code under test: a
// repo-root name, a walk, a Go parse, the module's go.mod, or a path climbing out of the package. It errs wide: a
// walk of a temporary directory matches too, which costs a test run, never a missed one.
var treeRead = regexp.MustCompile(`\b(repoRoot|moduleRoot|modRoot|findRepoRoot|findModuleRoot|treeRoot|projectRoot|sourceRoot)\b` +
	`|filepath\.WalkDir?\(|fs\.WalkDir\(|parser\.Parse(File|Dir)\(|packages\.Load\(|"go\.mod"|"\.\.(/[^"]*)?"`)

// docRead marks a tree-reading file that reads Markdown: its tests are the docs gate's.
var docRead = regexp.MustCompile(`\.md"|"docs"|"docs/|"spec"|"spec/|README`)

// seed is a source scanner known to read the tree (for example TestLedgerTargetSingleSource):
// always run whether or not the pattern scan finds it. test "" means every test of file.
type seed struct{ dir, file, test string }

var seeds = []seed{
	{dir: "internal/askclient", test: "TestLedgerTargetSingleSource"},
	{dir: "internal/control", file: "linkgate_test.go"},
	{dir: "pkg/spec/agent", test: "TestLiveOffGolden"},
	// go list ./... over its own subtree: a new package under internal/runtime/capture is what it checks.
	{dir: "internal/runtime/capture", test: "TestCaptureLinksNoEngine"},
}

// knownReaders are packages whose tests read a part of the tree by a path the literal scan cannot rebuild
// (filepath.Join of single segments): a change there selects the package.
var knownReaders = []struct{ prefix, dir string }{
	{prefix: "spec/record/", dir: "pkg/spec/record"},
	{prefix: "examples/", dir: "pkg/spec/agent"},
}

// hooksStep is the full gate's tegotesthooks line in scripts/precommit.sh, hooksDir a directory on it and hooksTag a
// test file behind that tag: the patterns of scripts/precommit_test.sh's item 21e.
var (
	hooksStep = regexp.MustCompile(`(?m)^[ \t]*pc_add tests unit "unit tests \(-tags tegotesthooks\)".*$`)
	hooksDir  = regexp.MustCompile(`\./[A-Za-z0-9_/.-]+/`)
	hooksTag  = regexp.MustCompile(`(?m)^//go:build .*tegotesthooks`)
)

// hooksList reads the directories the full gate's tegotesthooks step names from precommit.sh. No such step is an
// error, so no plan: the gate then runs in full.
func hooksList(gate []byte) (map[string]bool, error) {
	line := hooksStep.Find(gate)
	if line == nil {
		return nil, errors.New("scripts/precommit.sh has no tegotesthooks step")
	}
	out := map[string]bool{}
	for _, d := range hooksDir.FindAll(line, -1) {
		out[strings.TrimSuffix(strings.TrimPrefix(string(d), "./"), "/")] = true
	}
	if len(out) == 0 {
		return nil, errors.New("scripts/precommit.sh's tegotesthooks step names no directory")
	}
	return out, nil
}

// hooksTagged says whether a test file in dir sits behind the tegotesthooks tag. A file it cannot read is skipped:
// scanFile has already made its package a whole-package run, and go list has named it.
func hooksTagged(dir string) bool {
	files, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		return false
	}
	for _, f := range files {
		if src, err := os.ReadFile(f); err == nil && hooksTag.Match(src) {
			return true
		}
	}
	return false
}

// pkgFacts is what the scan found in one package's test files under one build.
type pkgFacts struct {
	whole  bool            // a tree read not pinned to named tests (a package-level var, TestMain, an unreferenced helper)
	tests  map[string]bool // the tests that read the tree, directly or through a helper of the package
	docs   bool            // a tree-reading file that reads Markdown
	why    string          // the first match, for the explanation
	builds []string        // module packages its tests name by path (built, run, listed)
	paths  []string        // repo-relative existing paths its tests name
}

// facts maps a build's tags to each package's facts.
type facts map[string]map[string]*pkgFacts

type funcFact struct {
	name  string
	test  bool   // a Test, Fuzz or Example function: runnable by -run
	bench bool   // a Benchmark: go test runs none without -bench
	glob  bool   // TestMain or init: runs for every test
	hit   string // the treeRead match in its body
	refs  map[string]bool
}

type fileFacts struct {
	funcs     []funcFact
	globalHit string          // a package-level declaration that reads the tree
	globRefs  map[string]bool // names package-level declarations use
	docs      bool
	lits      []string
	file      string // base name
	err       error
}

// scanCodeBuilds finds the module packages a package's own (non-test) code names by import path: a test helper that
// builds or runs a binary for the tests that import it. A test package's binary closure takes those of every
// package of its test binary (makePlan).
func scanCodeBuilds(root, module string, graphs map[string]*graph) (map[string][]string, error) {
	lit := regexp.MustCompile(`"(` + regexp.QuoteMeta(module) + `(?:/[A-Za-z0-9_.\-/]*)?)"`)
	known := knownDirs(graphs)
	cache := map[string][]string{}
	out := map[string][]string{}
	for _, g := range graphs {
		for path, p := range g.pkgs {
			got := map[string]bool{}
			for _, b := range out[path] {
				got[b] = true
			}
			for _, rel := range p.files {
				names, ok := cache[rel]
				if !ok {
					src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
					if err != nil {
						return nil, err
					}
					for _, m := range lit.FindAllSubmatch(src, -1) {
						for _, b := range modulePkgs(module, p.dir, string(m[1]), known) {
							if b != path {
								names = append(names, b)
							}
						}
					}
					cache[rel] = names
				}
				for _, b := range names {
					got[b] = true
				}
			}
			if len(got) > 0 {
				out[path] = sorted(got)
			}
		}
	}
	return out, nil
}

// scanTests scans each build's test files (each file parsed once) into per-package facts.
func scanTests(root, module string, graphs map[string]*graph) (facts, error) {
	cache := map[string]*fileFacts{}
	known := knownDirs(graphs)
	out := facts{}
	for tags, g := range graphs {
		out[tags] = map[string]*pkgFacts{}
		for path, p := range g.pkgs {
			if len(p.testFiles) == 0 {
				continue
			}
			var files []*fileFacts
			for _, rel := range p.testFiles {
				ff, ok := cache[rel]
				if !ok {
					ff = scanFile(filepath.Join(root, filepath.FromSlash(rel)))
					cache[rel] = ff
				}
				files = append(files, ff)
			}
			out[tags][path] = combine(root, module, p.dir, files, known)
		}
	}
	return out, nil
}

// knownDirs maps each repo-relative package directory of any build to its import path.
func knownDirs(graphs map[string]*graph) map[string]string {
	known := map[string]string{}
	for _, g := range graphs {
		for dir, p := range g.byDir {
			known[dir] = p
		}
	}
	return known
}

func scanFile(abs string) *fileFacts {
	ff := &fileFacts{file: filepath.Base(abs), globRefs: map[string]bool{}}
	src, err := os.ReadFile(abs)
	if err != nil {
		ff.err = err
		return ff
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, abs, src, parser.SkipObjectResolution)
	if err != nil {
		ff.err = err
		return ff
	}
	text := func(n ast.Node) string {
		return string(src[fset.Position(n.Pos()).Offset:fset.Position(n.End()).Offset])
	}
	ff.docs = docRead.Match(src) && treeRead.Match(src)
	for _, d := range f.Decls {
		switch d := d.(type) {
		case *ast.FuncDecl:
			name := d.Name.Name
			ft := funcFact{name: name, refs: identRefs(d.Body), hit: treeRead.FindString(text(d))}
			if d.Recv == nil { // a method is reached through its name, as a helper is
				ft.test = isTestName(name)
				ft.bench = strings.HasPrefix(name, "Benchmark")
				ft.glob = name == "TestMain" || name == "init"
			}
			ff.funcs = append(ff.funcs, ft)
		case *ast.GenDecl:
			if d.Tok == token.IMPORT {
				continue
			}
			if m := treeRead.FindString(text(d)); m != "" && ff.globalHit == "" {
				ff.globalHit = m
			}
			for n := range identRefs(d) {
				ff.globRefs[n] = true
			}
		}
	}
	ast.Inspect(f, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.ImportSpec:
			return false
		case *ast.BasicLit:
			if s, ok := stringLit(n); ok {
				ff.lits = append(ff.lits, s)
			}
		case *ast.CallExpr:
			if s := joinedLits(n); s != "" {
				ff.lits = append(ff.lits, s)
			}
		}
		return true
	})
	return ff
}

func stringLit(e ast.Expr) (string, bool) {
	l, ok := e.(*ast.BasicLit)
	if !ok || l.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(l.Value)
	if err != nil || s == "" || strings.ContainsAny(s, "\n\t") {
		return "", false
	}
	return s, true
}

// joinedLits folds the leading string-literal arguments of a filepath.Join or path.Join call (two or more) into the
// one path they make: filepath.Join("mcp", "testdata", name) reads under mcp/testdata, which no single segment
// names.
func joinedLits(c *ast.CallExpr) string {
	sel, ok := c.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Join" {
		return ""
	}
	if x, ok := sel.X.(*ast.Ident); !ok || (x.Name != "filepath" && x.Name != "path") {
		return ""
	}
	var segs []string
	for _, a := range c.Args {
		s, ok := stringLit(a)
		if !ok {
			break
		}
		segs = append(segs, s)
	}
	if len(segs) < 2 {
		return ""
	}
	return path.Join(segs...)
}

func isTestName(n string) bool {
	for _, p := range []string{"Test", "Fuzz", "Example"} {
		if rest, ok := strings.CutPrefix(n, p); ok && n != "TestMain" {
			if rest == "" || !('a' <= rest[0] && rest[0] <= 'z') {
				return true
			}
		}
	}
	return false
}

func identRefs(n ast.Node) map[string]bool {
	refs := map[string]bool{}
	if n == nil {
		return refs
	}
	ast.Inspect(n, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok {
			refs[id.Name] = true
		}
		return true
	})
	return refs
}

// combine merges one package's files: seeds and pattern hits, carried from helpers to the tests that call them, the
// module packages its tests name and the paths they name.
func combine(root, module, dir string, files []*fileFacts, known map[string]string) *pkgFacts {
	pf := &pkgFacts{tests: map[string]bool{}}
	tainted := map[string]bool{}
	var all []funcFact
	for _, ff := range files {
		if ff.err != nil {
			pf.whole, pf.why = true, "unparsable test file "+ff.file+": "+ff.err.Error()
			continue
		}
		for _, ft := range ff.funcs {
			for _, s := range seeds {
				if s.dir == dir && (s.file == "" || s.file == ff.file) && (s.test == ft.name || s.test == "" && ft.test) {
					ft.hit = "seed"
				}
			}
			if ft.hit != "" {
				if ff.docs {
					pf.docs = true
				}
				if pf.why == "" {
					pf.why = ff.file + ": " + ft.name + " (" + ft.hit + ")"
				}
			}
			all = append(all, ft)
		}
		if ff.globalHit != "" {
			pf.whole = true
			pf.docs = pf.docs || ff.docs
			if pf.why == "" {
				pf.why = ff.file + ": a package-level declaration (" + ff.globalHit + ")"
			}
		}
	}
	for _, ft := range all {
		if ft.hit != "" {
			tainted[ft.name] = true
		}
	}
	for changed := true; changed; {
		changed = false
		for _, ft := range all {
			if tainted[ft.name] {
				continue
			}
			for r := range ft.refs {
				if tainted[r] {
					tainted[ft.name], changed = true, true
					break
				}
			}
		}
	}
	reached := map[string]bool{}
	for _, ft := range all {
		if !tainted[ft.name] {
			continue
		}
		switch {
		case ft.glob:
			pf.whole = true
		case ft.test:
			pf.tests[ft.name] = true
		}
		for r := range ft.refs {
			reached[r] = true
		}
	}
	// A tainted helper no test, TestMain or tainted function reaches (a table's function value, a package-level
	// var) is run by something the scan cannot name: run the whole package.
	for _, ft := range all {
		if tainted[ft.name] && !ft.test && !ft.glob && !ft.bench && !reached[ft.name] && !pf.whole {
			used := false
			for _, ff := range files {
				if ff.globRefs[ft.name] {
					used = true
				}
			}
			if used || len(pf.tests) == 0 {
				pf.whole = true
			}
		}
	}
	builds, paths := map[string]bool{}, map[string]bool{}
	for _, ff := range files {
		for _, s := range ff.lits {
			if bs := modulePkgs(module, dir, s, known); len(bs) > 0 {
				for _, b := range bs {
					builds[b] = true
				}
				continue
			}
			for _, p := range literalPaths(root, dir, s, known) {
				paths[p] = true
			}
		}
	}
	pf.builds, pf.paths = sorted(builds), sorted(paths)
	return pf
}

// modulePkgs resolves a literal naming packages of the module: an import path ("github.com/x/y/cmd/tego") or a
// "./" path from the root or the package's directory, each also as a "/..." pattern, which names every package
// under that directory, one added by the change included (a test that runs go list ./... over its own subtree).
// "./..." from the root (the whole module) is left out: every change would select the test.
func modulePkgs(module, dir, s string, known map[string]string) []string {
	pat := strings.HasSuffix(s, "/...")
	s = strings.TrimSuffix(s, "/...")
	var dirs []string
	switch {
	case s == module:
		dirs = []string{"."}
	case strings.HasPrefix(s, module+"/"):
		dirs = []string{strings.TrimPrefix(s, module+"/")}
	case strings.HasPrefix(s, "./") || strings.HasPrefix(s, "../") || pat && s == ".":
		dirs = []string{path.Clean(s), path.Clean(dir + "/" + s)}
	default:
		return nil
	}
	for _, d := range dirs {
		if d == "." || d == ".." || strings.HasPrefix(d, "../") {
			continue
		}
		if !pat {
			if p, ok := known[d]; ok && d != dir {
				return []string{p}
			}
			continue
		}
		var out []string
		for kd, p := range known {
			if kd == d || strings.HasPrefix(kd, d+"/") {
				out = append(out, p)
			}
		}
		if len(out) > 0 {
			sort.Strings(out)
			return out
		}
	}
	if !pat && strings.HasPrefix(s, module) {
		// An import path the graphs do not list (a package of another build): still a build the test names.
		return []string{s}
	}
	return nil
}

// literalPaths resolves a literal that looks like a path (a slash or an extension) against the root and the
// package's directory, keeping the ones that exist inside the tree. A package directory above the test's own (a bare
// ".." chain, the start of a path built at run time) is not kept: it made the test a reader of every file under it
// (19 packages for one line of derive/mcp/testdata), and a test that climbs out by ".." is a source scanner, run in
// scoped mode whatever changed.
func literalPaths(root, dir, s string, known map[string]string) []string {
	if len(s) > 200 || strings.ContainsAny(s, " *?%:$") || !strings.ContainsAny(s, "/.") || filepath.IsAbs(s) {
		return nil
	}
	var out []string
	for _, c := range []string{path.Clean(dir + "/" + s), path.Clean(s)} {
		if c == "." || c == dir || c == ".." || strings.HasPrefix(c, "../") {
			continue
		}
		if _, pkg := known[c]; pkg && strings.HasPrefix(dir, c+"/") {
			continue
		}
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(c))); err == nil {
			out = append(out, c)
		}
	}
	return out
}

func sorted(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
