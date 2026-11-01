// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

// The typed load (ADR 0023's 2026-10-19 design-round note). fdcheck answers what an expression is with go/types,
// not with its syntax: which function a call reaches, which struct a field belongs to, whether a callback is a
// function, which method a method value names. A package is type-checked from its sources under a build
// configuration (GOARCH, build tags, cgo); the packages outside the module (the standard library, x/sys,
// cilium) come from the export data `go list -export` builds, and the module's own packages are checked in
// dependency order, each one importing the others' checked packages, so an object is the same object in every
// package that refers to it.

// buildConfig is one build of the module: the operating system, the architecture, the build tags and cgo.
type buildConfig struct {
	name   string
	goos   string
	goarch string
	tags   string
	cgo    bool
}

// lintTagSet is the tag set of the tagged lint run and of the KVM suites' binaries (.golangci.yml's build-tags).
const lintTagSet = "integration,tegobpf,tegotesthooks"

// mainConfigs are the builds every package is checked under: the two architectures the project ships, each with
// the lint's tag set (the KVM suites' binaries and the integration tests), with the release binary's (`make
// build`: tegobpf) and with none (the `!tegobpf` stubs, the `!integration` and `!tegotesthooks` files), cgo off
// as the binary is built.
var mainConfigs = []buildConfig{
	{"linux/amd64 " + lintTagSet, "linux", "amd64", lintTagSet, false},
	{"linux/amd64 tegobpf", "linux", "amd64", "tegobpf", false},
	{"linux/amd64", "linux", "amd64", "", false},
	{"linux/arm64 " + lintTagSet, "linux", "arm64", lintTagSet, false},
	{"linux/arm64 tegobpf", "linux", "arm64", "tegobpf", false},
	{"linux/arm64", "linux", "arm64", "", false},
}

// extraConfigs check only the packages that hold a file no main configuration builds: the cgo build (os/user's
// libc lookup, pkg/spec/config's passwd_libc.go), a big-endian architecture (bpf2go's _bpfeb.go objects) and
// macOS (the maze setup tool's _darwin.go files: it ships for darwin, and a macOS file is held to the same rules
// as a Linux one, ADR 0023's 2026-10-24 F6 note). A file none of these builds either is a problem: fdcheck cannot
// judge it (uncovered).
var extraConfigs = []buildConfig{
	{"linux/amd64 cgo", "linux", "amd64", "", true},
	{"linux/amd64 cgo " + lintTagSet, "linux", "amd64", lintTagSet, true},
	{"linux/s390x " + lintTagSet, "linux", "s390x", lintTagSet, false},
	{"linux/s390x", "linux", "s390x", "", false},
	{"darwin/arm64", "darwin", "arm64", "", false},
}

// listedPkg is what fdcheck reads of `go list -json`.
type listedPkg struct {
	ImportPath string
	Dir        string
	GoFiles    []string
	CgoFiles   []string
	Export     string
	Standard   bool
	Module     *struct {
		Path string
		Main bool
	}
	Error *struct{ Err string }
}

func (p listedPkg) inModule() bool {
	return p.Module != nil && p.Module.Main && p.Module.Path == modulePath
}

// typedPkg is one module package, type-checked.
type typedPkg struct {
	path  string // import path
	dir   string // relative to the root, with forward slashes
	names []string
	files []*ast.File
	types *types.Package
	info  *types.Info
}

// typedWorld is the module under one build configuration: its packages in dependency order, and the declarations
// fdcheck follows into (a function's body, a constant's value).
type typedWorld struct {
	cfg    buildConfig
	fset   *token.FileSet
	pkgs   []*typedPkg
	byPath map[string]*typedPkg
	imp    types.Importer
	funcs  map[*types.Func]funcDecl  // every module function and method with a body
	consts map[*types.Const]ast.Expr // every module package-level constant with its declared value
	std    map[string]*types.Package // syscall and x/sys/unix, when the world imports them
}

type funcDecl struct {
	decl *ast.FuncDecl
	pkg  *typedPkg
}

// overlay is a set of files that stand in for (or add to) the checkout's: root-relative name -> content.
type overlay map[string][]byte

// goEnv is the go command's environment for a configuration: the host's, but for what selects the files a build
// reads. GOFLAGS is cleared, so a user's -tags or -buildmode cannot change what is checked; GOWORK is off, so a
// go.work above the root cannot either; GOAMD64, GOARM64 and GOEXPERIMENT are cleared, since each sets build
// tags (amd64.v3, goexperiment.X). GOENV is off, because the go command reads every one of those from the
// user's go env file (`go env -w`) when the environment leaves it empty; the file's settings for
// where modules come from and are kept, which select no file, are carried over (goFetchEnv).
func goEnv(c buildConfig) []string {
	cgo := "0"
	if c.cgo {
		cgo = "1"
	}
	var env []string
	for _, e := range os.Environ() {
		k, _, _ := strings.Cut(e, "=")
		switch k {
		case "GOOS", "GOARCH", "CGO_ENABLED", "GOFLAGS", "GOWORK", "GOENV", "GOAMD64", "GOARM64", "GOEXPERIMENT":
			continue
		}
		env = append(env, e)
	}
	env = append(env, goFetchEnv()...)
	return append(env, "GOOS="+c.goos, "GOARCH="+c.goarch, "CGO_ENABLED="+cgo, "GOFLAGS=", "GOWORK=off", "GOENV=off")
}

// fetchKeys are the go command's settings for where modules come from and where they and builds are kept: none
// selects a file, so a value the user keeps in the go env file still applies under goEnv's GOENV=off. (The
// resolved value is the environment's own when it sets one, and exec.Cmd keeps the last of duplicate entries.)
var fetchKeys = []string{"GOPATH", "GOMODCACHE", "GOCACHE", "GOPROXY", "GONOPROXY", "GOPRIVATE", "GONOSUMDB",
	"GOSUMDB", "GOINSECURE", "GOVCS", "GOAUTH"}

// goFetchEnv is fetchKeys as the go command resolves them in the host's own environment and go env file, read
// once. When `go env` fails it is empty, and a load that needs a file-kept setting then fails as it would.
var goFetchEnv = sync.OnceValue(func() []string {
	out, err := exec.Command(goTool(), append([]string{"env"}, fetchKeys...)...).Output()
	if err != nil {
		return nil
	}
	vals := strings.Split(strings.TrimSuffix(string(out), "\n"), "\n")
	if len(vals) != len(fetchKeys) {
		return nil
	}
	env := make([]string, len(fetchKeys))
	for i, k := range fetchKeys {
		env[i] = k + "=" + vals[i]
	}
	return env
})

// writeOverlay writes ov as a `go build -overlay` file under a temporary directory and returns its path; the
// caller removes the directory.
func writeOverlay(root string, ov overlay) (file, dir string, err error) {
	if len(ov) == 0 {
		return "", "", nil
	}
	dir, err = os.MkdirTemp("", "fdcheck-overlay-")
	if err != nil {
		return "", "", err
	}
	abs, err := filepath.Abs(root)
	if err != nil {
		return "", dir, err
	}
	repl := map[string]string{}
	i := 0
	for name, src := range ov {
		f := filepath.Join(dir, fmt.Sprintf("%d.go", i))
		i++
		if err := os.WriteFile(f, src, 0o644); err != nil {
			return "", dir, err
		}
		repl[filepath.Join(abs, filepath.FromSlash(name))] = f
	}
	js, err := json.Marshal(map[string]any{"Replace": repl})
	if err != nil {
		return "", dir, err
	}
	file = filepath.Join(dir, "overlay.json")
	return file, dir, os.WriteFile(file, js, 0o644)
}

// goList runs `go list -e -json` with args under c and decodes the packages.
func goList(root string, c buildConfig, ovFile string, args ...string) ([]listedPkg, error) {
	full := []string{"list", "-e", "-json=ImportPath,Dir,GoFiles,CgoFiles,Export,Standard,Module,Error"}
	if c.tags != "" {
		full = append(full, "-tags", c.tags)
	}
	if ovFile != "" {
		full = append(full, "-overlay", ovFile)
	}
	full = append(full, args...)
	cmd := exec.Command(goTool(), full...)
	cmd.Dir = root
	cmd.Env = goEnv(c)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("go list (%s): %v: %s", c.name, err, strings.TrimSpace(stderr.String()))
	}
	var pkgs []listedPkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPkg
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			return pkgs, nil
		} else if err != nil {
			return nil, fmt.Errorf("go list (%s): %w", c.name, err)
		}
		pkgs = append(pkgs, p)
	}
}

// typeCheck loads the module packages patterns name, and their module dependencies, under c, with ov standing in
// for the checkout's files.
func typeCheck(root string, c buildConfig, ov overlay, patterns []string) (*typedWorld, error) {
	ovFile, ovDir, err := writeOverlay(root, ov)
	if ovDir != "" {
		defer func() { _ = os.RemoveAll(ovDir) }()
	}
	if err != nil {
		return nil, err
	}
	listed, err := goList(root, c, ovFile, append([]string{"-deps"}, patterns...)...)
	if err != nil {
		return nil, err
	}
	// Export data for what the module imports from outside it; the module's own packages are checked here.
	var external []string
	for _, p := range listed {
		if !p.inModule() && p.ImportPath != "unsafe" && p.ImportPath != "C" {
			external = append(external, p.ImportPath)
		}
	}
	// The lenders and SysProcAttr's identity are read from syscall, which every world needs.
	if !contains(external, pathSyscall) {
		external = append(external, pathSyscall)
	}
	exports := map[string]string{}
	if len(external) > 0 {
		ext, err := goList(root, c, "", append([]string{"-export"}, external...)...)
		if err != nil {
			return nil, err
		}
		for _, p := range ext {
			if p.Error != nil {
				return nil, fmt.Errorf("%s (%s): %s", p.ImportPath, c.name, p.Error.Err)
			}
			exports[p.ImportPath] = p.Export
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	w := &typedWorld{cfg: c, fset: token.NewFileSet(), byPath: map[string]*typedPkg{},
		funcs: map[*types.Func]funcDecl{}, consts: map[*types.Const]ast.Expr{}, std: map[string]*types.Package{}}
	gc := importer.ForCompiler(w.fset, "gc", func(path string) (io.ReadCloser, error) {
		e := exports[path]
		if e == "" {
			return nil, fmt.Errorf("no export data for %s (%s)", path, c.name)
		}
		return os.Open(e)
	})
	w.imp = importerFunc(func(path string) (*types.Package, error) {
		if p := w.byPath[path]; p != nil {
			return p.types, nil
		}
		if strings.HasPrefix(path, modulePath+"/") || path == modulePath {
			return nil, fmt.Errorf("%s is not checked before its importer (%s)", path, c.name)
		}
		return gc.Import(path)
	})
	for _, std := range []string{pathSyscall, pathUnix} {
		if exports[std] != "" {
			p, err := w.imp.Import(std)
			if err != nil {
				return nil, err
			}
			w.std[std] = p
		}
	}
	for _, lp := range listed {
		if !lp.inModule() {
			continue
		}
		if len(lp.CgoFiles) > 0 {
			return nil, fmt.Errorf("%s imports \"C\" (%s): fdcheck does not check cgo files", lp.ImportPath, c.name)
		}
		if len(lp.GoFiles) == 0 {
			continue // every file is excluded under c (its build constraints), which coverage accounts for
		}
		if lp.Error != nil {
			return nil, fmt.Errorf("%s (%s): %s", lp.ImportPath, c.name, lp.Error.Err)
		}
		rel, err := filepath.Rel(absRoot, lp.Dir)
		if err != nil || strings.HasPrefix(rel, "..") {
			return nil, fmt.Errorf("%s: %s is outside %s", lp.ImportPath, lp.Dir, root)
		}
		tp := &typedPkg{path: lp.ImportPath, dir: filepath.ToSlash(rel)}
		for _, f := range lp.GoFiles {
			name := f
			if tp.dir != "." {
				name = tp.dir + "/" + f
			}
			src, ok := ov[name]
			if !ok {
				if src, err = os.ReadFile(filepath.Join(lp.Dir, f)); err != nil {
					return nil, err
				}
			}
			af, err := parser.ParseFile(w.fset, name, src, parser.ParseComments|parser.SkipObjectResolution)
			if err != nil {
				return nil, err
			}
			tp.names = append(tp.names, name)
			tp.files = append(tp.files, af)
		}
		tp.info = &types.Info{
			Types:      map[ast.Expr]types.TypeAndValue{},
			Defs:       map[*ast.Ident]types.Object{},
			Uses:       map[*ast.Ident]types.Object{},
			Selections: map[*ast.SelectorExpr]*types.Selection{},
			Implicits:  map[ast.Node]types.Object{},
		}
		var errs []string
		conf := types.Config{Importer: w.imp, Error: func(err error) {
			if len(errs) < 10 {
				errs = append(errs, err.Error())
			}
		}}
		tp.types, _ = conf.Check(tp.path, w.fset, tp.files, tp.info)
		if len(errs) > 0 {
			return nil, fmt.Errorf("%s does not type-check (%s):\n\t%s", tp.path, c.name, strings.Join(errs, "\n\t"))
		}
		w.pkgs = append(w.pkgs, tp)
		w.byPath[tp.path] = tp
		w.index(tp)
	}
	return w, nil
}

type importerFunc func(path string) (*types.Package, error)

func (f importerFunc) Import(path string) (*types.Package, error) { return f(path) }

// index records tp's function bodies and constants' values, which the lent-number check and the constant
// resolution follow into from any package of the world.
func (w *typedWorld) index(tp *typedPkg) {
	for _, f := range tp.files {
		for _, d := range f.Decls {
			switch x := d.(type) {
			case *ast.FuncDecl:
				if fn, ok := tp.info.Defs[x.Name].(*types.Func); ok && x.Body != nil {
					w.funcs[fn] = funcDecl{x, tp}
				}
			case *ast.GenDecl:
				for _, sp := range x.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, n := range vs.Names {
						if k, ok := tp.info.Defs[n].(*types.Const); ok && i < len(vs.Values) {
							w.consts[k] = vs.Values[i]
						}
					}
				}
			}
		}
	}
}

// pkgOf is the module package that declares obj's position, or nil.
func (w *typedWorld) pkgOf(obj types.Object) *typedPkg {
	if obj == nil || obj.Pkg() == nil {
		return nil
	}
	return w.byPath[obj.Pkg().Path()]
}

// measured is a measure of the tree: its findings under every configuration, and the in-scope files no
// configuration builds.
type measured struct {
	findings  []Finding
	uncovered []string
	edges     []string // the edge list of the main configurations (edges.go)
	decls     declSet  // each package's declarations, under any configuration (moveCheck)
}

// measureFiles type-checks the packages patterns name (the tree: ./...) at root under the main configurations,
// then under the extra ones for the packages that hold a file of scope the main ones do not build, and returns
// every finding (a site found under several configurations once) and the files of scope no configuration builds.
func measureFiles(root string, ov overlay, scope []string, prod Producers, patterns []string) (measured, error) {
	m := measured{decls: declSet{}}
	es := edgeSet{}
	covered := map[string]bool{}
	seen := map[string]bool{}
	judged := map[string]bool{}
	for _, f := range scope {
		judged[f] = true
	}
	add := func(w *typedWorld) {
		for _, p := range w.pkgs {
			for _, n := range p.names {
				covered[n] = true
			}
			if m.decls[p.dir] == nil {
				m.decls[p.dir] = map[string]bool{}
			}
			for _, f := range p.files {
				for _, d := range declSpans(f) {
					m.decls[p.dir][d.name] = true
				}
			}
		}
		for _, f := range analyzeWorld(w, prod) {
			if !judged[f.File] {
				continue // a file git does not list (ignored); its package is checked with it, as go builds it
			}
			if k := f.key(); !seen[k] {
				seen[k] = true
				m.findings = append(m.findings, f)
			}
		}
	}
	for _, c := range mainConfigs {
		w, err := typeCheck(root, c, ov, patterns)
		if err != nil {
			return m, err
		}
		add(w)
		es.add(w)
	}
	m.edges = es.lines()
	uncovered := func() []string {
		var out []string
		for _, f := range scope {
			if !covered[f] {
				out = append(out, f)
			}
		}
		return out
	}
	if rest := uncovered(); len(rest) > 0 {
		dirs := map[string]bool{}
		for _, f := range rest {
			dirs["./"+dirOf(f)] = true
		}
		extra := sortedKeys(dirs)
		for _, c := range extraConfigs {
			pkgs := extra
			if c.goos != "linux" {
				// Another system's build (listed after the Linux ones) reads only the packages that hold a file
				// still uncovered which it builds: a Linux package's other files need not compile there, and a
				// Linux file no build covers stays a problem.
				var err error
				if pkgs, err = buildsAny(root, c, ov, uncovered()); err != nil {
					return m, err
				}
				if len(pkgs) == 0 {
					continue
				}
			}
			w, err := typeCheck(root, c, ov, pkgs)
			if err != nil {
				return m, err
			}
			add(w)
		}
	}
	m.uncovered = uncovered()
	sortFindings(m.findings)
	return m, nil
}

// buildsAny is the packages ("./dir") that hold one of files which c builds, by the go command's file rules (the
// name's _GOOS and _GOARCH, the //go:build line), with ov's files read in place of the checkout's.
func buildsAny(root string, c buildConfig, ov overlay, files []string) ([]string, error) {
	ctx := build.Default
	ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = c.goos, c.goarch, c.cgo
	ctx.BuildTags = nil
	if c.tags != "" {
		ctx.BuildTags = strings.Split(c.tags, ",")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	byAbs := map[string][]byte{}
	for n, src := range ov {
		byAbs[filepath.Join(absRoot, filepath.FromSlash(n))] = src
	}
	ctx.OpenFile = func(path string) (io.ReadCloser, error) {
		if src, ok := byAbs[path]; ok {
			return io.NopCloser(bytes.NewReader(src)), nil
		}
		return os.Open(path)
	}
	dirs := map[string]bool{}
	for _, f := range files {
		d, base := filepath.Split(filepath.Join(absRoot, filepath.FromSlash(f)))
		ok, err := ctx.MatchFile(d, base)
		if err != nil {
			return nil, err
		}
		if ok {
			dirs["./"+dirOf(f)] = true
		}
	}
	return sortedKeys(dirs), nil
}

// inScope is the files fdcheck must judge among names: non-test Go files outside the exempt paths (A7).
func inScope(names []string) []string {
	var out []string
	for _, n := range names {
		if strings.HasSuffix(n, ".go") && !Exempt(n) {
			out = append(out, n)
		}
	}
	return out
}

func sortFindings(fs []Finding) {
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].File != fs[j].File {
			return fs[i].File < fs[j].File
		}
		if fs[i].Line != fs[j].Line {
			return fs[i].Line < fs[j].Line
		}
		if fs[i].Kind != fs[j].Kind {
			return fs[i].Kind < fs[j].Kind
		}
		return fs[i].off < fs[j].off
	})
}
