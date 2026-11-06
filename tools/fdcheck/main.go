// SPDX-License-Identifier: Apache-2.0

// Command fdcheck holds ADR 0023's descriptor rules where forbidigo cannot (its 2026-10-05 note, A9 and A10,
// F1–F11), on type-checked packages (the standard library's go/types, over the export data `go list -export`
// builds; gopkg.in/yaml.v3 reads .golangci.yml):
//
//	F1   a fresh number becomes an owner in the expression that creates it: sys.Own around a direct call of a
//	     producer (producers.txt, generated from x/sys/unix and syscall), sys.OwnSyscall around an admitted raw
//	     syscall, or a sys helper; any other producer call, or a producer taken as a value, is a raw site
//	F2   a Hold is followed, past its error check and in its block, by its deferred Return (outside a loop) or
//	     by its hand-off to a goroutine that returns it by defer first, and is returned no other way;
//	     a *sys.Lease is never stored; a lent number (a lender's callback parameter, a Lease's Num) is used
//	     only in the closed set of ways lent.go admits, and a callback fdcheck cannot follow is refused
//	F3   ReleaseNumber's number goes to one taker (link.NewFromFD, ebpf.NewMapFromFD, ebpf.NewProgramFromFD), in
//	     the statement after the release's error check
//	F4   Adopt, Abandon, Inherited, Stdio and CloseInheritedFrom only at the sites adopt.txt, abandon.txt,
//	     inherited.txt, stdio.txt and sweep.txt list; InertForTest only in tests; other *ForTest accessors only
//	     in tests and testhooks files
//	F5   every call, method value and method expression of an Fd or FD method (an embedded *os.File, an
//	     interface{ Fd() uintptr }, cilium's FD), a Syscall whose trap is not a SYS_ constant, an fcntl command or
//	     ioctl request (raw, or through any x/sys Ioctl wrapper) outside its allowlist, unshare(CLONE_FILES)
//	F6   every non-test file is type-checked under a build configuration that builds it (load.go); a file no
//	     configuration builds is a problem
//	F7   the ratchet (A9): baseline.txt counts each unmigrated package's raw sites by kind, exactly; a package
//	     not listed has none; the list and .golangci.yml's per-package ADR 0023 exclusions name the same packages
//	F8   an exported API takes or returns a bare number named fd, ...fd or ...FD (or an unnamed one from a
//	     function named ...FD) only in a package the baseline still lists, and only such a package uses another
//	     package's (A6's edge list, edges.txt)
//	F9   an owned producer's flags are a constant expression carrying its CLOEXEC flag, and a recvmsg with a
//	     control buffer carries MSG_CMSG_CLOEXEC
//	F10  sys.OwnSyscall's admitted (trap, command or flags) pairs
//	F11  no product binary (./cmd/... under the four tag sets, for amd64 and arm64, and amd64 with cgo) links
//	     internal/testutil, tools, test or a testdata fixture
//
// The A4 primitives (close, dup, os.NewFile, Fd, ParseUnixRights and the control-message decoders, SCM_RIGHTS,
// io_uring, cilium's *FromFD) are counted too, by
// the objects they are, so the ratchet holds whatever golangci-lint reports: fdcheck reads no nolint comment as
// leave to skip a site, and counts a nolint directive that silences forbidigo as a site itself (kind nolint), since
// it hides forbidigo's reports from the lint. .golangci.yml must keep forbidigo on, typed, linting
// generated files, with every report failing the run and the lint's build tags kept, and excluded only where A7
// and A9 say (ParseShrinking); and no .golangci.json, .toml or .yaml at the root may shadow it (golangciShadow).
// The files are the ones git lists, tracked or untracked but not ignored, so worktree copies are never read.
// Exempt (A7): _test.go files, internal/testutil, tools, test, testdata fixtures, the sys owner's files and
// internal/bpf/fdborrow.go.
//
// Usage:
//
//	go run ./tools/fdcheck [-base REV] [root]   check (root defaults to the working directory)
//	go run ./tools/fdcheck -baseline [root]     print the measured baseline (to write baseline.txt)
//	go run ./tools/fdcheck -list [root]         print every raw site, the listed packages' included
//	go run ./tools/fdcheck -edges -w [root]     regenerate edges.txt
//	go run ./tools/fdcheck -producers -w [root] regenerate producers.txt
//
// -base REV also holds each kind's total, each package's count of each kind (a rise only by sites moved from
// another package), and the F4 lists', to REV's (A9's total check; precommit passes the merge base with main,
// CI's bench-gate job the push's base).
//
// Exit: 0 when every rule holds; 1 when one does not; 2 on a read, parse or tool error.
//
// Imports: the standard library and gopkg.in/yaml.v3 (in go.mod already). It runs `go list` and git.
package main

import (
	"archive/tar"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	fl := flag.NewFlagSet("fdcheck", flag.ContinueOnError)
	fl.SetOutput(stderr)
	base := fl.String("base", "", "hold each kind's total, and the F4 lists', to this revision's")
	printBaseline := fl.Bool("baseline", false, "print the measured baseline and exit")
	listAll := fl.Bool("list", false, "print every raw site, listed packages' included, and exit")
	edges := fl.Bool("edges", false, "with -w, regenerate edges.txt")
	producers := fl.Bool("producers", false, "with -w, regenerate producers.txt")
	write := fl.Bool("w", false, "write the generated file -edges or -producers names")
	if err := fl.Parse(args); err != nil {
		return 2
	}
	root := "."
	if fl.NArg() > 0 {
		root = fl.Arg(0)
	}
	fail := func(err error) int {
		fmt.Fprintln(stderr, "fdcheck:", err)
		return 2
	}
	switch {
	case *producers || *edges:
		if !*write {
			return fail(fmt.Errorf("-producers and -edges write their file: add -w"))
		}
		var content []byte
		var name string
		var err error
		if *producers {
			name = "producers.txt"
			content, err = generatedProducers(root)
		} else {
			name = "edges.txt"
			content, err = generatedEdges(root)
		}
		if err != nil {
			return fail(err)
		}
		if err := os.WriteFile(filepath.Join(root, "tools", "fdcheck", name), content, 0o644); err != nil {
			return fail(err)
		}
		return 0
	case *printBaseline || *listAll:
		m, _, err := measure(root, nil)
		if err != nil {
			return fail(err)
		}
		if *listAll {
			for _, f := range m.findings {
				fmt.Fprintln(stdout, f)
			}
			return 0
		}
		cfg, err := loadConfig(root)
		if err != nil {
			return fail(err)
		}
		_, _ = stdout.Write(FormatBaseline(MeasuredBaseline(cfg.Sites, m.findings)))
		return 0
	}
	problems, err := Check(root, *base, nil)
	if err != nil {
		return fail(err)
	}
	for _, p := range problems {
		fmt.Fprintln(stdout, "fdcheck:", p)
	}
	if len(problems) > 0 {
		fmt.Fprintf(stdout, "fdcheck: %d problems (ADR 0023; CONTRIBUTING.md says how to make a number an owner)\n", len(problems))
		return 1
	}
	return 0
}

// goTool is the go command fdcheck runs for `go list` and `go env`: $GO when set, as scripts/check-fd.sh and the
// Makefile pass it, so the producer list and F11 come from the toolchain that runs fdcheck; else go on PATH.
func goTool() string {
	if g := os.Getenv("GO"); g != "" {
		return g
	}
	return "go"
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
	if len(files) == 0 {
		return nil, fmt.Errorf("git listed no Go file under %s; nothing was checked", root)
	}
	return files, nil
}

func readFile(root, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, "tools", "fdcheck", name))
}

// readProducers loads producers.txt.
func readProducers(root string) (Producers, error) {
	ps, err := readFile(root, "producers.txt")
	if err != nil {
		return Producers{}, err
	}
	return ParseProducers(ps)
}

// measure type-checks and analyses the checkout at root, with ov's files standing in for (or added to) the
// checkout's, under every build configuration (load.go).
func measure(root string, ov overlay) (measured, Producers, error) {
	names, err := listGo(root)
	if err != nil {
		return measured{}, Producers{}, err
	}
	var present []string
	for _, n := range names {
		if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(n))); err == nil {
			present = append(present, n) // git lists a tracked file deleted from the working tree; no build has it
		} else if !errors.Is(err, fs.ErrNotExist) {
			return measured{}, Producers{}, err
		}
	}
	names = present
	for n := range ov {
		if !contains(names, n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	prod, err := readProducers(root)
	if err != nil {
		return measured{}, Producers{}, err
	}
	m, err := measureFiles(root, ov, inScope(names), prod, []string{"./..."})
	return m, prod, err
}

// uncoveredProblems names the files no build configuration builds (F6): fdcheck cannot judge them, so they fail.
func uncoveredProblems(files []string) []string {
	var out []string
	for _, f := range files {
		out = append(out, fmt.Sprintf("%s: no build configuration fdcheck type-checks builds this file (linux/amd64 and arm64, with the lint's tags and without, cgo, s390x, darwin/arm64), so fdcheck cannot judge it (ADR 0023 F6): give it a constraint one of them meets, or move it under an exempt path", f))
	}
	return out
}

// Check runs every rule on the checkout at root, with ov's files laid over it (a test's planted sites; nil for the
// gate), and returns the problems.
func Check(root, base string, ov overlay) ([]string, error) {
	m, prod, err := measure(root, ov)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(root)
	if err != nil {
		return nil, err
	}
	problems := append(uncoveredProblems(m.uncovered), Ratchet(cfg, m.findings)...)

	// producers.txt and edges.txt are what generation gives today.
	wantProd, err := generatedProducers(root)
	if err != nil {
		return nil, err
	}
	if haveProd, _ := readFile(root, "producers.txt"); !bytes.Equal(haveProd, wantProd) {
		problems = append(problems, "tools/fdcheck/producers.txt is stale (x/sys or the toolchain changed): run `go run ./tools/fdcheck -producers -w` and review the diff")
	}
	if haveEdges, _ := readFile(root, "edges.txt"); !bytes.Equal(haveEdges, FormatEdges(m.edges)) {
		problems = append(problems, "tools/fdcheck/edges.txt is stale: run `go run ./tools/fdcheck -edges -w`")
	}
	problems = append(problems, edgeProblems(m.edges, cfg.Baseline)...)

	// A9's total check against a base revision.
	if base != "" {
		p, err := totalCheck(root, base, prod, cfg, m.findings, m.decls)
		if err != nil {
			return nil, err
		}
		problems = append(problems, p...)
	}

	// F11.
	reach, err := Reach(root)
	if err != nil {
		return nil, err
	}
	return append(problems, reach...), nil
}

// loadConfig reads what the checked-in files say: baseline.txt, the F4 lists and .golangci.yml's per-package
// exclusions.
func loadConfig(root string) (Config, error) {
	var cfg Config
	bs, err := readFile(root, "baseline.txt")
	if err != nil {
		return cfg, err
	}
	if cfg.Baseline, err = ParseBaseline(bs); err != nil {
		return cfg, err
	}
	cfg.Sites = map[string]map[[2]string]int{}
	for kind, name := range listedKinds {
		src, err := readFile(root, name)
		if err != nil {
			return cfg, err
		}
		if cfg.Sites[kind], err = ParseSites(name, src); err != nil {
			return cfg, err
		}
	}
	if err := golangciShadow(root); err != nil {
		return cfg, err
	}
	gc, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		return cfg, err
	}
	cfg.Shrinking, err = ParseShrinking(gc)
	return cfg, err
}

// golangciShadows are the names golangci-lint's configuration search tries before .golangci.yml in the same
// directory (viper's order is json, toml, yaml, yml): one at the root is the configuration of every run
// without --config, and ParseShrinking would judge a file golangci-lint does not read.
var golangciShadows = []string{".golangci.json", ".golangci.toml", ".golangci.yaml"}

// golangciShadow fails when one of golangciShadows is at the root, tracked or not: the gate's own runs pass
// --config .golangci.yml, but `golangci-lint run` and an editor's run would read the other file.
func golangciShadow(root string) error {
	for _, n := range golangciShadows {
		if _, err := os.Lstat(filepath.Join(root, n)); err == nil {
			return fmt.Errorf("%s: golangci-lint reads it before .golangci.yml, which fdcheck checks (ADR 0023 A4); remove it and keep the configuration in .golangci.yml", n)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
}

// generatedEdges type-checks the checkout under the main configurations and generates edges.txt's content.
func generatedEdges(root string) ([]byte, error) {
	es := edgeSet{}
	for _, c := range mainConfigs {
		w, err := typeCheck(root, c, nil, []string{"./..."})
		if err != nil {
			return nil, err
		}
		es.add(w)
	}
	return FormatEdges(es.lines()), nil
}

// totalCheck holds the checkout to base (A9's total check, by kind): each kind's total over every package never
// rises, so a move of code moves its counts but a removed close cannot pay for a new os.NewFile, in its package
// or another; each package's count of a kind rises only by sites moved from another with the declaration they
// are in (moveCheck); and the F4
// lists together admit more sites than base's only when the raw total fell by at least as much (a migration
// that turns raw sites into listed ones pays for its entries). The base is measured, its tree extracted from git
// and type-checked and analysed by these rules with its own lists, not read from its baseline.txt: a rule that
// counts more on unchanged code counts it on both sides, and the base's file cannot be wrong. A base with
// no baseline.txt (before ADR 0023 C3) has no total to hold, and the check says so.
func totalCheck(root, base string, prod Producers, cur Config, curFindings []Finding, curDecls declSet) ([]string, error) {
	b, err := measureBase(root, base, prod)
	if err != nil {
		return nil, err
	}
	return holdToBase(b, cur, curFindings, curDecls), nil
}

// baseMeasure is a base revision as the checkout's rules measure it: its findings and its F4 lists. none is set
// when the base has no baseline.txt (before ADR 0023 C3), which leaves nothing to hold.
type baseMeasure struct {
	rev      string
	none     bool
	retagged bool // none because the base's lint builds its tagged files under other tag names than lintTags
	sites    map[string]map[[2]string]int
	findings []Finding
	decls    declSet
}

// measureBase extracts base's tree and measures it.
func measureBase(root, base string, prod Producers) (baseMeasure, error) {
	b := baseMeasure{rev: base, sites: map[string]map[[2]string]int{}}
	if _, ok, err := showAt(root, base, "baseline.txt"); err != nil || !ok {
		b.none = true
		return b, err
	}
	// A base whose lint builds its tagged files under other tag names (before ADR 0060 renamed them) cannot be
	// measured with this checkout's build configurations: its tagged files would drop out and its packages fail to
	// type-check. Its total is not held; the check starts at the commit that renamed the tags.
	if src, ok, err := showPath(root, base, ".golangci.yml"); err != nil {
		return b, err
	} else if tags, perr := golangciBuildTags(src); ok && perr == nil && !containsAll(tags, lintTags) {
		b.none, b.retagged = true, true
		return b, nil
	}
	for kind, name := range listedKinds {
		src, ok, err := showAt(root, base, name)
		if err != nil {
			return b, err
		}
		b.sites[kind] = map[[2]string]int{}
		if ok { // a list base does not have yet admits nothing there
			if b.sites[kind], err = ParseSites(name, src); err != nil {
				return b, fmt.Errorf("%s's %w", base, err)
			}
		}
	}
	dir, names, err := extractAt(root, base)
	if dir != "" {
		defer func() { _ = os.RemoveAll(dir) }()
	}
	if err != nil {
		return b, err
	}
	m, err := measureFiles(dir, nil, inScope(names), prod, []string{"./..."})
	if err != nil {
		return b, fmt.Errorf("%s: %w", base, err)
	}
	b.findings, b.decls = m.findings, m.decls
	return b, nil
}

// holdToBase is A9's total check of the checkout's counts, lists and declarations against a measured base.
func holdToBase(b baseMeasure, cur Config, curFindings []Finding, curDecls declSet) []string {
	if b.retagged {
		fmt.Fprintf(os.Stderr, "fdcheck: %s's .golangci.yml builds its tagged files under other tags than %s; the total check starts at the commit that renamed them (ADR 0060)\n", b.rev, strings.Join(lintTags, ","))
		return nil
	}
	if b.none {
		fmt.Fprintf(os.Stderr, "fdcheck: %s has no tools/fdcheck/baseline.txt; the total check starts at the commit that adds it\n", b.rev)
		return nil
	}
	base := b.rev
	was := MeasuredBaseline(b.sites, b.findings)
	var problems []string
	curK, wasK := cur.Baseline.KindTotals(), was.KindTotals()
	for _, k := range sortedKeys(curK) {
		if curK[k] > wasK[k] {
			problems = append(problems, fmt.Sprintf("tools/fdcheck/baseline.txt: %s sites total %d across packages, %s's %d: no kind's total ever rises (ADR 0023 A9; a move of code moves its counts, and a site of another kind removed cannot pay for it)",
				k, curK[k], base, wasK[k]))
		}
	}
	wasRaw, _ := admit(b.sites, b.findings)
	curRaw, _ := admit(cur.Sites, curFindings)
	problems = append(problems, moveCheck(base, wasRaw, curRaw, b.decls, curDecls)...)
	listed, wasListed := 0, 0
	for kind := range listedKinds {
		for _, n := range cur.Sites[kind] {
			listed += n
		}
		for _, n := range b.sites[kind] {
			wasListed += n
		}
	}
	if fell := max(was.Total()-cur.Baseline.Total(), 0); listed-wasListed > fell {
		problems = append(problems, fmt.Sprintf("tools/fdcheck: the F4 lists admit %d sites, %s's %d, and the raw total fell by %d: a listed site is paid for by the raw sites the same change removes (ADR 0023 A9, F4)",
			listed, base, wasListed, fell))
	}
	return problems
}

// siteID is a raw site's identity across packages: its kind, its enclosing declaration and its form (the
// finding's What, the primitive it names). A move of code keeps all three. At package level the declaration is
// named by the names it declares (funcName). A name a package does not declare once (init, main, the blank
// identifier alone) carries its package too, so its sites never move between packages: moving one means moving
// its code into a named declaration.
type siteID struct{ kind, fn, what string }

func siteOf(f Finding) siteID {
	fn := f.Func
	if !movable(fn) {
		fn = f.Pkg + ":" + fn
	}
	return siteID{f.Kind, fn, f.What}
}

// movable is whether a declaration's name names one declaration in its package: not init, main, a bare
// "<package>", or a package-level spec of blank identifiers only (`var _ = ...`).
func movable(fn string) bool {
	switch fn {
	case "init", "main", "<package>":
		return false
	}
	if names, ok := strings.CutPrefix(fn, "<package>:"); ok {
		for _, n := range strings.Split(names, ",") {
			if n != "_" {
				return true
			}
		}
		return false
	}
	return true
}

// declSet is each package's declarations by the names sites carry (declSpans): package directory -> names.
type declSet map[string]map[string]bool

// moveCheck holds each package's count of each kind to base's (A9): a count rises only by sites moved from
// another package, each matched by its siteID to a site that left one, and only when the declaration it is in
// moved with it: base's source package declared it and the checkout's does not, and the checkout's destination
// package declares it and base's did not. So a new raw site in one listed package cannot ride on a same-kind
// migration in another, nor on a site taken out of a same-named declaration that stays (the round-2 note's
// residual of functions of the same name in two packages). Within one package a new site can still stand in for
// a migrated one of the same kind; that is the ratchet's residual (the per-package count does not rise).
func moveCheck(base string, was, cur []Finding, wasDecls, curDecls declSet) []string {
	type pkgSite struct {
		pkg string
		id  siteID
	}
	type pkgKind struct{ pkg, kind string }
	wasN, curN := map[pkgSite]int{}, map[pkgSite]int{}
	wasK, curK := map[pkgKind]int{}, map[pkgKind]int{}
	for _, f := range was {
		wasN[pkgSite{f.Pkg, siteOf(f)}]++
		wasK[pkgKind{f.Pkg, f.Kind}]++
	}
	for _, f := range cur {
		curN[pkgSite{f.Pkg, siteOf(f)}]++
		curK[pkgKind{f.Pkg, f.Kind}]++
	}
	left := map[siteID]int{} // sites that left a package with their declaration, available to explain a gain
	for k, n := range wasN {
		if d := n - curN[k]; d > 0 && wasDecls[k.pkg][k.id.fn] && !curDecls[k.pkg][k.id.fn] {
			left[k.id] += d
		}
	}
	gained := map[pkgKind][]pkgSite{}
	for k, n := range curN {
		if n > wasN[k] {
			pk := pkgKind{k.pkg, k.id.kind}
			gained[pk] = append(gained[pk], k)
		}
	}
	arrived := func(k pkgSite) bool { return curDecls[k.pkg][k.id.fn] && !wasDecls[k.pkg][k.id.fn] }
	var rising []pkgKind
	for pk, n := range curK {
		if n > wasK[pk] {
			rising = append(rising, pk)
		}
	}
	sort.Slice(rising, func(i, j int) bool {
		if rising[i].pkg != rising[j].pkg {
			return rising[i].pkg < rising[j].pkg
		}
		return rising[i].kind < rising[j].kind
	})
	var problems []string
	for _, pk := range rising {
		rise, moved := curK[pk]-wasK[pk], 0
		g := gained[pk]
		sort.Slice(g, func(i, j int) bool {
			if g[i].id.fn != g[j].id.fn {
				return g[i].id.fn < g[j].id.fn
			}
			return g[i].id.what < g[j].id.what
		})
		var unmoved []string
		for _, k := range g {
			take := 0
			if arrived(k) {
				take = min(curN[k]-wasN[k], left[k.id], rise-moved)
			}
			left[k.id] -= take
			moved += take
			if take < curN[k]-wasN[k] {
				unmoved = append(unmoved, k.id.fn+" ("+k.id.what+")")
			}
		}
		if moved < rise {
			problems = append(problems, fmt.Sprintf("tools/fdcheck/baseline.txt: %s has %d %s sites, %s's %d, and only %d of the rise moved from another package (new: %s): a package's count rises only by a site moved with its kind, form and the declaration it is in, which leaves the one package and arrives in the other, so a new raw site cannot ride on a migration elsewhere (ADR 0023 A9)",
				pk.pkg, curK[pk], pk.kind, base, wasK[pk], moved, strings.Join(unmoved, ", ")))
		}
	}
	return problems
}

// extractAt writes rev's tracked tree (git's archive of it) into a new temporary directory, for the base's
// measure, and lists its Go files. The caller removes the directory.
func extractAt(root, rev string) (dir string, goFiles []string, err error) {
	dir, err = os.MkdirTemp("", "fdcheck-base-")
	if err != nil {
		return "", nil, err
	}
	cmd := exec.Command("git", "-C", root, "archive", "--format=tar", rev)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return dir, nil, err
	}
	if err := cmd.Start(); err != nil {
		return dir, nil, err
	}
	goFiles, terr := untar(out, dir)
	if terr != nil {
		_, _ = io.Copy(io.Discard, out)
	}
	if err := cmd.Wait(); err != nil {
		return dir, nil, fmt.Errorf("git archive %s: %v: %s", rev, err, strings.TrimSpace(stderr.String()))
	}
	if terr != nil {
		return dir, nil, fmt.Errorf("git archive %s: %w", rev, terr)
	}
	sort.Strings(goFiles)
	return dir, goFiles, nil
}

// untar writes a tar stream's directories, files and symbolic links under dir, refusing a name that leaves it,
// and returns the Go files' names.
func untar(r io.Reader, dir string) ([]string, error) {
	tr := tar.NewReader(r)
	var goFiles []string
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			// The reader stops at the end-of-archive marker, and git archive pads its stream past it to a whole
			// 10240-byte record, 8704 bytes after a small tree's marker. Left unread they block git once its pipe
			// is smaller, as a user's new pipes are (8192 bytes) when the user is over fs.pipe-user-pages-soft, and
			// extractAt's Wait never returned: TestTotalCheck hung for its whole 10-minute timeout (2026-11-06).
			if _, err := io.Copy(io.Discard, r); err != nil {
				return nil, err
			}
			return goFiles, nil
		}
		if err != nil {
			return nil, err
		}
		name := filepath.Clean(filepath.FromSlash(h.Name))
		if !filepath.IsLocal(name) {
			return nil, fmt.Errorf("%q leaves the tree", h.Name)
		}
		dst := filepath.Join(dir, name)
		switch h.Typeflag {
		case tar.TypeDir:
			err = os.MkdirAll(dst, 0o755)
		case tar.TypeReg:
			if err = os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
				var f *os.File
				if f, err = os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644); err == nil {
					_, err = io.Copy(f, tr)
					if cerr := f.Close(); err == nil {
						err = cerr
					}
				}
			}
			if strings.HasSuffix(h.Name, ".go") {
				goFiles = append(goFiles, filepath.ToSlash(name))
			}
		case tar.TypeSymlink:
			if err = os.MkdirAll(filepath.Dir(dst), 0o755); err == nil {
				err = os.Symlink(h.Linkname, dst)
			}
		}
		if err != nil {
			return nil, err
		}
	}
}

// showAt is tools/fdcheck/name at rev; ok is false when rev has no such file.
func showAt(root, rev, name string) ([]byte, bool, error) {
	return showPath(root, rev, "tools/fdcheck/"+name)
}

// showPath is the file at path, from the repository's root, at rev: ok is false when rev's tree has no such file.
func showPath(root, rev, path string) (out []byte, ok bool, err error) {
	cmd := exec.Command("git", "-C", root, "show", rev+":"+path)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err = cmd.Output()
	if err != nil {
		if strings.Contains(stderr.String(), "does not exist") || strings.Contains(stderr.String(), "exists on disk, but not in") {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("git show %s:%s: %v: %s", rev, path, err, strings.TrimSpace(stderr.String()))
	}
	return out, true, nil
}
