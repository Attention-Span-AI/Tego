// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

// input is everything the selection reads; load fills it from the tree, the tests by hand.
type input struct {
	base, mergeBase, root, module string
	changed                       []string // repo-relative, forward slashes
	graphs                        map[string]*graph
	facts                         facts
	codeBuilds                    map[string][]string // package -> module packages its own code names (scanCodeBuilds)
	exists                        func(rel string) bool
	hooksListed                   map[string]bool       // the directories the full gate's tegotesthooks step names
	hooksTagged                   func(dir string) bool // dir holds a test file behind tegotesthooks
}

// plan is the selection: per build, the packages to vet and test and the single tests to run.
type plan struct {
	mode            string // "full", "docs" or "scoped"
	base, mergeBase string
	reasons         []string // why the full gate (mode full)
	notes           []string // each changed file's class and effect
	vet             map[string]map[string]bool
	test            map[string]map[string]bool
	run             map[string]map[string]map[string]bool // tags -> dir -> tests
	why             map[string]string                     // "tags dir" -> why a test package was selected
	lint            map[string]bool
	shell           []string
}

// globalFiles and globalDirs are trap list (e): inputs of every package's build or of the gate itself.
var globalFiles = map[string]string{
	"go.mod": "the module's requirements", "go.sum": "the module's checksums", "go.work": "a workspace",
	"go.work.sum": "a workspace", "Makefile": "the gate's targets", ".golangci.yml": "the linters' config",
	".goreleaser.yaml": "the release build", "test/unit-skips.txt": "the unit skip list",
	"test/integration-skips.txt": "the integration skip list", ".gitignore": "the tree's file lists",
	".gitattributes": "the tree's file lists", "LICENSE": "check-licenses", "NOTICE": "check-licenses",
	"THIRD_PARTY_NOTICES.txt": "check-licenses",
	// Two test files test/vm/fetch-kernel_test.sh reads by name: scoped mode runs their tests, not that self-test.
	"internal/platform/peer/peer_test.go":                       "test/vm/fetch-kernel_test.sh reads rowsWithoutPeerPidfd",
	"internal/runtime/enforce/landlock/integration_abi_test.go": "test/vm/fetch-kernel_test.sh reads rowABIFloor",
	// m0-demo.sh copies it, through a variable no scan reads, and test/e2e/m0_demo_test.sh runs m0-demo.sh.
	"test/workloads/python-httpx/agent.py": "test/e2e/m0_demo_test.sh copies it",
	// A release asset beside the installers: scripts/precommit_test.sh holds .goreleaser.yaml to shipping it.
	"examples/lima/tego.yaml": "scripts/precommit_test.sh reads it as a release asset",
}

var globalDirs = map[string]string{
	".github/": "CI's workflows and owners", ".githooks/": "the commit hook", "scripts/": "the gate's scripts, run by the script self-tests and by tests",
	"test/vm/": "the KVM suites and their lists", "test/e2e/": "the shell self-tests read this directory", "tools/": "the static checks", "internal/testutil/": "every package's test helpers",
	"LICENSES/": "check-licenses", "bpf/": "the BPF sources the committed objects come from", "internal/bpf/": "the committed BPF objects (bpf-objects)",
	// Script self-test inputs outside the directories above (TestSelfTestFixturesAreGlobal holds the ones a self-test
	// names): scoped mode runs no self-test, so only the full gate's see a change here.
	"internal/control/web/testdata/edgelint/": "scripts/check-edgelint_test.sh lints it",
	"test/workloads/build/":                   "test/e2e/pydeps_test.sh and test/e2e/overhead/run_test.sh read it",
	// The demo safety self-tests copy whole kits, including assets read through shell variables.
	"examples/demo/":              "scripts/demo-reset_test.sh and scripts/cleanup-guards_test.sh copy it",
	"examples/supply-chain-demo/": "scripts/demo-credentials_test.sh and scripts/cleanup-guards_test.sh read it",
	"examples/live-modes-demo/":   "scripts/cleanup-guards_test.sh copies it",
}

func makePlan(in input) *plan {
	p := &plan{base: in.base, mergeBase: in.mergeBase, vet: map[string]map[string]bool{}, test: map[string]map[string]bool{},
		run: map[string]map[string]map[string]bool{}, why: map[string]string{}, lint: map[string]bool{}}
	src := map[string]bool{}   // packages whose own code changed (import paths)
	tests := map[string]bool{} // packages whose tests must run
	docsOnly := len(in.changed) > 0
	for _, f := range in.changed {
		cls, note := in.classify(f, src, tests, p)
		p.notes = append(p.notes, f+": "+note)
		switch cls {
		case "full":
			p.reasons = append(p.reasons, f+": "+note)
		case "docs":
		default:
			docsOnly = false
		}
	}
	switch {
	case len(p.reasons) > 0:
		p.mode = "full"
		return p
	case docsOnly:
		p.mode = "docs"
	default:
		p.mode = "scoped"
	}
	hooks := in.hooksPkgs()
	closure := map[string]bool{} // memo: module package -> its closure holds a changed package
	inClosure := func(b string) bool {
		if v, ok := closure[b]; ok {
			return v
		}
		v := src[b]
		for _, g := range in.graphs {
			if pk := g.pkgs[b]; pk != nil && intersects(pk.deps, src) {
				v = true
			}
		}
		closure[b] = v
		return v
	}
	for tags, g := range in.graphs {
		for path, pk := range g.pkgs {
			testing := contains(testTagSets, tags) && (tags != "tegotesthooks" || hooks[path])
			byCode := src[path] || intersects(pk.deps, src)
			byTest := pk.testDeps != nil && intersects(pk.testDeps, src)
			if p.mode == "scoped" && (byCode || byTest || tests[path]) {
				add(p.vet, tags, dirArg(pk.dir))
			}
			if !testing || pk.testDeps == nil {
				continue
			}
			why := ""
			switch {
			case byTest:
				why = "depends on the change"
			case tests[path]:
				why = "its tests or files changed, or its tests read a changed file"
			}
			if why == "" && p.mode == "scoped" {
				for _, b := range in.builds(tags, path, pk) {
					if inClosure(b) {
						why = "binary closure: its tests build or run " + b
						break
					}
				}
			}
			if f := in.facts[tags][path]; why == "" && f != nil && f.whole && (p.mode == "scoped" || f.docs) {
				why = "source scanner (whole package): " + f.why
			}
			if why != "" {
				add(p.test, tags, dirArg(pk.dir))
				p.why[tags+" "+dirArg(pk.dir)] = why
				continue
			}
			if f := in.facts[tags][path]; f != nil && len(f.tests) > 0 && (p.mode == "scoped" || f.docs) {
				for t := range f.tests {
					if p.run[tags] == nil {
						p.run[tags] = map[string]map[string]bool{}
					}
					add(p.run[tags], dirArg(pk.dir), t)
				}
				p.why[tags+" "+dirArg(pk.dir)] = "source scanner: " + f.why
			}
		}
	}
	p.lintAffected()
	return p
}

// lintAffected lints every package the vets cover, not only the changed directories: a change to one package
// (an enum value, a // Deprecated: line) can break the lint of an unchanged dependent (exhaustive, staticcheck's
// SA1019), which the full gate's ./... finds.
func (p *plan) lintAffected() {
	if p.mode != "scoped" {
		return
	}
	for _, dirs := range p.vet {
		for d := range dirs {
			p.lint[d] = true
		}
	}
}

// builds are the module packages a test package's tests name, and those its test binary's helpers name.
func (in input) builds(tags, path string, pk *pkg) []string {
	var out []string
	if f := in.facts[tags][path]; f != nil {
		out = append(out, f.builds...)
	}
	for dep := range pk.testDeps {
		out = append(out, in.codeBuilds[dep]...)
	}
	sort.Strings(out)
	return out
}

// classify records what one changed file selects and returns its class ("full", "docs" or another) and a note.
func (in input) classify(f string, src, tests map[string]bool, p *plan) (string, string) {
	base := path.Base(f)
	if why, ok := globalFiles[f]; ok {
		return "full", "global input (" + why + ")"
	}
	for d, why := range globalDirs {
		if strings.HasPrefix(f, d) {
			return "full", "global input (" + why + ")"
		}
	}
	if strings.HasSuffix(base, "_test.sh") {
		return "full", "a shell self-test: scripts/precommit_test.sh holds each one to ci.yml, and scoped mode runs neither"
	}
	if strings.HasSuffix(base, "_test.go") && in.hooksListDrifts(path.Dir(f)) {
		return "full", "the tegotesthooks directories no longer match the list scripts/precommit_test.sh holds to precommit.sh and ci.yml"
	}
	if (base == "go.mod" || base == "go.sum") && !hasSegment(f, "testdata") {
		return "full", "a nested module changes what ./... holds"
	}
	readers := in.readers(f)
	for _, r := range readers {
		tests[r] = true
	}
	if hasSegment(f, "testdata") {
		owner := in.owner(strings.TrimSuffix(f[:strings.Index("/"+f, "/testdata/")], "/"))
		if owner == "" && len(readers) == 0 {
			return "full", "testdata no package owns or names"
		}
		if owner != "" {
			tests[owner] = true
		}
		return "testdata", "testdata of " + orNone(owner) + readersNote(readers)
	}
	if embedders, testEmbedders := in.embedders(f); len(embedders)+len(testEmbedders) > 0 {
		for _, e := range embedders {
			src[e] = true
			p.lint[dirArg(in.dirOf(e))] = true
		}
		for _, e := range testEmbedders {
			tests[e] = true
		}
		return "embed", "embedded by " + strings.Join(append(embedders, testEmbedders...), ", ")
	}
	if strings.HasSuffix(f, ".go") {
		ip := in.pkgAt(path.Dir(f))
		if ip == "" {
			return "full", "a Go file of a directory no build lists as a package (a deleted, ignored or new-tagged package)"
		}
		p.lint[dirArg(path.Dir(f))] = true
		if strings.HasSuffix(f, "_test.go") {
			tests[ip] = true
			return "test", "tests of " + ip
		}
		src[ip] = true
		return "go", "source of " + ip
	}
	owner := in.owner(path.Dir(f))
	if strings.EqualFold(path.Ext(f), ".md") {
		if owner == "" || in.exists == nil || in.exists(f) {
			return "docs", "docs" + readersNote(readers)
		}
		// A deleted Markdown file under a package may have been embedded (go list no longer names it): docs mode
		// would build nothing, so it falls through to the deleted-file rule below.
	}
	if strings.HasSuffix(f, ".sh") {
		if owner == "" {
			return "full", "a shell script outside a Go package (the script self-tests run it)"
		}
		if in.exists == nil || in.exists(f) {
			p.shell = append(p.shell, f)
		}
	}
	if owner != "" {
		if in.exists != nil && !in.exists(f) {
			// A deleted file may have been embedded (go list no longer names it): count it as the owner's source.
			src[owner] = true
			p.lint[dirArg(in.dirOf(owner))] = true
			return "owned", "a deleted file of " + owner + ", counted as its source" + readersNote(readers)
		}
		tests[owner] = true
		return "owned", "a file of " + owner + readersNote(readers)
	}
	if len(readers) > 0 {
		return "read", "read by tests" + readersNote(readers)
	}
	return "full", "no package owns it and no test names it"
}

// hooksListDrifts says whether dir's place in the full gate's tegotesthooks list is out of step with the tree: a test
// file behind the tag in a directory the list leaves out, or the last one gone from a directory it names. A scoped run
// sees neither (scripts/precommit_test.sh does), and the fixed list would leave the first one's tests out of CI.
func (in input) hooksListDrifts(dir string) bool {
	return in.hooksTagged != nil && in.hooksTagged(dir) != in.hooksListed[dir]
}

// readers are the packages whose tests name f (or a directory above it) by a path literal, or read its part of
// the tree (knownReaders).
func (in input) readers(f string) []string {
	got := map[string]bool{}
	for _, byPkg := range in.facts {
		for ip, pf := range byPkg {
			for _, p := range pf.paths {
				if f == p || strings.HasPrefix(f, p+"/") {
					got[ip] = true
				}
			}
		}
	}
	for _, k := range knownReaders {
		if strings.HasPrefix(f, k.prefix) {
			if ip := in.pkgAt(k.dir); ip != "" {
				got[ip] = true
			}
		}
	}
	return sorted(got)
}

// owner is the package of dir or of the nearest directory above it, in any build.
func (in input) owner(dir string) string {
	for d := dir; d != "." && d != "/" && d != ""; d = path.Dir(d) {
		if ip := in.pkgAt(d); ip != "" {
			return ip
		}
	}
	return ""
}

func (in input) pkgAt(dir string) string {
	for _, tags := range tagSets {
		if g := in.graphs[tags]; g != nil {
			if ip, ok := g.byDir[dir]; ok {
				return ip
			}
		}
	}
	return ""
}

func (in input) dirOf(ip string) string {
	for _, g := range in.graphs {
		if pk := g.pkgs[ip]; pk != nil {
			return pk.dir
		}
	}
	return "."
}

func (in input) embedders(f string) (code, tests []string) {
	c, t := map[string]bool{}, map[string]bool{}
	for _, g := range in.graphs {
		for ip, pk := range g.pkgs {
			if contains(pk.embeds, f) {
				c[ip] = true
			}
			if contains(pk.testEmbeds, f) {
				t[ip] = true
			}
		}
	}
	return sorted(c), sorted(t)
}

// hooksPkgs are the packages with test files only a tegotesthooks build compiles: the ones precommit tests with
// that tag.
func (in input) hooksPkgs() map[string]bool {
	out := map[string]bool{}
	h, d := in.graphs["tegotesthooks"], in.graphs[""]
	if h == nil {
		return out
	}
	for ip, pk := range h.pkgs {
		var plain []string
		if d != nil && d.pkgs[ip] != nil {
			plain = d.pkgs[ip].testFiles
		}
		for _, f := range pk.testFiles {
			if !contains(plain, f) {
				out[ip] = true
			}
		}
	}
	return out
}

func readersNote(r []string) string {
	if len(r) == 0 {
		return ""
	}
	return "; named by the tests of " + strings.Join(r, ", ")
}

func orNone(s string) string {
	if s == "" {
		return "no package"
	}
	return s
}

func hasSegment(f, seg string) bool { return strings.Contains("/"+f, "/"+seg+"/") }

func dirArg(dir string) string {
	if dir == "." {
		return "."
	}
	return "./" + dir
}

func intersects(a, b map[string]bool) bool {
	if len(b) < len(a) {
		a, b = b, a
	}
	for k := range a {
		if b[k] {
			return true
		}
	}
	return false
}

func contains(xs []string, x string) bool {
	for _, y := range xs {
		if y == x {
			return true
		}
	}
	return false
}

func add(m map[string]map[string]bool, k, v string) {
	if m[k] == nil {
		m[k] = map[string]bool{}
	}
	m[k][v] = true
}

func tagArg(tags string) string {
	if tags == "" {
		return "-"
	}
	return tags
}

func tagName(tags string) string {
	if tags == "" {
		return "default"
	}
	return tags
}

// runs groups a build's single tests into one -run regex over the packages that hold them.
func (p *plan) runs(tags string) (string, []string) {
	names, dirs := map[string]bool{}, map[string]bool{}
	for d, ts := range p.run[tags] {
		dirs[d] = true
		for t := range ts {
			names[t] = true
		}
	}
	if len(dirs) == 0 {
		return "", nil
	}
	return "^(" + strings.Join(sorted(names), "|") + ")$", sorted(dirs)
}

// writePlan prints the directives scripts/precommit.sh reads.
func (p *plan) writePlan(w io.Writer) {
	fmt.Fprintf(w, "mode %s\n", p.mode)
	for _, r := range p.reasons {
		fmt.Fprintf(w, "reason %s\n", r)
	}
	if p.mode == "full" {
		return
	}
	for _, tags := range vetTagSets {
		if v := sorted(p.vet[tags]); len(v) > 0 {
			fmt.Fprintf(w, "vet %s %s\n", tagArg(tags), strings.Join(v, " "))
		}
	}
	// The integration build last: precommit runs it after the other two, and prints in this order.
	for _, tags := range []string{"", "tegotesthooks", "integration"} {
		if t := sorted(p.test[tags]); len(t) > 0 {
			fmt.Fprintf(w, "test %s %s\n", tagArg(tags), strings.Join(t, " "))
		}
		if re, dirs := p.runs(tags); re != "" {
			fmt.Fprintf(w, "run %s %s %s\n", tagArg(tags), re, strings.Join(dirs, " "))
		}
	}
	if l := sorted(p.lint); len(l) > 0 {
		fmt.Fprintf(w, "lint %s\n", strings.Join(l, " "))
	}
	if len(p.shell) > 0 {
		sh := append([]string{}, p.shell...)
		sort.Strings(sh)
		fmt.Fprintf(w, "shell %s\n", strings.Join(sh, " "))
	}
}

// writeExplain prints what was selected and why, for the reader of the run's log.
func (p *plan) writeExplain(w io.Writer) {
	fmt.Fprintf(w, "affected: %d changed file(s) since the merge base %.12s of HEAD and %s\n", len(p.notes), p.mergeBase, p.base)
	for _, n := range p.notes {
		fmt.Fprintf(w, "  %s\n", n)
	}
	switch p.mode {
	case "full":
		fmt.Fprintln(w, "affected: mode full: a global input changed, so every step runs on every package:")
		for _, r := range p.reasons {
			fmt.Fprintf(w, "  %s\n", r)
		}
		return
	case "docs":
		fmt.Fprintln(w, "affected: mode docs: Markdown alone changed; rulecheck, check-spdx and the tests that read Markdown")
	default:
		fmt.Fprintln(w, "affected: mode scoped: the packages the change reaches, the binary closure and the source scanners")
	}
	for _, tags := range vetTagSets {
		if v := sorted(p.vet[tags]); len(v) > 0 {
			fmt.Fprintf(w, "vet [%s]: %d package(s): %s\n", tagName(tags), len(v), strings.Join(v, " "))
		}
	}
	for _, tags := range testTagSets {
		t := sorted(p.test[tags])
		if len(t) > 0 {
			fmt.Fprintf(w, "test [%s]: %d package(s):\n", tagName(tags), len(t))
			for _, d := range t {
				fmt.Fprintf(w, "  %s  (%s)\n", d, p.why[tags+" "+d])
			}
		}
		if re, dirs := p.runs(tags); re != "" {
			fmt.Fprintf(w, "run [%s] %s in:\n", tagName(tags), re)
			for _, d := range dirs {
				fmt.Fprintf(w, "  %s  (%s)\n", d, p.why[tags+" "+d])
			}
		}
	}
	if l := sorted(p.lint); len(l) > 0 {
		fmt.Fprintf(w, "lint: %s\n", strings.Join(l, " "))
	}
	if len(p.shell) > 0 {
		fmt.Fprintf(w, "shellcheck: %s\n", strings.Join(p.shell, " "))
	}
}
