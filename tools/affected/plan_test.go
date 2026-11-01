// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

const mod = "github.com/attention-span-ai/tego"

// tegoDir is cmd/tego's directory argument, spelled so tools/isocheck (GO-3, GO-4) does not read the fixture as a
// test that builds the binary.
const tegoDir = "./cmd/" + "tego"

type pk struct {
	dir        string
	main       bool
	deps       []string // repo-relative dirs
	tests      bool
	testFiles  []string // names in dir
	embeds     []string
	testEmbeds []string
}

// fixture builds a small module like this one: cmd/tego over internal/cli, internal/runtime and its supervisor;
// cmd/tego-control over internal/control (which embeds its web files); askclient, whose test reads the tree;
// supply-chain-demo and web/e2e, whose integration tests build the binaries; a tegotesthooks-only test in
// internal/bpf and internal/cli.
func fixture() input {
	common := []pk{
		{dir: "cmd/tego", main: true, deps: []string{"internal/cli", "internal/runtime", "internal/runtime/supervisor"}, tests: true, testFiles: []string{"main_test.go"}},
		{dir: "cmd/tego-control", main: true, deps: []string{"internal/control"}},
		{dir: "internal/cli", deps: []string{"internal/runtime", "internal/runtime/supervisor"}, tests: true, testFiles: []string{"cli_test.go"}},
		{dir: "internal/runtime", deps: []string{"internal/runtime/supervisor"}, tests: true, testFiles: []string{"run_test.go"}},
		{dir: "internal/runtime/supervisor", tests: true, testFiles: []string{"sup_test.go"}},
		{dir: "internal/askclient", tests: true, testFiles: []string{"imports_test.go"}},
		{dir: "internal/control", tests: true, testFiles: []string{"control_test.go"}, embeds: []string{"web/static/app.js"}},
		{dir: "internal/bpf", tests: true, testFiles: []string{"bpf_test.go"}, embeds: []string{"obj_bpfel.o"}},
		{dir: "internal/check/rule", tests: true, testFiles: []string{"docs_test.go"}},
		{dir: "pkg/spec/record", tests: true, testFiles: []string{"fixture_test.go"}},
		{dir: "pkg/spec/agent", tests: true, testFiles: []string{"compile_live_test.go"}},
		{dir: "test/conformance", deps: []string{"test/conformance/harness"}, tests: true, testFiles: []string{"c_test.go"}},
		{dir: "test/conformance/harness"},
	}
	integration := []pk{
		{dir: "examples/supply-chain-demo", tests: true, testFiles: []string{"demo_test.go"}},
		{dir: "internal/control/web/e2e", tests: true, testFiles: []string{"launch_test.go"}},
	}
	graphs := map[string]*graph{}
	for _, tags := range tagSets {
		ps := append([]pk{}, common...)
		if strings.Contains(tags, "integration") {
			ps = append(ps, integration...)
		}
		if tags == "tegotesthooks" {
			for i := range ps {
				if ps[i].dir == "internal/bpf" || ps[i].dir == "internal/cli" {
					ps[i].testFiles = append(append([]string{}, ps[i].testFiles...), "hooks_test.go")
				}
			}
		}
		graphs[tags] = mkGraph(tags, ps)
	}
	f := facts{}
	for _, tags := range tagSets {
		f[tags] = map[string]*pkgFacts{
			mod + "/internal/askclient":          {tests: map[string]bool{"TestLedgerTargetSingleSource": true}, why: "seed"},
			mod + "/internal/check/rule":         {tests: map[string]bool{"TestDocsCiteRules": true}, docs: true, why: "docs"},
			mod + "/pkg/spec/agent":              {tests: map[string]bool{"TestLiveOffGolden": true}, why: "seed"},
			mod + "/internal/cli":                {paths: []string{"internal/cli/testdata"}},
			mod + "/internal/runtime":            {},
			mod + "/pkg/spec/record":             {},
			mod + "/internal/control":            {},
			mod + "/internal/bpf":                {},
			mod + "/cmd/tego":                    {},
			mod + "/internal/runtime/supervisor": {},
		}
		if strings.Contains(tags, "integration") {
			f[tags][mod+"/examples/supply-chain-demo"] = &pkgFacts{builds: []string{mod + "/cmd/tego"}}
			f[tags][mod+"/internal/control/web/e2e"] = &pkgFacts{builds: []string{mod + "/cmd/tego", mod + "/cmd/tego-control"}}
		}
	}
	return input{base: "master", mergeBase: "0123456789abcdef", module: mod, graphs: graphs, facts: f,
		// The conformance harness (non-test code) builds tego-control for the tests that import it.
		codeBuilds: map[string][]string{mod + "/test/conformance/harness": {mod + "/cmd/tego-control"}},
		exists:     func(string) bool { return true },
		// internal/bpf and internal/cli hold the tegotesthooks tests, and the gate's list names them.
		hooksListed: map[string]bool{"internal/bpf": true, "internal/cli": true},
		hooksTagged: func(dir string) bool { return dir == "internal/bpf" || dir == "internal/cli" }}
}

func mkGraph(tags string, ps []pk) *graph {
	g := &graph{tags: tags, pkgs: map[string]*pkg{}, byDir: map[string]string{}}
	byDir := map[string]pk{}
	for _, p := range ps {
		byDir[p.dir] = p
	}
	var closure func(dir string, into map[string]bool)
	closure = func(dir string, into map[string]bool) {
		for _, d := range byDir[dir].deps {
			if !into[mod+"/"+d] {
				into[mod+"/"+d] = true
				closure(d, into)
			}
		}
	}
	for _, p := range ps {
		ip := mod + "/" + p.dir
		n := &pkg{path: ip, dir: p.dir, main: p.main, deps: map[string]bool{}}
		closure(p.dir, n.deps)
		if p.tests {
			n.testDeps = map[string]bool{ip: true}
			for d := range n.deps {
				n.testDeps[d] = true
			}
			for _, f := range p.testFiles {
				n.testFiles = append(n.testFiles, p.dir+"/"+f)
			}
		}
		for _, e := range p.embeds {
			n.embeds = append(n.embeds, p.dir+"/"+e)
		}
		for _, e := range p.testEmbeds {
			n.testEmbeds = append(n.testEmbeds, p.dir+"/"+e)
		}
		g.pkgs[ip] = n
		g.byDir[p.dir] = ip
	}
	return g
}

func keys(m map[string]bool) []string {
	out := sorted(m)
	if len(out) == 0 {
		return nil
	}
	return out
}

func runKeys(p *plan, tags string) []string {
	var out []string
	for d, ts := range p.run[tags] {
		for t := range ts {
			out = append(out, d+" "+t)
		}
	}
	sort.Strings(out)
	return out
}

// TestMakePlan holds the selection for the change shapes the gate meets: a network ask
// change to the supervisor that askclient's TestLedgerTargetSingleSource (a source scanner, no import of the
// supervisor) caught, and a change in cmd/tego's closure that the binary-building integration suites test.
func TestMakePlan(t *testing.T) {
	tests := []struct {
		name       string
		changed    []string
		mode       string
		reason     string   // a substring of the first full reason
		unit       []string // test [default]
		integ      []string // test [integration] (nil: not checked)
		hooks      []string // test [tegotesthooks] (nil: not checked)
		run        []string // run [default]
		notInUnit  []string
		vetDefault []string // nil: not checked
		lint       []string // nil: not checked
		missing    []string // changed files that no longer exist
		hookDirs   []string // directories with tegotesthooks test files, when not the fixture's
	}{{
		name:    "NETASK supervisor change runs askclient's single-source scan and cmd/tego's binary suites",
		changed: []string{"internal/runtime/supervisor/ask_connect.go", "spec/policy/SEMANTICS.md"},
		mode:    "scoped",
		unit:    []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
		integ: []string{tegoDir, "./examples/supply-chain-demo", "./internal/cli", "./internal/control/web/e2e",
			"./internal/runtime", "./internal/runtime/supervisor"},
		hooks: []string{"./internal/cli"},
		run: []string{"./internal/askclient TestLedgerTargetSingleSource", "./internal/check/rule TestDocsCiteRules",
			"./pkg/spec/agent TestLiveOffGolden"},
		notInUnit:  []string{"./internal/askclient", "./internal/control"},
		vetDefault: []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
		lint:       []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
	}, {
		// An enum value added in pkg/spec/backend broke exhaustive in internal/runtime/enforce, whose code did not
		// change: the lint covers every package the change reaches, not only the changed directory.
		name:    "a source change lints the unchanged packages that depend on it",
		changed: []string{"internal/runtime/supervisor/tier.go"},
		mode:    "scoped",
		lint:    []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
	}, {
		name:    "control-plane change selects the suites that build tego-control (directly or through a helper), not the demo that builds only tego",
		changed: []string{"internal/control/handler.go"},
		mode:    "scoped",
		unit:    []string{"./internal/control", "./test/conformance"},
		integ:   []string{"./internal/control", "./internal/control/web/e2e", "./test/conformance"},
		hooks:   []string{},
		run: []string{"./internal/askclient TestLedgerTargetSingleSource", "./internal/check/rule TestDocsCiteRules",
			"./pkg/spec/agent TestLiveOffGolden"},
	}, {
		name:    "an embedded web file is a change to its package's source",
		changed: []string{"internal/control/web/static/app.js"},
		mode:    "scoped",
		unit:    []string{"./internal/control"},
		integ:   []string{"./internal/control", "./internal/control/web/e2e", "./test/conformance"},
		lint:    []string{"./cmd/tego-control", "./internal/control"},
	}, {
		name:      "a _test.go change runs that package's tests alone",
		changed:   []string{"internal/runtime/supervisor/sup_test.go"},
		mode:      "scoped",
		unit:      []string{"./internal/runtime/supervisor"},
		integ:     []string{"./internal/runtime/supervisor"},
		notInUnit: []string{"./internal/cli", tegoDir},
	}, {
		name:       "testdata runs its owner's tests",
		changed:    []string{"internal/cli/testdata/golden/status.txt"},
		mode:       "scoped",
		unit:       []string{"./internal/cli"},
		hooks:      []string{"./internal/cli"},
		vetDefault: []string{"./internal/cli"},
		lint:       []string{"./internal/cli"},
	}, {
		name:    "a fixture a known reader takes by joined segments",
		changed: []string{"spec/record/v1/fixtures/live-block.jsonl"},
		mode:    "scoped",
		unit:    []string{"./pkg/spec/record"},
	}, {
		name:    "a file under a package's directory runs that package",
		changed: []string{"internal/runtime/supervisor/notes/x.yaml"},
		mode:    "scoped",
		unit:    []string{"./internal/runtime/supervisor"},
	}, {
		name:    "a deleted file under a package (perhaps embedded) counts as the package's source",
		changed: []string{"internal/runtime/supervisor/policy.json"},
		missing: []string{"internal/runtime/supervisor/policy.json"},
		mode:    "scoped",
		unit:    []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
		lint:    []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
	}, {
		name:    "a deleted Markdown file under a package (perhaps embedded) is its source, not docs",
		changed: []string{"internal/runtime/supervisor/help.md"},
		missing: []string{"internal/runtime/supervisor/help.md"},
		mode:    "scoped",
		unit:    []string{tegoDir, "./internal/cli", "./internal/runtime", "./internal/runtime/supervisor"},
	}, {
		name:    "the edgelint fixture the script self-tests lint is a global input",
		changed: []string{"internal/control/web/testdata/edgelint/dialers.go"},
		mode:    "full",
		reason:  "check-edgelint_test.sh",
	}, {
		name:    "a script beside the shell self-tests is a global input",
		changed: []string{"test/e2e/kt4.sh"},
		mode:    "full",
		reason:  "shell self-tests",
	}, {
		name:    "the pinned wheels pydeps_test.sh holds are a global input",
		changed: []string{"test/workloads/build/python/requirements.txt"},
		mode:    "full",
		reason:  "pydeps_test.sh",
	}, {
		name:    "a Go test table fetch-kernel_test.sh reads is a global input",
		changed: []string{"internal/platform/peer/peer_test.go"},
		mode:    "full",
		reason:  "rowsWithoutPeerPidfd",
	}, {
		name:    "the other Go test table fetch-kernel_test.sh reads is a global input",
		changed: []string{"internal/runtime/enforce/landlock/integration_abi_test.go"},
		mode:    "full",
		reason:  "rowABIFloor",
	}, {
		name:    "the agent m0_demo_test.sh copies through a variable is a global input",
		changed: []string{"test/workloads/python-httpx/agent.py"},
		missing: []string{"test/workloads/python-httpx/agent.py"},
		mode:    "full",
		reason:  "m0_demo_test.sh",
	}, {
		name:     "a test file behind tegotesthooks in a directory the gate's list leaves out is the full gate",
		changed:  []string{"internal/runtime/supervisor/hook_rev_test.go"},
		hookDirs: []string{"internal/bpf", "internal/cli", "internal/runtime/supervisor"},
		mode:     "full",
		reason:   "tegotesthooks directories",
	}, {
		name:     "the last test file behind tegotesthooks gone from a listed directory is the full gate",
		changed:  []string{"internal/cli/hooks_test.go"},
		missing:  []string{"internal/cli/hooks_test.go"},
		hookDirs: []string{"internal/bpf"},
		mode:     "full",
		reason:   "tegotesthooks directories",
	}, {
		name:    "a test file behind tegotesthooks in a listed directory stays scoped",
		changed: []string{"internal/cli/hooks_test.go"},
		mode:    "scoped",
		unit:    []string{"./internal/cli"},
		hooks:   []string{"./internal/cli"},
	}, {
		name:    "a new shell self-test under a package is the full gate: precommit_test.sh holds it to ci.yml",
		changed: []string{"internal/cli/x_test.sh"},
		mode:    "full",
		reason:  "shell self-test",
	}, {
		name:    "the notices check-licenses holds are a global input",
		changed: []string{"THIRD_PARTY_NOTICES.txt"},
		mode:    "full",
		reason:  "check-licenses",
	}, {
		name:    "go.mod is a global input: the full gate",
		changed: []string{"go.mod", "internal/cli/x.go"},
		mode:    "full",
		reason:  "go.mod: global input",
	}, {
		name:    "the skip list is a global input",
		changed: []string{"test/integration-skips.txt"},
		mode:    "full",
		reason:  "skip list",
	}, {
		name:    "a gate script is a global input",
		changed: []string{"scripts/skipgate.sh"},
		mode:    "full",
		reason:  "scripts/skipgate.sh: global input",
	}, {
		name:    "the test helpers every package shares are a global input",
		changed: []string{"internal/testutil/timing.go"},
		mode:    "full",
		reason:  "test helpers",
	}, {
		name:    "a file no package owns or names is the full gate",
		changed: []string{"misc/notes.txt"},
		mode:    "full",
		reason:  "no package owns it",
	}, {
		name:    "a Go file in a directory no build lists (a deleted package) is the full gate",
		changed: []string{"internal/gone/gone.go"},
		mode:    "full",
		reason:  "no build lists",
	}, {
		name:    "a nested module is the full gate",
		changed: []string{"internal/cli/sub/go.mod"},
		mode:    "full",
		reason:  "nested module",
	}, {
		name:      "Markdown alone is the docs gate: only the tests that read Markdown",
		changed:   []string{"docs/OPERATIONS.md", "spec/policy/SEMANTICS.md"},
		mode:      "docs",
		run:       []string{"./internal/check/rule TestDocsCiteRules"},
		notInUnit: []string{"./internal/cli"},
	}, {
		name:    "Markdown inside testdata is not docs",
		changed: []string{"internal/cli/testdata/help.md"},
		mode:    "scoped",
		unit:    []string{"./internal/cli"},
	}, {
		name:    "the committed BPF objects are a global input",
		changed: []string{"internal/bpf/obj_bpfel.o"},
		mode:    "full",
		reason:  "BPF objects",
	}}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			in := fixture()
			in.changed = tc.changed
			in.exists = func(f string) bool { return !contains(tc.missing, f) }
			if tc.hookDirs != nil {
				in.hooksTagged = func(dir string) bool { return contains(tc.hookDirs, dir) }
			}
			p := makePlan(in)
			if p.mode != tc.mode {
				t.Fatalf("mode %q, want %q; notes %v", p.mode, tc.mode, p.notes)
			}
			if tc.reason != "" && (len(p.reasons) == 0 || !strings.Contains(strings.Join(p.reasons, "\n"), tc.reason)) {
				t.Errorf("reasons %v, want one holding %q", p.reasons, tc.reason)
			}
			if tc.mode == "full" {
				var b bytes.Buffer
				p.writePlan(&b)
				if !strings.HasPrefix(b.String(), "mode full\nreason ") || strings.Contains(b.String(), "\ntest ") {
					t.Errorf("full plan:\n%s", b.String())
				}
				return
			}
			unit := keys(p.test[""])
			for _, want := range tc.unit {
				if !contains(unit, want) {
					t.Errorf("test [default] %v lacks %s", unit, want)
				}
			}
			for _, not := range tc.notInUnit {
				if contains(unit, not) {
					t.Errorf("test [default] %v holds %s", unit, not)
				}
			}
			if tc.integ != nil && !reflect.DeepEqual(keys(p.test["integration"]), nilIfEmpty(tc.integ)) {
				t.Errorf("test [integration] = %v, want %v", keys(p.test["integration"]), tc.integ)
			}
			if tc.hooks != nil && !reflect.DeepEqual(keys(p.test["tegotesthooks"]), nilIfEmpty(tc.hooks)) {
				t.Errorf("test [tegotesthooks] = %v, want %v", keys(p.test["tegotesthooks"]), tc.hooks)
			}
			if tc.run != nil && !reflect.DeepEqual(runKeys(p, ""), tc.run) {
				t.Errorf("run [default] = %v, want %v", runKeys(p, ""), tc.run)
			}
			if tc.vetDefault != nil && !reflect.DeepEqual(keys(p.vet[""]), nilIfEmpty(tc.vetDefault)) {
				t.Errorf("vet [default] = %v, want %v", keys(p.vet[""]), tc.vetDefault)
			}
			if tc.lint != nil && !reflect.DeepEqual(keys(p.lint), nilIfEmpty(tc.lint)) {
				t.Errorf("lint = %v, want %v", keys(p.lint), tc.lint)
			}
		})
	}
}

func nilIfEmpty(xs []string) []string {
	if len(xs) == 0 {
		return nil
	}
	return xs
}

// TestWritePlanIsDeterministic: the directives precommit.sh reads come out in one order, whatever map order the
// selection met, and in the shape it parses.
func TestWritePlanIsDeterministic(t *testing.T) {
	in := fixture()
	in.changed = []string{"internal/runtime/supervisor/ask_connect.go"}
	var first string
	for i := 0; i < 20; i++ {
		var b bytes.Buffer
		makePlan(in).writePlan(&b)
		if i == 0 {
			first = b.String()
		} else if b.String() != first {
			t.Fatalf("run %d printed\n%s\nthe first printed\n%s", i, b.String(), first)
		}
	}
	for _, want := range []string{
		"mode scoped\n",
		"vet - ./cmd/tego ./internal/cli ./internal/runtime ./internal/runtime/supervisor\n",
		"test - ./cmd/tego ./internal/cli ./internal/runtime ./internal/runtime/supervisor\n",
		"run - ^(TestDocsCiteRules|TestLedgerTargetSingleSource|TestLiveOffGolden)$ ./internal/askclient ./internal/check/rule ./pkg/spec/agent\n",
		"test integration ./cmd/tego ./examples/supply-chain-demo ./internal/cli ./internal/control/web/e2e ./internal/runtime ./internal/runtime/supervisor\n",
		"test tegotesthooks ./internal/cli\n",
		"lint ./cmd/tego ./internal/cli ./internal/runtime ./internal/runtime/supervisor\n",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("plan lacks %q:\n%s", want, first)
		}
	}
	var e bytes.Buffer
	makePlan(in).writeExplain(&e)
	for _, want := range []string{"mode scoped", "binary closure: its tests build or run " + mod + "/cmd/tego", "source scanner: seed"} {
		if !strings.Contains(e.String(), want) {
			t.Errorf("explanation lacks %q:\n%s", want, e.String())
		}
	}
}

// TestSeedsAreInTheTree: each seeded source scanner is still where the seed says, so a rename does not quietly
// drop it from the always-run set.
func TestSeedsAreInTheTree(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, s := range seeds {
		files, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(s.dir), "*_test.go"))
		if err != nil || len(files) == 0 {
			t.Errorf("seed %+v: no test files in %s (%v)", s, s.dir, err)
			continue
		}
		found := false
		for _, f := range files {
			if s.file != "" && filepath.Base(f) != s.file {
				continue
			}
			b, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if s.test == "" || bytes.Contains(b, []byte("func "+s.test+"(")) {
				found = true
			}
		}
		if !found {
			t.Errorf("seed %+v names a test or file that is not in %s", s, s.dir)
		}
	}
	for _, k := range knownReaders {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(k.dir))); err != nil {
			t.Errorf("known reader %s of %s: %v", k.dir, k.prefix, err)
		}
	}
}

// TestNewSubpackageSelectsTheSubtreeLister: a test that runs go list ./... over its own subtree
// (TestCaptureLinksNoEngine) is selected when a package added under that subtree reaches a changed package, though
// its test binary links none of it.
func TestNewSubpackageSelectsTheSubtreeLister(t *testing.T) {
	in := fixture()
	for tags, g := range in.graphs {
		extra := mkGraph(tags, []pk{
			{dir: "internal/runtime/capture", tests: true, testFiles: []string{"links_test.go"}},
			{dir: "internal/runtime/capture/newsrc"},
		})
		for ip, p := range extra.pkgs {
			g.pkgs[ip] = p
			g.byDir[p.dir] = ip
		}
		known := map[string]string{}
		for d, ip := range g.byDir {
			known[d] = ip
		}
		in.facts[tags][mod+"/internal/runtime/capture"] = &pkgFacts{
			builds: modulePkgs(mod, "internal/runtime/capture", "./...", known)}
	}
	in.changed = []string{"internal/runtime/capture/newsrc/newsrc.go"}
	p := makePlan(in)
	if got := keys(p.test[""]); !contains(got, "./internal/runtime/capture") {
		t.Errorf("test [default] %v lacks ./internal/runtime/capture; why %v", got, p.why)
	}
}

// selfTestPath is a path in a script, with a leading variable if it has one; selfTestJoin a Python os.path.join tail
// that climbs from the script's directory; scratchRepo a $repo that is the self-test's own scratch tree.
var (
	selfTestPath = regexp.MustCompile(`(\$\{?[A-Za-z_]+\}?/)?[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+`)
	selfTestJoin = regexp.MustCompile(`"\.\."(?:,\s*"[^"]+")+`)
	scratchRepo  = regexp.MustCompile(`(?m)^repo="\$tmp`)
)

// selfTestReads gives the repo-relative paths a self-test's code names, comments left out: each as written against
// the root and against the script's directory, $here and a $repo of the real tree dropped, and the os.path.join of a
// climb. A path under another variable ($tmp) is the script's scratch tree, a redirection's target is written, not
// read, and part of a longer path is not a path.
func selfTestReads(script string, src []byte) []string {
	treeVars := map[string]bool{"here": true, "repo": !scratchRepo.Match(src)}
	var code []string
	for _, l := range strings.Split(string(src), "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			code = append(code, l)
		}
	}
	body := strings.Join(code, "\n")
	dir := path.Dir(script)
	got := map[string]bool{}
	for _, m := range selfTestPath.FindAllStringIndex(body, -1) {
		lit := body[m[0]:m[1]]
		if m[0] > 0 && strings.ContainsRune("/~.{_-$>", rune(body[m[0]-1])) || m[0] > 0 && isWordByte(body[m[0]-1]) {
			continue
		}
		if strings.HasPrefix(lit, "$") {
			name, rest, _ := strings.Cut(lit[1:], "/")
			if !treeVars[strings.Trim(name, "{}")] {
				continue
			}
			lit = rest
		}
		got[path.Clean(lit)] = true
		got[path.Join(dir, lit)] = true
	}
	for _, m := range selfTestJoin.FindAllString(body, -1) {
		var segs []string
		for _, q := range regexp.MustCompile(`"[^"]+"`).FindAllString(m, -1) {
			segs = append(segs, strings.Trim(q, `"`))
		}
		got[path.Join(dir, path.Join(segs...))] = true
	}
	return sorted(got)
}

func isWordByte(c byte) bool {
	return c >= '0' && c <= '9' || c|0x20 >= 'a' && c|0x20 <= 'z'
}

// TestSelfTestReadsResolvesTheForms: the forms the self-tests read the tree by, and the forms that are not reads.
func TestSelfTestReadsResolvesTheForms(t *testing.T) {
	src := `#!/usr/bin/env bash
# a comment naming internal/in/comment.txt
wl="$here/../workloads/build/python/requirements.txt"
sha256sum "${repo}/internal/a/b.txt"
cat internal/c/d.txt
cp x "$tmp/internal/e/f.txt"
printf x >internal/w/x.txt
src = open(os.path.join(os.path.dirname(sys.argv[1]), "..", "..", "internal", "g", "h_test.go")).read()
`
	got := selfTestReads("test/e2e/x_test.sh", []byte(src))
	for _, want := range []string{"test/workloads/build/python/requirements.txt", "internal/a/b.txt", "internal/c/d.txt", "internal/g/h_test.go"} {
		if !contains(got, want) {
			t.Errorf("reads %v lack %s", got, want)
		}
	}
	for _, not := range []string{"internal/in/comment.txt", "internal/e/f.txt", "internal/w/x.txt"} {
		if contains(got, not) {
			t.Errorf("reads %v hold %s", got, not)
		}
	}
	if got := selfTestReads("test/e2e/x_test.sh", []byte("repo=\"$tmp/repo\"\ncat \"$repo/internal/a/b.txt\"\n")); contains(got, "internal/a/b.txt") {
		t.Errorf("reads %v hold a path of a scratch $repo", got)
	}
}

// TestSelfTestFixturesAreGlobal: scoped mode runs no script self-test, so every file one of them names, and every
// fixture= or testdata path (a directory too), must lie under a global input, whose change takes the full gate. A
// package directory is not held: a self-test names one as an argument, not as an input.
func TestSelfTestFixturesAreGlobal(t *testing.T) {
	root := filepath.Join("..", "..")
	pc, err := os.ReadFile(filepath.Join(root, "scripts", "precommit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	body := string(pc)
	start, end := strings.Index(body, "script_tests() {"), strings.Index(body, `return "$st"`)
	if start < 0 || end < start {
		t.Fatal("scripts/precommit.sh has no script_tests function")
	}
	scripts := regexp.MustCompile(`(?:scripts|test)/[A-Za-z0-9_./-]*_test\.sh`).FindAllString(body[start:end], -1)
	if len(scripts) < 10 {
		t.Fatalf("found %d self-tests in script_tests: %v", len(scripts), scripts)
	}
	global := func(f string) bool {
		if _, ok := globalFiles[f]; ok {
			return true
		}
		for d := range globalDirs {
			if strings.HasPrefix(f+"/", d) {
				return true
			}
		}
		return false
	}
	for _, sc := range scripts {
		src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(sc)))
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range selfTestReads(sc, src) {
			fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(f)))
			if err != nil || global(f) {
				continue
			}
			fixture := strings.Contains(string(src), "fixture="+f)
			if !fi.Mode().IsRegular() && !fixture && !hasSegment(f+"/", "testdata") {
				continue
			}
			t.Errorf("%s reads %s, which is under no global input: add it to globalFiles or globalDirs", sc, f)
		}
	}
}

// TestHooksListIsTheGateStep: hooksList reads the real scripts/precommit.sh, whose directories all hold a test file
// behind the tag, and a gate without that step gives no list, so no plan.
func TestHooksListIsTheGateStep(t *testing.T) {
	root := filepath.Join("..", "..")
	gate, err := os.ReadFile(filepath.Join(root, "scripts", "precommit.sh"))
	if err != nil {
		t.Fatal(err)
	}
	listed, err := hooksList(gate)
	if err != nil {
		t.Fatal(err)
	}
	if !listed["internal/bpf"] || !listed["internal/runtime/enforce/landlock"] {
		t.Errorf("list %v lacks a directory the gate names", listed)
	}
	for d := range listed {
		if !hooksTagged(filepath.Join(root, filepath.FromSlash(d))) {
			t.Errorf("%s is on the list and holds no test file behind tegotesthooks", d)
		}
	}
	if hooksTagged(filepath.Join(root, "tools", "affected")) {
		t.Error("tools/affected's tests only name the tag: they are not behind it")
	}
	if _, err := hooksList([]byte("pc_add tests unit \"unit tests\" step gated_unit ./...\n")); err == nil {
		t.Error("a gate with no tegotesthooks step gave a list")
	}
	if _, err := hooksList([]byte("\tpc_add tests unit \"unit tests (-tags tegotesthooks)\" step hooks_test\n")); err == nil {
		t.Error("a tegotesthooks step that names no directory gave a list")
	}
}

// TestHooksTaggedReadsTheConstraint: a test file behind the tag counts, one that merely names it does not.
func TestHooksTaggedReadsTheConstraint(t *testing.T) {
	for _, tc := range []struct {
		name, file, src string
		want            bool
	}{
		{"tagged", "a_test.go", "//go:build tegotesthooks\n\npackage a\n", true},
		{"tagged with another", "a_test.go", "// SPDX-License-Identifier: Apache-2.0\n\n//go:build linux && tegotesthooks\n\npackage a\n", true},
		{"named in a comment", "a_test.go", "// see tegotesthooks\npackage a\n", false},
		{"not a test file", "a.go", "//go:build tegotesthooks\n\npackage a\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, tc.file), []byte(tc.src), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := hooksTagged(dir); got != tc.want {
				t.Errorf("hooksTagged = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestMergeGraphsKeepsEitherCgoFile: an integration build listed cgo-free and with cgo keeps the test files, and the
// imports, of both (`integration && !cgo` runs in the gate; `integration && cgo` is vetted).
func TestMergeGraphsKeepsEitherCgoFile(t *testing.T) {
	ip := mod + "/internal/runtime/launch"
	mk := func(file, dep string) *graph {
		return &graph{pkgs: map[string]*pkg{ip: {path: ip, dir: "internal/runtime/launch", deps: map[string]bool{},
			testDeps: map[string]bool{ip: true, dep: true}, testFiles: []string{"internal/runtime/launch/" + file}}},
			byDir: map[string]string{"internal/runtime/launch": ip}}
	}
	a := mk("cgo_on_integration_test.go", mod+"/a")
	mergeGraph(a, mk("cgo_off_integration_test.go", mod+"/b"))
	p := a.pkgs[ip]
	if len(p.testFiles) != 2 || !p.testDeps[mod+"/a"] || !p.testDeps[mod+"/b"] {
		t.Errorf("merged: test files %v, test deps %v", p.testFiles, keys(p.testDeps))
	}
}
