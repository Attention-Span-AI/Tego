// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// The layer rules in .golangci.yml (depguard) keep the repository's layers apart (docs/REPO-LAYOUT.md,
// docs/FEATURES.md section 0). A rule names the directories it governs, so a directory that no rule names is a
// directory the layers do not govern, and the first import that crosses a layer there goes unseen. These tests keep
// every such directory under a rule from the day it appears.

// depguardRule is the part of a depguard rule these tests read.
type depguardRule struct {
	Files    []string `yaml:"files"`
	ListMode string   `yaml:"list-mode"`
	Allow    []string `yaml:"allow"`
	Deny     []struct {
		Pkg  string `yaml:"pkg"`
		Desc string `yaml:"desc"`
	} `yaml:"deny"`
}

func loadDepguardRules(path string) (map[string]depguardRule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Linters struct {
			Settings struct {
				Depguard struct {
					Rules map[string]depguardRule `yaml:"rules"`
				} `yaml:"depguard"`
			} `yaml:"settings"`
		} `yaml:"linters"`
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if len(cfg.Linters.Settings.Depguard.Rules) == 0 {
		return nil, fmt.Errorf("%s: no depguard rules", path)
	}
	return cfg.Linters.Settings.Depguard.Rules, nil
}

// globRegexp turns a depguard file glob into a regexp over a slash-led path: "**/" is any run of leading
// directories (or none), "/**" anything below, "*" a run of non-slash characters.
func globRegexp(glob string) *regexp.Regexp {
	var sb strings.Builder
	sb.WriteString("^")
	for i := 0; i < len(glob); {
		switch {
		case strings.HasPrefix(glob[i:], "**/"):
			sb.WriteString("(?:.*/)?")
			i += 3
		case strings.HasPrefix(glob[i:], "/**"):
			sb.WriteString("/.*")
			i += 3
		case strings.HasPrefix(glob[i:], "**"):
			sb.WriteString(".*")
			i += 2
		case glob[i] == '*':
			sb.WriteString("[^/]*")
			i++
		case glob[i] == '?':
			sb.WriteString("[^/]")
			i++
		default:
			sb.WriteString(regexp.QuoteMeta(string(glob[i])))
			i++
		}
	}
	sb.WriteString("$")
	return regexp.MustCompile(sb.String())
}

// governs reports whether the rule names the product file rel (a slash path below the repository root): a
// non-negated pattern matches it and no negated one excludes it. The $all pattern names no directory, so it does not
// count, "!$test" excludes only test files, and a rule that lists $test is for test files alone.
func (r depguardRule) governs(rel string) bool {
	path := "/" + rel
	named := false
	for _, p := range r.Files {
		switch {
		case p == "$test":
			return false // a rule for test files alone governs no product file
		case p == "$all":
		case strings.HasPrefix(p, "!"):
			neg := p[1:]
			if neg != "$test" && !strings.HasPrefix(neg, "$") && globRegexp(neg).MatchString(path) {
				return false
			}
		case globRegexp(p).MatchString(path):
			named = true
		}
	}
	return named
}

// layeredFixedDirs are the single directories to govern; the wildcard roots are in layeredDirs.
var layeredFixedDirs = []string{"internal/setup", "internal/selftest", "tools/launchfacts", "tools/publiccheck", "tools/readmecheck"}

// layeredDirs returns the existing directories the layer rules must govern: a child of internal/adapters,
// internal/check or pkg/spec, and the fixed ones. Slash paths below root, sorted.
func layeredDirs(root string) ([]string, error) {
	var dirs []string
	for _, pattern := range []string{"internal/adapters/*", "internal/check/*", "pkg/spec/*"} {
		matches, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(pattern)))
		if err != nil {
			return nil, err
		}
		for _, m := range matches {
			if fi, err := os.Stat(m); err == nil && fi.IsDir() {
				rel, _ := filepath.Rel(root, m)
				dirs = append(dirs, filepath.ToSlash(rel))
			}
		}
	}
	for _, d := range layeredFixedDirs {
		if fi, err := os.Stat(filepath.Join(root, filepath.FromSlash(d))); err == nil && fi.IsDir() {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	return dirs, nil
}

// uncoveredLayeredDirs returns the layered directories under root that no depguard rule of root/.golangci.yml
// governs.
func uncoveredLayeredDirs(root string) ([]string, error) {
	rules, err := loadDepguardRules(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		return nil, err
	}
	dirs, err := layeredDirs(root)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range dirs {
		covered := false
		for _, r := range rules {
			if r.governs(d + "/x.go") {
				covered = true
				break
			}
		}
		if !covered {
			out = append(out, d)
		}
	}
	return out, nil
}

// TestEveryLayeredDirHasARule: every existing directory under internal/adapters/*, internal/check/*,
// internal/setup, internal/selftest, pkg/spec/* and tools/{launchfacts,publiccheck,readmecheck} is governed by a
// depguard rule, so a package added there is under its layer's rule the day it appears.
func TestEveryLayeredDirHasARule(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dirs, err := layeredDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"pkg/spec/agent", "pkg/spec/record", "internal/check/drift"} {
		if !slices.Contains(dirs, want) {
			t.Fatalf("layeredDirs found %v, want it to include %s", dirs, want)
		}
	}
	got, err := uncoveredLayeredDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range got {
		t.Errorf("%s is governed by no depguard rule in .golangci.yml; add the directory to its layer's rule (docs/REPO-LAYOUT.md)", d)
	}
}

// writeFixture writes files (slash path to content) under a new temporary directory and returns it.
func writeFixture(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, c := range files {
		full := filepath.Join(root, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

const fixtureRules = `linters:
  settings:
    depguard:
      rules:
        process-starts:
          files: ["$all", "!$test"]
          deny:
            - pkg: os/exec
              desc: x
        adapters:
          files: ["**/internal/adapters/**"]
          deny:
            - pkg: a
              desc: b
        setup:
          files: ["**/internal/setup/**", "!**/internal/setup/gen/**"]
          deny:
            - pkg: a
              desc: b
        testsonly:
          files: ["**/pkg/spec/testsonly/**", "$test"]
          deny:
            - pkg: a
              desc: b
`

// TestLayeredDirCheckFindsPlantedBreakage tests the test with a fixture tree: a directory no rule names is reported
// ($all names none, a rule for test files alone governs no directory, a wildcard root's children are found, a
// sibling whose name only begins like a governed one is not governed), and a directory a rule names is not.
func TestLayeredDirCheckFindsPlantedBreakage(t *testing.T) {
	root := writeFixture(t, map[string]string{
		".golangci.yml":                       fixtureRules,
		"internal/adapters/foo/doc.go":        "package foo\n",
		"internal/adapters/doc.go":            "package adapters\n",
		"internal/setup/s.go":                 "package setup\n",
		"internal/selftest/t.go":              "package selftest\n",
		"internal/check/receipt/r.go":         "package receipt\n",
		"pkg/spec/reason/r.go":                "package reason\n",
		"pkg/spec/testsonly/r.go":             "package testsonly\n",
		"tools/launchfacts/l.go":              "package main\n",
		"tools/publiccheck/p.go":              "package main\n",
		"tools/other/o.go":                    "package main\n",
		"internal/setupx/x.go":                "package setupx\n",
		"internal/adapters/foo/testdata/x.go": "package x\n",
	})
	got, err := uncoveredLayeredDirs(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"internal/check/receipt", "internal/selftest", "pkg/spec/reason", "pkg/spec/testsonly", "tools/launchfacts", "tools/publiccheck"}
	if !slices.Equal(got, want) {
		t.Fatalf("uncovered = %v, want %v", got, want)
	}

	// The same tree with a rule per layer is fully covered.
	root = writeFixture(t, map[string]string{
		".golangci.yml": fixtureRules + `        selftest:
          files: ["**/internal/selftest/**"]
        check:
          files: ["**/internal/check/**"]
        spec:
          files: ["**/pkg/spec/**"]
        tools:
          files: ["**/tools/launchfacts/**", "**/tools/publiccheck/**"]
`,
		"internal/adapters/foo/doc.go": "package foo\n",
		"internal/setup/s.go":          "package setup\n",
		"internal/selftest/t.go":       "package selftest\n",
		"internal/check/receipt/r.go":  "package receipt\n",
		"pkg/spec/reason/r.go":         "package reason\n",
		"tools/launchfacts/l.go":       "package main\n",
		"tools/publiccheck/p.go":       "package main\n",
	})
	if got, err := uncoveredLayeredDirs(root); err != nil || len(got) != 0 {
		t.Fatalf("a fully covered tree reported %v (err %v)", got, err)
	}

	// No configuration, and one with no depguard rules, are errors and not "nothing uncovered".
	if _, err := uncoveredLayeredDirs(t.TempDir()); err == nil {
		t.Error("a tree with no .golangci.yml passed")
	}
	if _, err := uncoveredLayeredDirs(writeFixture(t, map[string]string{".golangci.yml": "linters:\n  enable: [depguard]\n"})); err == nil {
		t.Error("a configuration with no depguard rules passed")
	}
}

// TestGlobRegexp pins the glob dialect the coverage test reads.
func TestGlobRegexp(t *testing.T) {
	for _, tc := range []struct {
		glob, path string
		want       bool
	}{
		{"**/internal/setup/**", "/internal/setup/x.go", true},
		{"**/internal/setup/**", "/a/b/internal/setup/sub/x.go", true},
		{"**/internal/setup/**", "/internal/setupx/x.go", false},
		{"**/internal/setup/**", "/xinternal/setup/x.go", false},
		{"**/tools/launchfacts/**", "/tools/launchfacts/main.go", true},
		{"**/pkg/spec/agent/decide_link_test.go", "/pkg/spec/agent/decide_link_test.go", true},
		{"**/pkg/spec/agent/decide_link_test.go", "/pkg/spec/agent/other.go", false},
		{"**/internal/a*/x/**", "/internal/abc/x/f.go", true},
		{"**/internal/a*/x/**", "/internal/abc/d/x/f.go", false},
	} {
		if got := globRegexp(tc.glob).MatchString(tc.path); got != tc.want {
			t.Errorf("%s ~ %s = %v, want %v", tc.glob, tc.path, got, tc.want)
		}
	}
}

// layerRuleSpec is what one of the V1 plumbing package's rules must say.
type layerRuleSpec struct {
	name   string
	dir    string   // a directory the rule must govern
	strict []string // a strict allow list, exactly; nil for a deny list
	deny   []string // packages the deny list must name (a subset)
}

const mod = "github.com/attention-span-ai/tego/"

var layerRuleSpecs = []layerRuleSpec{
	{name: "reason-spec-is-leaf", dir: "pkg/spec/reason", strict: []string{"$gostd", mod + "pkg/spec/record"}},
	{name: "harness-spec-is-leaf", dir: "pkg/spec/harness", strict: []string{"$gostd"}},
	{name: "receipt-spec-is-a-leaf", dir: "pkg/spec/receipt", strict: []string{"$gostd"}},
	{name: "claudecode-imports", dir: "internal/adapters/claudecode", strict: []string{"$gostd", "golang.org/x/sys/unix", mod + "pkg/spec/reason", mod + "pkg/spec/harness"}},
	{name: "adapters-never-import-engine", dir: "internal/adapters/openaicodex", deny: []string{
		mod + "internal/runtime", mod + "internal/ledger", mod + "internal/check", mod + "internal/serve", mod + "internal/cli",
		mod + "internal/bpf", mod + "internal/policy/decide", "github.com/cilium/ebpf"}},
	{name: "receipt-reads-the-ledger-only", dir: "internal/check/receipt", deny: []string{
		mod + "internal/runtime", mod + "internal/cli", mod + "internal/serve", mod + "internal/doctor", mod + "internal/registry",
		mod + "internal/adapters", mod + "internal/bpf", mod + "internal/platform", "github.com/cilium/ebpf", "gopkg.in/yaml.v3",
		mod + "pkg/spec/agent"}},
	{name: "setup-never-imports-engine", dir: "internal/setup", deny: []string{
		mod + "internal/runtime", mod + "internal/policy/decide", mod + "internal/bpf", mod + "internal/ledger",
		mod + "internal/check", mod + "internal/cli", "github.com/cilium/ebpf"}},
	{name: "selftest-never-imports-runtime", dir: "internal/selftest", deny: []string{
		mod + "internal/runtime", mod + "internal/policy/decide", mod + "internal/bpf", mod + "internal/cli", "github.com/cilium/ebpf"}},
	{name: "tools-are-stdlib", dir: "tools/launchfacts", deny: []string{"github.com/attention-span-ai/tego"}},
}

// extraDocRuleSpecs are layer rules beyond layerRuleSpecs that a package doc's Imports line must also agree with.
// A test file in this package may fill it from init; with none, docRuleSpecs is the V1 rules alone.
var extraDocRuleSpecs []layerRuleSpec

// docRuleSpecs returns every layer rule a package doc's Imports line must agree with: the V1 rules, then any
// extraDocRuleSpecs.
func docRuleSpecs() []layerRuleSpec {
	return append(slices.Clone(layerRuleSpecs), extraDocRuleSpecs...)
}

// TestV1LayerRulesAreDeclared: each rule is in .golangci.yml, governs the directory it is for,
// says what its layer allows (a strict allow list where it names the only imports, a deny list that names every
// package it must), and gives each denied package a description that names the layer. A rule dropped or loosened
// fails here; the directory-less rules are otherwise inert.
func TestV1LayerRulesAreDeclared(t *testing.T) {
	rules, err := loadDepguardRules(filepath.Join("..", "..", ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range layerRuleSpecs {
		r, ok := rules[s.name]
		if !ok {
			t.Errorf("rule %s is not in .golangci.yml", s.name)
			continue
		}
		if !r.governs(s.dir + "/x.go") {
			t.Errorf("rule %s does not govern %s", s.name, s.dir)
		}
		if s.strict != nil {
			if r.ListMode != "strict" {
				t.Errorf("rule %s has list-mode %q, want strict", s.name, r.ListMode)
			}
			if got := slices.Sorted(slices.Values(r.Allow)); !slices.Equal(got, slices.Sorted(slices.Values(s.strict))) {
				t.Errorf("rule %s allows %v, want exactly %v", s.name, got, s.strict)
			}
			if r.governs(s.dir+"/x_test.go") && !slices.Contains(r.Files, "!$test") {
				t.Errorf("rule %s governs test files; tests may import what they check", s.name)
			}
			continue
		}
		have := map[string]bool{}
		for _, d := range r.Deny {
			have[d.Pkg] = true
			if !strings.Contains(d.Desc, "Layer") {
				t.Errorf("rule %s: denial of %s has description %q, want one that names its layer", s.name, d.Pkg, d.Desc)
			}
		}
		for _, p := range s.deny {
			if !have[p] {
				t.Errorf("rule %s does not deny %s", s.name, p)
			}
		}
	}
	// tools-are-stdlib's one exception is the shared Markdown link reader.
	r := rules["tools-are-stdlib"]
	if r.ListMode != "lax" || !slices.Equal(r.Allow, []string{mod + "tools/internal/mdlinks"}) {
		t.Errorf("tools-are-stdlib: list-mode %q allow %v, want lax and tools/internal/mdlinks alone", r.ListMode, r.Allow)
	}
	for _, d := range []string{"tools/launchfacts", "tools/publiccheck", "tools/readmecheck"} {
		if !r.governs(d + "/x.go") {
			t.Errorf("tools-are-stdlib does not govern %s", d)
		}
	}
}

// importsStatement returns the text of the "Imports:" statement of a package doc comment: from "Imports:" to the
// "Must not import:" line (or the end of the comment), with the comment markers dropped. It returns "" for a
// file that has none.
func importsStatement(src string) string {
	var out []string
	in := false
	for _, line := range strings.Split(src, "\n") {
		t := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "//"))
		switch {
		case strings.HasPrefix(t, "Imports:"):
			in = true
			out = append(out, strings.TrimPrefix(t, "Imports:"))
		case in && (strings.HasPrefix(t, "Must not import") || t == "" || strings.HasPrefix(line, "package ")):
			return strings.Join(out, " ")
		case in:
			out = append(out, t)
		}
	}
	return strings.Join(out, " ")
}

// TestPackageDocsAgreeWithTheirLayerRule: the "Imports:" line of a package doc.go under a directory a layer
// deny rule governs names none of the packages the rule denies, and one under a strict rule names nothing under internal/
// that the rule does not allow. A doc that allows what depguard refuses sends the next author to a lint failure.
func TestPackageDocsAgreeWithTheirLayerRule(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	rules, err := loadDepguardRules(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, top := range []string{"internal", "pkg", "tools"} {
		walkErr := filepath.WalkDir(filepath.Join(root, top), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || d.Name() != "doc.go" {
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			st := importsStatement(string(b))
			for _, s := range docRuleSpecs() {
				if !rules[s.name].governs(rel) {
					continue
				}
				checked++
				for _, d := range s.deny {
					pkg := strings.TrimSuffix(strings.TrimSuffix(strings.TrimPrefix(d, mod), "$"), "/")
					if pkg != strings.TrimSuffix(mod, "/") && regexp.MustCompile(`(^|[^A-Za-z0-9_./-])`+regexp.QuoteMeta(pkg)+`($|[^A-Za-z0-9_-])`).MatchString(st) {
						t.Errorf("%s: its Imports line names %s, which depguard %s denies there", rel, pkg, s.name)
					}
				}
				for _, w := range strings.FieldsFunc(st, func(r rune) bool { return r == ',' || r == ' ' || r == '(' || r == ')' }) {
					if s.strict != nil && strings.HasPrefix(w, "internal/") && !slices.Contains(s.strict, mod+w) {
						t.Errorf("%s: its Imports line names %s, which depguard %s does not allow there", rel, w, s.name)
					}
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatal(walkErr)
		}
	}
	if checked < 3 {
		t.Fatalf("checked %d package docs under a V1 layer rule, want the three under internal/adapters", checked)
	}
}

// TestImportsStatement: the reader of a doc comment's Imports line.
func TestImportsStatement(t *testing.T) {
	src := "// Package x.\n//\n// Imports: pkg/spec/**, golang.org/x/sys/unix\n// and the standard library\n// Must not import: internal/runtime\npackage x\n"
	if got, want := strings.Join(strings.Fields(importsStatement(src)), " "), "pkg/spec/**, golang.org/x/sys/unix and the standard library"; got != want {
		t.Errorf("importsStatement = %q, want %q", got, want)
	}
	if got := importsStatement("// Package x.\npackage x\n"); got != "" {
		t.Errorf("a file with no Imports line gave %q", got)
	}
}
