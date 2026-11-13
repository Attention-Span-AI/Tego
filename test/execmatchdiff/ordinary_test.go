// SPDX-License-Identifier: Apache-2.0

package execmatchdiff_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	old "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline"
	oldrows "github.com/attention-span-ai/tego/test/execmatchdiff/internal/baseline/rows"
	"gopkg.in/yaml.v3"
)

type ordinaryRow struct {
	Entry                                 string
	MeasuredEntry                         string `json:",omitempty"`
	ParseError                            string `json:",omitempty"`
	ReleasedParseError                    string `json:",omitempty"`
	Sources                               []string
	Generated, AdmittedBefore, RefusedNow int
	Regressions                           [][]string `json:",omitempty"`
}

var prosePlaceholder = regexp.MustCompile(`<[^>]*>`)

var fencedYAML = regexp.MustCompile("(?s)```(?:yaml|yml)?\\n(.*?)```")

func ordinaryEntries(t *testing.T) map[string][]string { return catalogEntries(t, "allow") }

func catalogEntries(t *testing.T, list string) map[string][]string {
	t.Helper()
	return catalogEntriesAt(t, list, filepath.Join("..", ".."))
}

func catalogEntriesAt(t *testing.T, list, tree string) map[string][]string {
	t.Helper()
	entries := map[string][]string{}
	inlineEntries := regexp.MustCompile("(?:exec\\." + list + "|" + list + "):[ \\t]*\\[([^]]*)\\]")
	scalarEntries := regexp.MustCompile("`(exec\\.)?" + list + ":[ \\t]+([^`\\n]+)`")
	add := func(entry, source string) {
		if entry != "" && !slices.Contains(entries[entry], source) {
			entries[entry] = append(entries[entry], source)
		}
	}
	// Keep the reviewed source inputs when the public overlay replaces private
	// documents. Historical labels never masquerade as a current file's source.
	data, err := os.ReadFile(filepath.Join("testdata", "source-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	var retained map[string]map[string][]string
	if err := json.Unmarshal(data, &retained); err != nil {
		t.Fatal(err)
	}
	for entry, sources := range retained[list] {
		for _, source := range sources {
			add(entry, "historical source: "+source)
		}
	}
	var parseYAML func([]byte, string)
	parseYAML = func(data []byte, source string) {
		var n yaml.Node
		if yaml.Unmarshal(data, &n) != nil {
			return
		}
		var walk func(*yaml.Node)
		walk = func(n *yaml.Node) {
			if n.Kind == yaml.MappingNode {
				for i := 0; i+1 < len(n.Content); i += 2 {
					key, value := n.Content[i], n.Content[i+1]
					if key.Value == "contract" && value.Kind == yaml.ScalarNode && strings.Contains(value.Value, "exec:") {
						parseYAML([]byte(value.Value), source+" (contract)")
					}
					if key.Value == "exec" && value.Kind == yaml.MappingNode {
						for j := 0; j+1 < len(value.Content); j += 2 {
							if value.Content[j].Value == list && value.Content[j+1].Kind == yaml.SequenceNode {
								for _, e := range value.Content[j+1].Content {
									if e.Kind == yaml.ScalarNode {
										add(e.Value, source)
									}
								}
							}
						}
					}
					if (key.Value == "exec_"+list+"_commands" || key.Value == "exec_"+list) && value.Kind == yaml.SequenceNode {
						for _, e := range value.Content {
							if e.Kind == yaml.ScalarNode {
								add(e.Value, source)
							}
						}
					}
				}
			}
			for _, c := range n.Content {
				walk(c)
			}
		}
		walk(&n)
	}
	for _, root := range []string{"examples", "pkg/spec/presets", "spec/policy/conformance", "test/conformance", "test/fixtures", "docs", "tools/oss/testdata/overlay/docs", "tools/oss/testdata/overlay/README.md", "README.md", "CONTRIBUTING.md", "spec/policy"} {
		if strings.HasPrefix(root, "tools/oss/") {
			if _, err := os.Stat(filepath.Join(tree, root)); os.IsNotExist(err) {
				continue // public cuts retain these inputs in source-catalog.json
			}
		}
		err := filepath.WalkDir(filepath.Join(tree, root), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return nil
			}
			ext := filepath.Ext(path)
			if ext != ".yaml" && ext != ".yml" && ext != ".md" && ext != ".go" && ext != ".sh" {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, err := filepath.Rel(tree, path)
			if err != nil {
				return err
			}
			source := filepath.ToSlash(rel)
			switch ext {
			case ".yaml", ".yml":
				parseYAML(data, source)
			case ".sh":
				for _, body := range shellHeredocs(t, data) {
					parseYAML(body, source+" (heredoc)")
				}
			case ".md":
				for _, m := range fencedYAML.FindAllSubmatch(data, -1) {
					parseYAML(m[1], source)
				}
				// Prose also gives standalone allow examples without an exec map.
				for _, m := range inlineEntries.FindAllSubmatch(data, -1) {
					var values []string
					body := prosePlaceholder.ReplaceAllStringFunc(string(m[1]), strconv.Quote)
					if yaml.Unmarshal([]byte("["+body+"]"), &values) != nil {
						continue
					}
					for _, entry := range values {
						if proseExecEntry(entry, source, bytes.HasPrefix(m[0], []byte("exec."+list))) {
							add(entry, source)
						}
					}
				}
				for _, m := range scalarEntries.FindAllSubmatch(data, -1) {
					entry := strings.TrimSpace(string(m[2]))
					if strings.HasPrefix(entry, "[") || entry == "" {
						continue
					}
					if proseExecEntry(entry, source, len(m[1]) > 0) {
						add(entry, source+" (scalar example)")
					}
				}
			case ".go":
				if root != "test/conformance" {
					return nil
				}
				f, err := parser.ParseFile(token.NewFileSet(), path, data, 0)
				if err != nil {
					return err
				}
				ast.Inspect(f, func(n ast.Node) bool {
					if literal, ok := n.(*ast.BasicLit); ok && literal.Kind == token.STRING {
						if text, err := strconv.Unquote(literal.Value); err == nil && strings.Contains(text, "exec:") {
							parseYAML([]byte(text), source+" (contract literal)")
						}
					}
					kv, ok := n.(*ast.KeyValueExpr)
					if !ok {
						return true
					}
					key, ok := kv.Key.(*ast.Ident)
					if !ok || !catalogModelField(list, key.Name) {
						return true
					}
					lit, ok := kv.Value.(*ast.CompositeLit)
					if !ok {
						return true
					}
					for _, e := range lit.Elts {
						if s, ok := e.(*ast.BasicLit); ok && s.Kind == token.STRING {
							entry, err := strconv.Unquote(s.Value)
							if err == nil {
								add(entry, source)
							}
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if list == "allow" {
		add("git reflog", "review regression control")
	}
	for entry := range entries {
		sort.Strings(entries[entry])
	}
	return entries
}

func proseExecEntry(entry, source string, qualified bool) bool {
	if strings.HasPrefix(entry, "<") && strings.HasSuffix(entry, ">") {
		return true
	}
	words, _, err := execmatch.SplitWords(entry)
	if !strings.ContainsAny(entry, " \t") {
		words = []string{entry}
		err = nil
	}
	if err != nil || len(words) == 0 {
		return false
	}
	// Numeric gate thresholds and network addresses are different allow fields.
	if _, err := strconv.Atoi(words[0]); err == nil {
		return false
	}
	if strings.Contains(words[0], "://") {
		return false
	}
	// This diagnostic shows an editing instruction, not a literal exec entry.
	if words[0] == "add" && strings.Contains(source, "agent-contract.md") {
		return false
	}
	if qualified || rows.Builtin().Lookup(filepath.Base(words[0])) != nil {
		return true
	}
	if strings.Contains(source, "exec-command") || strings.Contains(source, "exec-ask") || strings.Contains(source, "0048-") {
		return true
	}
	return (filepath.IsAbs(words[0]) || strings.HasPrefix(words[0], "./") || strings.HasPrefix(words[0], "../")) && !strings.HasSuffix(source, "p0/proxy-protocols.md")
}

func catalogModelField(list, name string) bool {
	switch list {
	case "allow":
		return name == "ExecAllowCommands" || name == "ExecAllow"
	case "deny":
		return name == "ExecDeny"
	case "ask":
		return name == "ExecAsk"
	}
	return false
}

func instantiateEntry(entry string) (string, error) {
	if strings.Join(strings.Fields(entry), " ") == "<the git on the run's PATH, by path>" {
		return "/usr/bin/git", nil
	}
	// Fixture roles are fixed by examples/live-modes-demo/demo.sh:106,135 and
	// examples/supply-chain-demo/demo.sh:247-259. Representative stable paths
	// preserve those tool basenames and therefore their actual matcher rows.
	result := strings.NewReplacer(
		"{{P}}", "/fixture",
		"{{LOADER}}", "/lib64/ld-linux-x86-64.so.2",
		"@@PYREAL@@", "/usr/bin/python3",
		"$PYTHON3", "/usr/bin/python3",
		"@SH@", "/bin/sh",
		"@CAT@", "/usr/bin/cat",
		"@SLEEP@", "/usr/bin/sleep",
		"@@CODEXHOST@@", "/fixture/host",
	).Replace(entry)
	words, _, err := execmatch.SplitWords(result)
	if !strings.ContainsAny(result, " \t") {
		words = []string{result}
		err = nil
	}
	placeholder := regexp.MustCompile(`\{\{[^}]+\}\}|@@?[A-Z][A-Z0-9_]*@@?`)
	if err == nil && len(words) > 0 && placeholder.MatchString(filepath.Base(words[0])) {
		return "", fmt.Errorf("unresolved program-name template in %q", entry)
	}
	return result, nil
}

func TestOrdinaryTemplateRolesUseRealRows(t *testing.T) {
	for _, tc := range []struct{ entry, want string }{
		{"<the git on the run's PATH, by path>", "/usr/bin/git"},
		{"@@PYREAL@@", "/usr/bin/python3"},
		{"@SH@", "/bin/sh"},
		{"@CAT@", "/usr/bin/cat"},
		{"@SLEEP@", "/usr/bin/sleep"},
		{"@@CODEXHOST@@/codex-code-mode-host", "/fixture/host/codex-code-mode-host"},
	} {
		got, err := instantiateEntry(tc.entry)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q,%v want %q", tc.entry, got, err, tc.want)
		}
		if strings.Contains(tc.entry, "PYREAL") || tc.entry == "@SH@" || strings.HasPrefix(tc.entry, "<the git") {
			if rows.Builtin().Lookup(filepath.Base(got)) == nil || len(ordinaryVectors(t, got)) <= 3 {
				t.Errorf("%s omitted its real row options", tc.entry)
			}
		}
	}
	for _, entry := range []string{"{{UNKNOWN}}", "@@UNKNOWN@@", "@UNKNOWN@"} {
		if _, err := instantiateEntry(entry); err == nil {
			t.Errorf("unresolved %s was measured as a generic command", entry)
		}
	}
}

func TestEntrySeparatorInventory(t *testing.T) {
	type inventory struct {
		Entries    map[string]map[string][]string
		Separators map[string]map[string][]string
	}
	all := inventory{Entries: map[string]map[string][]string{}, Separators: map[string]map[string][]string{}}
	for _, list := range []string{"allow", "deny", "ask"} {
		entries := catalogEntries(t, list)
		all.Entries[list] = entries
		all.Separators[list] = map[string][]string{}
		for entry, sources := range entries {
			words, _, err := execmatch.SplitWords(entry)
			if err == nil && slices.Contains(words, "--") {
				all.Separators[list][entry] = sources
				t.Logf("separator %s %q sources=%q", list, entry, sources)
			}
		}
		t.Logf("%s entries=%d separator entries=%d", list, len(entries), len(all.Separators[list]))
	}
	if file := os.Getenv("TEGO_EXECMATCH_INVENTORY"); file != "" {
		data, err := json.MarshalIndent(all, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func ordinaryVectors(t *testing.T, entry string) [][]string {
	t.Helper()
	words, _, err := execmatch.SplitWords(entry)
	if !strings.ContainsAny(entry, " \t") {
		words = []string{entry}
		err = nil
	}
	if err != nil || len(words) == 0 {
		return nil
	}
	if words[len(words)-1] == "*" {
		words = words[:len(words)-1]
	}
	seen := map[string]bool{}
	var out [][]string
	add := func(toks []string) {
		key := strings.Join(toks, "\x00")
		if !seen[key] {
			seen[key] = true
			out = append(out, toks)
		}
	}
	add(words)
	add(append(slices.Clone(words), "operand"))
	add(append(slices.Clone(words), "operand", "second"))
	// The row does not enumerate the git-log options accepted by reflog show.
	// Keep the review's actual ordinary spellings in the measured catalog too.
	if entry == "git reflog" {
		add([]string{"git", "reflog", "-n", "5"})
		add([]string{"git", "reflog", "--date=iso"})
	}
	row := rows.Builtin().Lookup(filepath.Base(words[0]))
	if row == nil {
		return out
	}
	p, err := execmatch.Parse(entry, execmatch.ListAllow, rows.Builtin())
	if err != nil {
		return out
	}
	lv := row.Root
	var inherited []execmatch.Opt
	for _, n := range p.Path {
		if lv == nil {
			break
		}
		for _, o := range lv.Opts {
			if o.Persistent {
				inherited = append(inherited, o)
			}
		}
		next, ok := lv.Subs[n]
		if !ok {
			next = lv.Wild
		}
		lv = next
	}
	levels := []*execmatch.Level{lv, {Opts: inherited}}
	if lv != nil && lv.Default != "" {
		levels = append(levels, lv.Subs[lv.Default])
	}
	for _, level := range levels {
		for _, opt := range optionSpellings(level) {
			v := append(slices.Clone(words), opt...)
			add(v)
			add(append(slices.Clone(v), "operand"))
		}
	}
	return out
}

// TestOrdinaryAllowRegression measures all allow entries found in the shipped
// examples, presets, conformance fixtures, and documentation. A released admit
// that now refuses needs a concrete tool-behaviour justification, or a fix.
func TestOrdinaryAllowRegression(t *testing.T) {
	entries := ordinaryEntries(t)
	keys := make([]string, 0, len(entries))
	for e := range entries {
		keys = append(keys, e)
	}
	sort.Strings(keys)
	var table []ordinaryRow
	counts := map[string]int{}
	for _, entry := range keys {
		measured, err := instantiateEntry(entry)
		if err != nil {
			t.Fatal(err)
		}
		row := ordinaryRow{Entry: entry, Sources: entries[entry]}
		if measured != entry {
			row.MeasuredEntry = measured
		}
		_, err = execmatch.Parse(measured, execmatch.ListAllow, rows.Builtin())
		if err != nil {
			row.ParseError = err.Error()
			table = append(table, row)
			counts["entries"]++
			if _, beforeErr := old.Parse(measured, old.ListAllow, oldrows.Builtin()); beforeErr == nil {
				counts["new-compile-errors"]++
				t.Errorf("released allow entry %q now fails to compile: %v", entry, err)
			} else {
				row.ReleasedParseError = beforeErr.Error()
				table[len(table)-1] = row
				counts["released-and-current-compile-errors"]++
			}
			continue
		}
		if _, beforeErr := old.Parse(measured, old.ListAllow, oldrows.Builtin()); beforeErr != nil {
			if measured != "git add --no-f" {
				t.Fatalf("unapproved released-invalid entry restored: %q", measured)
			}
			row.ReleasedParseError = beforeErr.Error()
			row.Generated = len(ordinaryVectors(t, measured))
			table = append(table, row)
			counts["entries"]++
			counts["generated"] += row.Generated
			counts["restored-compile-entry"]++
			continue
		}
		pair := newPair(t, measured, execmatch.ListAllow)
		for _, argv := range ordinaryVectors(t, measured) {
			row.Generated++
			tool := filepath.Base(argv[0])
			f := routeFacts(tool, argv[1:], 0)
			a, b := pair.decide(f)
			// OutcomeNone continues past the command matcher too (for example a
			// bare image grant), so it is an admitted invocation for this check.
			if b.Outcome == old.OutcomeRefused {
				continue
			}
			row.AdmittedBefore++
			if a.Outcome == execmatch.OutcomeRefused {
				row.RefusedNow++
				row.Regressions = append(row.Regressions, argv)
			}
		}
		table = append(table, row)
		counts["entries"]++
		counts["generated"] += row.Generated
		counts["admitted-before"] += row.AdmittedBefore
		counts["refused-now"] += row.RefusedNow
	}
	if file := os.Getenv("TEGO_EXECMATCH_ORDINARY"); file != "" {
		data, err := json.MarshalIndent(table, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(file, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	logCounts(t, counts)
	for _, row := range table {
		for _, argv := range row.Regressions {
			t.Errorf("released allow %q now refuses %q (sources %q)", row.Entry, argv, row.Sources)
		}
	}
}

func TestOrdinaryCatalogIncludesProseAndShippedDocs(t *testing.T) {
	entries := ordinaryEntries(t)
	checks := []struct{ entry, source string }{
		{"a.js", "docs/spec/exec-command-rows.md (scalar example)"},
		{"node --stack-trace-limit=5 a.js", "docs/CHANGELOG.md (scalar example)"},
		{"cargo build", "tools/oss/testdata/overlay/docs/CHANGELOG.md"},
		{"git status", "spec/policy/SEMANTICS.md"},
		{"<the git on the run's PATH, by path>", "docs/p0/exec-ask-plan.md"},
	}
	if _, err := os.Stat(filepath.Join("../..", "tools/oss/manifest.txt")); err != nil {
		if !os.IsNotExist(err) {
			t.Fatal(err)
		}
		checks[1].source = "historical source: docs/CHANGELOG.md (scalar example)"
		checks[2].source = "docs/CHANGELOG.md"
	}
	for _, tc := range checks {
		found := false
		for entry, sources := range entries {
			if strings.Join(strings.Fields(entry), " ") == tc.entry && slices.Contains(sources, tc.source) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("unmeasured prose entry %q from %s", tc.entry, tc.source)
		}
	}
	if _, ok := entries["by path>"]; ok {
		t.Error("schematic comma became a separate command")
	}
}

func TestOrdinaryCatalogIncludesShellAndFixtureContracts(t *testing.T) {
	entries := ordinaryEntries(t)
	for _, tc := range []struct{ entry, source string }{
		{"unshare", "examples/demo/scenes/features.sh (heredoc)"},
		{"true", "examples/demo/scenes/features.sh (heredoc)"},
		{"sudo", "examples/demo/scenes/features.sh (heredoc)"},
		{"id", "examples/demo/scenes/features.sh (heredoc)"},
		{"$PYTHON3", "examples/demo/scenes/network.sh (heredoc)"},
		{"dirname", "test/fixtures/ledger/kt4-pip-landlock/contract.yaml"},
		{"git", "test/fixtures/init/demo-repo/agent.yaml"},
	} {
		if !slices.Contains(entries[tc.entry], tc.source) {
			t.Errorf("unmeasured contract entry %q from %s", tc.entry, tc.source)
		}
	}
	if got, err := instantiateEntry("$PYTHON3"); err != nil || got != "/usr/bin/python3" {
		t.Errorf("script's interpreter role: %q, %v", got, err)
	}
}

// Read heredoc bodies as data. Never evaluate the scripts or expand their words.
// The shipped contracts use literal delimiters, with optional quoting and <<-.
func shellHeredocs(t *testing.T, data []byte) [][]byte {
	t.Helper()
	start := regexp.MustCompile(`<<(-?)[ \t]*['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?`)
	lines := strings.Split(string(data), "\n")
	var bodies [][]byte
	for i := 0; i < len(lines); i++ {
		matches := start.FindAllStringSubmatch(lines[i], -1)
		for _, m := range matches {
			var body []string
			closed := false
			for i++; i < len(lines); i++ {
				line := lines[i]
				if m[1] == "-" {
					line = strings.TrimLeft(line, "\t")
				}
				if line == m[2] {
					closed = true
					break
				}
				body = append(body, line)
			}
			if !closed {
				t.Fatalf("unterminated inventory heredoc %q", m[2])
			}
			bodies = append(bodies, []byte(strings.Join(body, "\n")))
		}
	}
	return bodies
}

// TestRetainedSourceCatalog keeps every reviewed input family in public cuts.
func TestRetainedSourceCatalog(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "source-catalog.json"))
	if err != nil {
		t.Fatal(err)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256(data)); got != "0d0113877b5a9c5f95a700e997127e185a107046332236798bb3ad6103712db9" {
		t.Fatalf("reviewed source catalog digest changed: %s", got)
	}
	var retained map[string]map[string][]string
	if err := json.Unmarshal(data, &retained); err != nil {
		t.Fatal(err)
	}
	for list, count := range map[string]int{"allow": 129, "deny": 52, "ask": 7} {
		if len(retained[list]) != count {
			t.Fatalf("retained %s inputs: %d, want %d", list, len(retained[list]), count)
		}
		entries := catalogEntries(t, list)
		for entry, sources := range retained[list] {
			if len(sources) == 0 {
				t.Fatalf("retained %s %q has no source", list, entry)
			}
			for _, source := range sources {
				if !slices.Contains(entries[entry], "historical source: "+source) {
					t.Errorf("lost retained %s %q from %s", list, entry, source)
				}
			}
		}
	}
}

func TestCatalogWithoutPrivateOverlay(t *testing.T) {
	tree := t.TempDir()
	for _, dir := range []string{"examples", "pkg/spec/presets", "spec/policy/conformance", "test/conformance", "test/fixtures", "docs", "spec/policy"} {
		if err := os.MkdirAll(filepath.Join(tree, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{"README.md", "CONTRIBUTING.md"} {
		if err := os.WriteFile(filepath.Join(tree, file), []byte("# Public fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(tree, "docs", "CHANGELOG.md"), []byte("`allow: [cargo build]`\n"), 0600); err != nil {
		t.Fatal(err)
	}
	entries := catalogEntriesAt(t, "allow", tree)
	if len(entries) != 129 {
		t.Fatalf("public-only tree lost catalog entries: %d", len(entries))
	}
	if !slices.Contains(entries["cargo build"], "docs/CHANGELOG.md") {
		t.Fatal("public changelog was not collected")
	}
	if !slices.Contains(entries["node --stack-trace-limit=5 a.js"], "historical source: docs/CHANGELOG.md (scalar example)") {
		t.Fatal("replaced private input was lost")
	}
	for _, sources := range entries {
		for _, source := range sources {
			if strings.HasPrefix(source, "tools/oss/") {
				t.Fatalf("historical input misreported as a current public source: %s", source)
			}
		}
	}
}
