// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// Baseline is tools/fdcheck/baseline.txt (ADR 0023 A9): per excluded package, its count of raw sites by kind.
// The counts are exact: a package's measured counts equal its line, so a migration that removes sites lowers
// the line in the same commit, and the slack can never be spent again.
type Baseline map[string]map[string]int

// ParseBaseline reads the file: "# comment" lines, and one line per package, "dir kind=n kind=n ...".
func ParseBaseline(src []byte) (Baseline, error) {
	b := Baseline{}
	sc := bufio.NewScanner(bytes.NewReader(src))
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		if len(f) < 2 {
			return nil, fmt.Errorf("baseline.txt:%d: want \"dir kind=n ...\", have %q", line, t)
		}
		if _, dup := b[f[0]]; dup {
			return nil, fmt.Errorf("baseline.txt:%d: %s is listed twice", line, f[0])
		}
		counts := map[string]int{}
		for _, kv := range f[1:] {
			k, v, ok := strings.Cut(kv, "=")
			n, err := strconv.Atoi(v)
			if !ok || err != nil || n <= 0 {
				return nil, fmt.Errorf("baseline.txt:%d: %q is not kind=n with n > 0", line, kv)
			}
			if _, known := kindHelp[k]; !known {
				return nil, fmt.Errorf("baseline.txt:%d: unknown kind %q", line, k)
			}
			if _, dup := counts[k]; dup {
				return nil, fmt.Errorf("baseline.txt:%d: kind %s twice", line, k)
			}
			counts[k] = n
		}
		b[f[0]] = counts
	}
	return b, sc.Err()
}

// Total is the sum of every count.
func (b Baseline) Total() int {
	t := 0
	for _, m := range b {
		for _, n := range m {
			t += n
		}
	}
	return t
}

// KindTotals is each kind's count summed over the packages.
func (b Baseline) KindTotals() map[string]int {
	t := map[string]int{}
	for _, m := range b {
		for k, n := range m {
			t[k] += n
		}
	}
	return t
}

// Line formats one package's line.
func baselineLine(dir string, counts map[string]int) string {
	var kinds []string
	for k := range counts {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := []string{dir}
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s=%d", k, counts[k]))
	}
	return strings.Join(parts, " ")
}

// FormatBaseline writes a baseline file for measured counts.
func FormatBaseline(b Baseline) []byte {
	var dirs []string
	for d := range b {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	var out bytes.Buffer
	out.WriteString(baselineHeader)
	for _, d := range dirs {
		out.WriteString(baselineLine(d, b[d]) + "\n")
	}
	return out.Bytes()
}

const baselineHeader = `# ADR 0023 A9, the ratchet: each package not yet migrated to sys.FD, with its raw sites counted by kind
# (tools/fdcheck; the kinds are in tools/fdcheck/rules.go). The counts are exact: a commit that removes a site
# lowers its line, a package that reaches zero loses its line and its .golangci.yml exclusion, and no kind's
# total ever rises: a move of code between packages moves its counts, and nothing else raises a line (precommit
# and CI hold each kind's total, and the F4 lists', to the base). A package not listed here has no raw site.
# The file is empty when ADR 0023 is done.
`

// Site is one entry of an F4 list: a file, its enclosing function and the count of sites there.
type Site struct {
	File, Func string
	Count      int
}

// ParseSites reads an F4 list file: "# comment" lines and "file func count" lines.
func ParseSites(name string, src []byte) (map[[2]string]int, error) {
	out := map[[2]string]int{}
	sc := bufio.NewScanner(bytes.NewReader(src))
	line := 0
	for sc.Scan() {
		line++
		t := strings.TrimSpace(sc.Text())
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		f := strings.Fields(t)
		n := 0
		var err error
		if len(f) == 3 {
			n, err = strconv.Atoi(f[2])
		}
		if len(f) != 3 || err != nil || n <= 0 {
			return nil, fmt.Errorf("%s:%d: want \"file func count\", have %q", name, line, t)
		}
		out[[2]string{f[0], f[1]}] += n
	}
	return out, sc.Err()
}

// Config is what the checked-in files say.
type Config struct {
	Producers Producers
	Baseline  Baseline
	Sites     map[string]map[[2]string]int // by kind (adopt, abandon, inherited, stdio)
	Shrinking map[string]bool              // .golangci.yml's per-package ADR 0023 exclusions
}

// MeasuredBaseline is the baseline the findings meet, what -baseline prints: every raw site by package and kind,
// a listed kind's site counted when its list does not admit it, as Ratchet counts it.
func MeasuredBaseline(sites map[string]map[[2]string]int, findings []Finding) Baseline {
	raw, _ := admit(sites, findings)
	b := Baseline{}
	for _, f := range raw {
		if b[f.Pkg] == nil {
			b[f.Pkg] = map[string]int{}
		}
		b[f.Pkg][f.Kind]++
	}
	return b
}

// siteKey is one F4 list entry's site: a kind, a file and a function.
type siteKey struct{ kind, file, fn string }

// admit applies the F4 lists: listed sites are admitted up to their count, and the rest stay findings. It returns
// the findings left (the raw sites) and the listed kinds' sites by list entry.
func admit(sites map[string]map[[2]string]int, findings []Finding) ([]Finding, map[siteKey][]Finding) {
	seen := map[siteKey][]Finding{}
	var raw []Finding
	for _, f := range findings {
		if _, listed := listedKinds[f.Kind]; listed {
			k := siteKey{f.Kind, f.File, f.Func}
			seen[k] = append(seen[k], f)
			continue
		}
		raw = append(raw, f)
	}
	for k, fs := range seen {
		if allowed := sites[k.kind][[2]string{k.file, k.fn}]; len(fs) > allowed {
			raw = append(raw, fs[allowed:]...)
		}
	}
	return raw, seen
}

// Ratchet applies the lists and the baseline to the findings (A9, F4, F7). It returns the problems, each a
// line to print.
func Ratchet(cfg Config, findings []Finding) []string {
	var problems []string
	// F4: listed sites are admitted up to their count; the rest stay findings. A list entry with fewer sites
	// than it admits is stale, so the lists only shrink with the code.
	raw, seen := admit(cfg.Sites, findings)
	for kind, list := range cfg.Sites {
		for site, n := range list {
			if have := len(seen[siteKey{kind, site[0], site[1]}]); have < n {
				problems = append(problems, fmt.Sprintf("tools/fdcheck/%s: %s %s admits %d sites, the code has %d: lower or remove the entry",
					listedKinds[kind], site[0], site[1], n, have))
			}
		}
	}
	// F7: the per-package counts.
	byPkg := map[string][]Finding{}
	for _, f := range raw {
		byPkg[f.Pkg] = append(byPkg[f.Pkg], f)
	}
	var dirs []string
	for d := range byPkg {
		dirs = append(dirs, d)
	}
	for d := range cfg.Baseline {
		if _, ok := byPkg[d]; !ok {
			dirs = append(dirs, d)
		}
	}
	sort.Strings(dirs)
	for _, d := range dirs {
		fs := byPkg[d]
		base, listed := cfg.Baseline[d]
		measured := map[string]int{}
		for _, f := range fs {
			measured[f.Kind]++
		}
		switch {
		case !listed:
			for _, f := range fs {
				problems = append(problems, f.String())
			}
			problems = append(problems, fmt.Sprintf("%s: %d raw descriptor sites in a package that has none in tools/fdcheck/baseline.txt (ADR 0023 A9: no new raw site; make the number an owner)", d, len(fs)))
		case len(fs) == 0:
			problems = append(problems, fmt.Sprintf("tools/fdcheck/baseline.txt: %s has no raw site left: delete its line and its .golangci.yml exclusion", d))
		default:
			kinds := map[string]bool{}
			for k := range base {
				kinds[k] = true
			}
			for k := range measured {
				kinds[k] = true
			}
			var ks []string
			for k := range kinds {
				ks = append(ks, k)
			}
			sort.Strings(ks)
			for _, k := range ks {
				switch m, b := measured[k], base[k]; {
				case m > b:
					for _, f := range fs {
						if f.Kind == k {
							problems = append(problems, f.String())
						}
					}
					problems = append(problems, fmt.Sprintf("%s: %s sites rose from %d to %d (ADR 0023 A9: the count never rises; one of the sites above is new)", d, k, b, m))
				case m < b:
					problems = append(problems, fmt.Sprintf("%s: %s sites fell from %d to %d: write its line as %q in tools/fdcheck/baseline.txt", d, k, b, m, baselineLine(d, measured)))
				}
			}
		}
	}
	// A9: the baseline and .golangci.yml's shrinking exclusions name the same packages.
	var mismatch []string
	for d := range cfg.Baseline {
		if !cfg.Shrinking[d] {
			mismatch = append(mismatch, fmt.Sprintf(".golangci.yml: no ADR 0023 exclusion for %s, which tools/fdcheck/baseline.txt lists (add `- path: ^%s/[^/]+\\.go$` with linters [forbidigo] and text \"ADR 0023\")", d, regexp.QuoteMeta(d)))
		}
	}
	for d := range cfg.Shrinking {
		if _, ok := cfg.Baseline[d]; !ok {
			mismatch = append(mismatch, fmt.Sprintf(".golangci.yml: the ADR 0023 exclusion for %s names a package tools/fdcheck/baseline.txt does not list: delete it", d))
		}
	}
	sort.Strings(mismatch)
	return append(problems, mismatch...)
}

// shrinkingRE is one package's ADR 0023 exclusion path: ^dir/[^/]+\.go$, the package's own files only.
var shrinkingRE = regexp.MustCompile(`^\^(.+)/\[\^/\]\+\\\.go\$$`)

// golangciConfig is the part of .golangci.yml that decides whether forbidigo reports an ADR 0023 site.
type golangciConfig struct {
	Linters struct {
		Enable   []string `yaml:"enable"`
		Disable  []string `yaml:"disable"`
		Settings struct {
			Forbidigo struct {
				AnalyzeTypes bool `yaml:"analyze-types"`
				Forbid       []struct {
					Pattern string `yaml:"pattern"`
					Pkg     string `yaml:"pkg"`
					Msg     string `yaml:"msg"`
				} `yaml:"forbid"`
			} `yaml:"forbidigo"`
		} `yaml:"settings"`
		Exclusions yaml.Node `yaml:"exclusions"`
	} `yaml:"linters"`
}

// golangciTop are golangci-lint 2's top-level keys (pkg/config.Config); any other is refused, since fdcheck
// cannot say what it does.
var golangciTop = []string{"version", "run", "output", "linters", "issues", "severity", "formatters"}

// golangciIssues are the issues keys that only cap or merge the reports shown: the run still fails on any
// report. new, new-from-rev, new-from-merge-base, new-from-patch and whole-files hide every report outside a
// diff, fix rewrites the files, and an unknown key is not read.
var golangciIssues = []string{"max-issues-per-linter", "max-same-issues", "uniq-by-line"}

// golangciRun are the run keys that select neither files nor the exit code: build-tags and issues-exit-code
// are judged on their own (pkg/config.Run holds these and no others).
var golangciRun = []string{"timeout", "concurrency", "go", "relative-path-mode", "modules-download-mode",
	"enable-build-vcs", "tests", "allow-parallel-runners", "allow-serial-runners", "build-tags", "issues-exit-code"}

// lintTags are the build tags the lint must keep: forbidigo's typed rules see a tagged file only when its tag
// is on, and these files compile into the shipped and the KVM suites' binaries (.golangci.yml's run comment).
var lintTags = []string{"integration", "tegobpf", "tegotesthooks"}

// golangciBuildTags is .golangci.yml's run.build-tags, nil when it sets none.
func golangciBuildTags(src []byte) ([]string, error) {
	var c struct {
		Run struct {
			BuildTags []string `yaml:"build-tags"`
		} `yaml:"run"`
	}
	if err := config.GuardYAML(func() error { return yaml.Unmarshal(src, &c) }); err != nil {
		return nil, fmt.Errorf(".golangci.yml: %w", err)
	}
	return c.Run.BuildTags, nil
}

// containsAll reports whether have holds every element of want.
func containsAll(have, want []string) bool {
	for _, w := range want {
		if !contains(have, w) {
			return false
		}
	}
	return true
}

// golangciOuter fails on the parts of the file outside linters that could keep a forbidigo report from failing
// the run: a top-level key golangci-lint 2 does not have, an issues key other than golangciIssues, a run key
// other than golangciRun, an issues-exit-code other than 1, and build-tags without each of lintTags.
func golangciOuter(src []byte) error {
	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return fmt.Errorf(".golangci.yml: %w", err)
	}
	if len(doc.Content) != 1 || doc.Content[0].Kind != yaml.MappingNode {
		return fmt.Errorf(".golangci.yml: the file must be one mapping")
	}
	var run, issues *yaml.Node
	top := doc.Content[0].Content
	for i := 0; i+1 < len(top); i += 2 {
		k, v := top[i], top[i+1]
		if k.Tag == "!!merge" || !contains(golangciTop, k.Value) {
			return fmt.Errorf(".golangci.yml: top-level key %q is not golangci-lint 2's (%s)", k.Value, strings.Join(golangciTop, ", "))
		}
		switch k.Value {
		case "run":
			run = v
		case "issues":
			issues = v
		}
	}
	keys := func(n *yaml.Node, name string, allowed []string) (map[string]*yaml.Node, error) {
		out := map[string]*yaml.Node{}
		if n == nil {
			return out, nil
		}
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf(".golangci.yml: %s must be a mapping", name)
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Tag == "!!merge" || !contains(allowed, k.Value) {
				return nil, fmt.Errorf(".golangci.yml: %s.%s could keep an ADR 0023 report from failing the run: only %s may be set there", name, k.Value, strings.Join(allowed, ", "))
			}
			out[k.Value] = n.Content[i+1]
		}
		return out, nil
	}
	if _, err := keys(issues, "issues", golangciIssues); err != nil {
		return err
	}
	r, err := keys(run, "run", golangciRun)
	if err != nil {
		return err
	}
	// The exit code is pinned, not judged: golangci-lint does not check the value and the OS keeps its low byte, so
	// 256, 512, -256 or 0x100 exit 0 with reports. Only its default, 1, is known to fail the run,
	// written as a plain integer (a quoted "1" or a 1.0 is a value viper converts and fdcheck would have to guess).
	if v := r["issues-exit-code"]; v != nil && (v.Kind != yaml.ScalarNode || v.Tag != "!!int" || v.Value != "1") {
		return fmt.Errorf(".golangci.yml: run.issues-exit-code %q: leave it out or write 1, golangci-lint's default; any other value may let a run with reports exit 0", v.Value)
	}
	var tags []string
	if v := r["build-tags"]; v != nil {
		if err := v.Decode(&tags); err != nil {
			return fmt.Errorf(".golangci.yml: run.build-tags: %w", err)
		}
	}
	for _, t := range lintTags {
		if !contains(tags, t) {
			return fmt.Errorf(".golangci.yml: run.build-tags lacks %s: forbidigo's typed rules would not see the files that build only with it", t)
		}
	}
	return nil
}

// exclusionRule is one linters.exclusions.rules item, with every key golangci-lint 2 reads in one.
type exclusionRule struct {
	Path        string   `yaml:"path"`
	PathExcept  string   `yaml:"path-except"`
	Text        string   `yaml:"text"`
	Source      string   `yaml:"source"`
	Linters     []string `yaml:"linters"`
	keys        []string // the keys the item spells, in order
	hasKeyOther bool     // a key golangci-lint does not have, or a merge key
}

// ParseShrinking decodes .golangci.yml (YAML, as golangci-lint reads it: any quoting, block scalars, comments,
// block or flow lists) and returns the packages of the per-package ADR 0023 exclusions: rules with text
// "ADR 0023", linters [forbidigo] and a path of the form ^dir/[^/]+\.go$. It fails closed on anything that could
// keep forbidigo from reporting an ADR 0023 site where fdcheck's syntax cannot see it:
//   - outside linters (golangciOuter): an unknown top-level key, an issues diff mode or fix, a run key that is
//     not golangci-lint's, an issues-exit-code other than 1, and build-tags without lintTags;
//   - forbidigo not enabled, or disabled, or without analyze-types (its (*os.File).Fd rule needs the types);
//   - a linters.exclusions key other than rules and warn-unused (paths, paths-except and presets hide files or
//     reports wholesale), and generated other than disable: golangci-lint's default, lax, skips every file whose
//     header says it is generated, and a hand-written header is enough;
//   - a rule key golangci-lint does not have, or a YAML merge key;
//   - a rule that applies to forbidigo (it names it, or names no linter) and whose text is empty or could match an
//     ADR 0023 report, unless it is exactly one of A7's permanentExclusions or one package's own files, with the
//     keys path, linters [forbidigo] and text "ADR 0023" alone; a package with two such rules (A9).
//
// A forbidigo rule's text cannot match an ADR 0023 report only when it is a literal (golangci-lint matches it
// case-insensitively as a regular expression) that contains a space, no backtick or double quote, and occurs in
// another rule's message but in no ADR 0023 message and in neither words of the report's frame ("use of `x`
// forbidden because "msg""): the expression a report quotes is Go syntax, which has no such phrase.
func ParseShrinking(src []byte) (map[string]bool, error) {
	if err := golangciOuter(src); err != nil {
		return nil, err
	}
	var cfg golangciConfig
	if err := config.GuardYAML(func() error { return yaml.Unmarshal(src, &cfg) }); err != nil {
		return nil, fmt.Errorf(".golangci.yml: %w", err)
	}
	l := cfg.Linters
	if !contains(l.Enable, "forbidigo") || contains(l.Disable, "forbidigo") {
		return nil, fmt.Errorf(".golangci.yml: forbidigo must be in linters.enable and not in linters.disable: it reports ADR 0023's primitives")
	}
	if !l.Settings.Forbidigo.AnalyzeTypes {
		return nil, fmt.Errorf(".golangci.yml: linters.settings.forbidigo.analyze-types must be true: the (*os.File).Fd rule matches a method by its receiver's type")
	}
	var adr23, others []string // the forbidigo rules' messages
	for _, f := range l.Settings.Forbidigo.Forbid {
		if strings.Contains(f.Msg, "ADR 0023") {
			adr23 = append(adr23, f.Msg)
		} else {
			others = append(others, f.Msg)
		}
	}
	rules, err := exclusionRules(&l.Exclusions)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, it := range rules {
		if it.hasKeyOther {
			return nil, fmt.Errorf(".golangci.yml: exclusion %q has a key fdcheck does not read (%s): a rule may use path, path-except, text, source and linters", it.Path, strings.Join(it.keys, ", "))
		}
		if !hidesADR0023(it.Text, it.Linters, adr23, others) {
			continue
		}
		m := shrinkingRE.FindStringSubmatch(it.Path)
		exact := it.Text == "ADR 0023" && len(it.Linters) == 1 && it.Linters[0] == "forbidigo" &&
			strings.Join(it.keys, ",") == "linters,path,text"
		if !exact || (m == nil && !contains(permanentExclusions, it.Path)) {
			return nil, fmt.Errorf(".golangci.yml: exclusion %q (keys %s, text %q, linters %q) would hide ADR 0023's descriptor rules: only A7's two permanent exemptions and one `- path: ^dir/[^/]+\\.go$` rule per package tools/fdcheck/baseline.txt lists may, each with the keys path, linters [forbidigo] and text \"ADR 0023\" alone (A7, A9)",
				it.Path, strings.Join(it.keys, ","), it.Text, it.Linters)
		}
		if m == nil {
			continue // a permanent exemption
		}
		dir := strings.ReplaceAll(m[1], `\.`, ".")
		if strings.ContainsAny(dir, "|()[]*+?^$\\{}") {
			return nil, fmt.Errorf(".golangci.yml: ADR 0023 exclusion %q names more than one package; give each its own rule (A9)", it.Path)
		}
		if out[dir] {
			return nil, fmt.Errorf(".golangci.yml: two ADR 0023 exclusions for %s", dir)
		}
		out[dir] = true
	}
	return out, nil
}

// exclusionRules checks linters.exclusions' keys and decodes its rules, recording each rule's keys.
func exclusionRules(n *yaml.Node) ([]exclusionRule, error) {
	generated := ""
	var rules []exclusionRule
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf(".golangci.yml: linters.exclusions must be a mapping with generated: disable")
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		switch k.Value {
		case "generated":
			generated = v.Value
		case "warn-unused":
		case "rules":
			if v.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf(".golangci.yml: linters.exclusions.rules must be a list")
			}
			for _, item := range v.Content {
				if item.Kind != yaml.MappingNode {
					return nil, fmt.Errorf(".golangci.yml: linters.exclusions.rules item at line %d is not a mapping", item.Line)
				}
				var r exclusionRule
				if err := config.GuardYAML(func() error { return item.Decode(&r) }); err != nil {
					return nil, fmt.Errorf(".golangci.yml: linters.exclusions.rules: %w", err)
				}
				for j, name := range r.Linters {
					r.Linters[j] = strings.ToLower(name)
				}
				for j := 0; j+1 < len(item.Content); j += 2 {
					key := item.Content[j].Value
					r.keys = append(r.keys, key)
					if item.Content[j].Tag == "!!merge" || !contains([]string{"path", "path-except", "text", "source", "linters"}, key) {
						r.hasKeyOther = true
					}
				}
				sort.Strings(r.keys)
				rules = append(rules, r)
			}
		default:
			// paths, paths-except and presets hide whole files or reports from forbidigo too.
			return nil, fmt.Errorf(".golangci.yml: linters.exclusions.%s could hide ADR 0023's descriptor rules: only rules (A7, A9), warn-unused and generated: disable may be set", k.Value)
		}
	}
	if generated != "disable" {
		return nil, fmt.Errorf(".golangci.yml: linters.exclusions.generated is %q: it must be disable, or a file whose header says it is generated is not linted for ADR 0023's rules", generated)
	}
	return rules, nil
}

// hidesADR0023 is whether an exclusion rule with this text and these linters could hide an ADR 0023 forbidigo
// report: it applies to forbidigo (no linters means every linter), and its text is not provably another rule's
// marker (ParseShrinking's comment says when it is).
func hidesADR0023(text string, linters, adr23, others []string) bool {
	if len(linters) > 0 && !contains(linters, "forbidigo") {
		return false
	}
	if text == "" || regexp.QuoteMeta(text) != text || !strings.Contains(text, " ") || strings.ContainsAny(text, "`\"") {
		return true
	}
	low := strings.ToLower(text)
	for _, frame := range []string{"use of ", " forbidden because "} {
		if strings.Contains(frame, low) {
			return true
		}
	}
	for _, m := range adr23 {
		if strings.Contains(strings.ToLower(m), low) {
			return true
		}
	}
	for _, m := range others {
		if strings.Contains(strings.ToLower(m), low) {
			return false
		}
	}
	return true
}
