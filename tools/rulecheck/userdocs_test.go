// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

// The user guide (docs/user) tells a person what a command does and what it needs. Tier landlock needs no privilege;
// Tego's root tiers (cgroup and BPF-LSM) and the adopt command need root and a kernel that offers them, and the
// release binary carries them as a build from source does (.goreleaser.yaml builds with -tags tegobpf). A page that
// names one without saying it needs root sends a user to a command that fails with a permission error.
// docs/user/README.md states the rule, and these tests hold the pages to it: every paragraph that names a root tier
// or adopt says in words that it needs root, the README defining that rule and the one label "Not built yet." word
// for word, and the README indexing every page.

const (
	// rootRule opens the README paragraph that states what the root tiers and adopt need.
	rootRule = "Tier cgroup, tier bpflsm and adopt need root."
	// labelNotBuilt marks a statement about a feature that has no code.
	labelNotBuilt = "Not built yet."
	// staleLabel is the words of the label this guide used before the release carried the root tiers: it said the
	// release binary lacked them. No page may say so now.
	staleLabel = "not in the v0.1.0 binary"
)

// rootTierRe matches the words that name a root tier or the adopt command: "tier cgroup", "tier: bpflsm",
// "tier-2", "tier three", "tiers 2 and 3", "the cgroup tier", "the **cgroup** tier", "the BPF LSM tier", a bare
// "bpflsm" or "BPF-LSM", "root tiers", and "adopt" in any form ("tego adopt", "adopts", "adopted", "adopting",
// "adoption"). Markup (asterisks, underscores, backticks, quotes) and a hyphen may stand between the words. A
// paragraph that uses one of these words of something else says it needs root anyway or uses a different word; the
// false match costs one phrase, and a missed match sends a user to a command that fails without root.
var rootTierRe = regexp.MustCompile(`(?i)(?:\btiers?[\s:=*_"'` + "`" + `-]*(?:cgroup|bpf[- ]?lsm|[23]|two|three)\b` +
	`|\bcgroup[*_"'` + "`" + `]*[\s-]+tiers?\b` +
	`|\bbpf[- ]?lsm\b` +
	`|\broot[- ]tiers?\b` +
	`|\badopt(?:s|ed|ing|ion)?\b)`)

// needsRootRe matches the words that say a root tier or adopt needs root: "needs root", "need root", "requires root",
// "root is needed", "as root", "sudo". Only prose counts (withoutCode drops code spans), so a command in
// backticks does not say it, and the bare noun in "the root tiers" does not either.
var needsRootRe = regexp.MustCompile(`(?i)\b(?:needs?|needed|requires?|required|requiring)\s+(?:to\s+(?:run|be|start)\s+(?:as\s+)?)?(?:the\s+)?root\b` +
	`|\broot\s+(?:is\s+)?(?:needed|required)\b` +
	`|\b(?:as|run by|started by)\s+root\b` +
	`|\bsudo\b`)

// inlineCodeRe matches an inline code span.
var inlineCodeRe = regexp.MustCompile("`[^`\\n]*`")

// visibleText blanks what a reader of the rendered page does not see: an HTML comment outside a fenced code
// block. It keeps every newline, so a line number in the result is the line number in the page.
func visibleText(text string) string {
	lines := strings.Split(text, "\n")
	fence, inComment := "", false
	for i, line := range lines {
		t := strings.TrimLeft(line, " ")
		if fence != "" {
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
			continue
		}
		if !inComment && (strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~")) {
			fence = t[:3]
			continue
		}
		b := []byte(line)
		for pos := 0; pos < len(b); {
			if !inComment {
				j := strings.Index(string(b[pos:]), "<!--")
				if j < 0 {
					break
				}
				pos += j
				inComment = true
			}
			end := strings.Index(string(b[pos:]), "-->")
			stop := len(b)
			if end >= 0 {
				stop = pos + end + 3
				inComment = false
			}
			for k := pos; k < stop; k++ {
				b[k] = ' '
			}
			pos = stop
		}
		lines[i] = string(b)
	}
	return strings.Join(lines, "\n")
}

// withoutCode drops the fenced code blocks and inline code spans of a paragraph: a label inside code is a
// string a reader would type, not a label that tells them anything.
func withoutCode(text string) string {
	var kept []string
	fence := ""
	for _, line := range strings.Split(text, "\n") {
		t := strings.TrimLeft(line, " ")
		switch {
		case fence != "":
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
		case strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~"):
			fence = t[:3]
		default:
			kept = append(kept, line)
		}
	}
	return inlineCodeRe.ReplaceAllString(strings.Join(kept, "\n"), " ")
}

// paragraph is a run of lines between blank lines; a fenced code block is part of the paragraph it sits in, and
// its blank lines do not end it.
type paragraph struct {
	line int // the 1-based line the paragraph starts on
	text string
}

func paragraphs(text string) []paragraph {
	var out []paragraph
	var cur []string
	start, fence := 0, ""
	flush := func() {
		if len(cur) > 0 {
			out = append(out, paragraph{start, strings.Join(cur, "\n")})
		}
		cur = nil
	}
	for i, line := range strings.Split(text, "\n") {
		t := strings.TrimLeft(line, " ")
		switch {
		case fence != "":
			cur = append(cur, line)
			if strings.HasPrefix(t, fence) {
				fence = ""
			}
		case strings.TrimSpace(line) == "":
			flush()
		default:
			if len(cur) == 0 {
				start = i + 1
			}
			cur = append(cur, line)
			if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
				fence = t[:3]
			}
		}
	}
	flush()
	return out
}

// userDocPages returns the page paths of pages (every key is a path like docs/user/x.md), sorted.
func userDocPages(pages map[string]string) []string {
	var names []string
	for p := range pages {
		names = append(names, p)
	}
	sort.Strings(names)
	return names
}

// requirementFindings reports, for every page, each paragraph that names a root tier or adopt and does not say in
// prose that it needs root, and each page that still carries the label staleLabel.
func requirementFindings(pages map[string]string) []string {
	var out []string
	for _, p := range userDocPages(pages) {
		visible := visibleText(pages[p])
		for _, para := range paragraphs(visible) {
			if strings.Contains(para.text, staleLabel) {
				out = append(out, fmt.Sprintf("%s:%d: carries the label %q, which is no longer true: the release binary has the root tiers", p, para.line, staleLabel))
			}
			m := rootTierRe.FindString(para.text)
			if m == "" || needsRootRe.MatchString(withoutCode(para.text)) {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: names %q without saying in words, in the same paragraph, that it needs root", p, para.line, m))
		}
	}
	return out
}

// readmeFindings reports a README that does not state the root rule and define the label word for word at the start
// of a paragraph, and each page that the README does not link.
func readmeFindings(pages map[string]string) []string {
	const readme = "docs/user/README.md"
	text, ok := pages[readme]
	if !ok {
		return []string{readme + " does not exist"}
	}
	var out []string
	for _, label := range []string{rootRule, labelNotBuilt} {
		defined := false
		for _, para := range paragraphs(visibleText(text)) {
			if strings.HasPrefix(para.text, label) {
				defined = true
			}
		}
		if !defined {
			out = append(out, fmt.Sprintf("%s does not state %q at the start of a paragraph", readme, label))
		}
	}
	for _, p := range userDocPages(pages) {
		if p == readme {
			continue
		}
		name := filepath.Base(p)
		if !strings.Contains(text, "]("+name+")") && !strings.Contains(text, "]("+name+"#") {
			out = append(out, fmt.Sprintf("%s does not link %s", readme, p))
		}
	}
	return out
}

func loadUserDocs(t *testing.T) map[string]string {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(root, "docs", "user", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pages["docs/user/"+filepath.Base(f)] = string(b)
	}
	if _, ok := pages["docs/user/README.md"]; !ok {
		t.Fatal("docs/user/README.md does not exist")
	}
	return pages
}

// TestUserDocsNameRootRequirement: every paragraph of docs/user/*.md that names tier cgroup, tier bpflsm, adopt or
// the root tiers says in words that it needs root, and no page carries the old "not in the v0.1.0 binary" label.
func TestUserDocsNameRootRequirement(t *testing.T) {
	for _, f := range requirementFindings(loadUserDocs(t)) {
		t.Error(f)
	}
}

// TestUserDocsReadmeStatesRuleAndIndexesPages: the README states the root rule and defines the label verbatim, and
// links every page.
func TestUserDocsReadmeStatesRuleAndIndexesPages(t *testing.T) {
	for _, f := range readmeFindings(loadUserDocs(t)) {
		t.Error(f)
	}
}

// TestUserDocsIndexListsEveryPage is the README index's check under the name its text gives.
func TestUserDocsIndexListsEveryPage(t *testing.T) {
	pages := loadUserDocs(t)
	for _, f := range readmeFindings(pages) {
		if strings.Contains(f, "does not link") {
			t.Error(f)
		}
	}
}

// TestUserDocsRequirementCheckFindsPlantedBreakage tests the requirement test with fixture pages: each way a
// paragraph names a root tier or adopt without saying in words that it needs root is reported, with the line it
// starts on. A paragraph that says it in prose, names nothing, or has the words only in a code span, a code block or
// an HTML comment (the last is not shown to a reader) is judged on what is left. The stale label is reported
// wherever it stands.
func TestUserDocsRequirementCheckFindsPlantedBreakage(t *testing.T) {
	pages := map[string]string{
		"docs/user/a.md": "# A\n\nRun `tego run --tier cgroup agent.yaml` for a cgroup limit.\n\n" +
			"Set tier: bpflsm in the contract.\n\n" +
			"The cgroup tier and the BPF-LSM tier are the root tiers.\n\n" +
			"Use tego adopt to bring a running agent in.\n\n" +
			"Tiers 2 and 3 are stronger.\n\n" +
			"Use the **cgroup** tier.\n\n" +
			"The BPF LSM tier decides.\n\n" +
			"Set `tier` to `bpflsm`.\n\n" +
			"Run tier-2.\n\n" +
			"Run tier three.\n\n" +
			"Adopting a running agent.\n\n" +
			"tego adopted it.\n\n" +
			"With tier: auto as root, tego picks cgroup or bpflsm.\n\n",
		"docs/user/b.md": "# B\n\nTier cgroup needs root. Run `tego run --tier cgroup agent.yaml`.\n\n" +
			"The default tier is landlock and needs no privilege.\n\n" +
			labelNotBuilt + " The adopt command is planned.\n\n" +
			"```sh\ntego adopt 1234\n\nsudo tego run --tier cgroup\n```\n\n" +
			"Run `sudo tego run --tier cgroup`.\n\n" +
			"Run tier 3 here. <!--\n\nneeds root\n\n-->\n\n" +
			"Use `needs root` to adopt it.\n\n" +
			"Tier bpflsm: root is required, and so is `bpf` in the boot list.\n\n" +
			"Adopt needs to run as root.\n\n" +
			"Tiers 2 and 3 require root.\n\n" +
			"With sudo, adopt moves a process in.\n\n" +
			"The tier of a rule is its priority.\n",
		"docs/user/c.md": "# C\n\nThe **cgroup** tier needs root, and tier-2 too.\n\n" +
			"Run `tego adopt 1`. <!-- needs root -->\n\n" +
			"```md\n<!-- not a comment: it is code -->\n```\n\n" +
			"<!-- tier 2 is commented out -->\n",
		"docs/user/d.md": "# D\n\nTier cgroup needs root, but it is " + staleLabel + ".\n",
	}
	want := []string{
		`docs/user/a.md:3: names "tier cgroup"`,
		`docs/user/a.md:5: names "tier: bpflsm"`,
		`docs/user/a.md:7: names "cgroup tier"`,
		`docs/user/a.md:9: names "adopt"`,
		`docs/user/a.md:11: names "Tiers 2"`,
		`docs/user/a.md:13: names "cgroup** tier"`,
		`docs/user/a.md:15: names "BPF LSM"`,
		`docs/user/a.md:17: names "bpflsm"`,
		`docs/user/a.md:19: names "tier-2"`,
		`docs/user/a.md:21: names "tier three"`,
		`docs/user/a.md:23: names "Adopting"`,
		`docs/user/a.md:25: names "adopted"`,
		`docs/user/b.md:7: names "adopt"`,
		`docs/user/b.md:9: names "adopt"`,
		`docs/user/b.md:15: names "tier cgroup"`,
		`docs/user/b.md:17: names "tier 3"`,
		`docs/user/b.md:23: names "adopt"`,
		`docs/user/c.md:5: names "adopt"`,
		`docs/user/d.md:3: carries the label "` + staleLabel + `"`,
	}
	got := requirementFindings(pages)
	if len(got) != len(want) {
		t.Fatalf("findings:\n%s\nwant %d starting:\n%s", strings.Join(got, "\n"), len(want), strings.Join(want, "\n"))
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("finding %d = %q, want prefix %q", i, got[i], want[i])
		}
	}
}

// TestUserDocsReadmeCheckFindsPlantedBreakage: a README without the root rule, with the label mid-paragraph, and one
// that does not link a page are each reported; a README that does everything is not.
func TestUserDocsReadmeCheckFindsPlantedBreakage(t *testing.T) {
	good := rootRule + " text.\n\n" + labelNotBuilt + " text.\n\n| [Limits](limits.md) | x |\n| [Rules](rules.md#top) | y |\n"
	if got := readmeFindings(map[string]string{
		"docs/user/README.md": good, "docs/user/limits.md": "# L\n", "docs/user/rules.md": "# R\n",
	}); len(got) != 0 {
		t.Errorf("a complete README was reported: %v", got)
	}
	bad := map[string]string{
		"docs/user/README.md": "Intro. " + rootRule + "\n\n" + labelNotBuilt + "\n\n[Limits](limits.md)\n",
		"docs/user/limits.md": "# L\n", "docs/user/rules.md": "# R\n",
	}
	got := strings.Join(readmeFindings(bad), "\n")
	for _, want := range []string{
		`does not state "` + rootRule + `"`,
		"does not link docs/user/rules.md",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("findings lack %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, labelNotBuilt) || strings.Contains(got, "limits.md") {
		t.Errorf("findings report what is right:\n%s", got)
	}
	if got := readmeFindings(map[string]string{"docs/user/limits.md": "# L\n"}); len(got) != 1 {
		t.Errorf("a missing README gave %v", got)
	}
}
