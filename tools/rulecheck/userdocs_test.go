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

// The user docs (docs/site, which the website copies) tell a person what a command does and what it needs. Basic
// (tier landlock) needs no privilege; Plus and Max (tiers cgroup and bpflsm) and the adopt command need root and a
// kernel that offers them, and the release binary carries them as a build from source does (.goreleaser.yaml builds
// with -tags tegobpf). A page that names one without saying it needs root sends a user to a command that fails with a
// permission error. The Protection levels page states the rule, and these tests hold the pages to it: every paragraph
// that names a root tier by its technical name or adopt says in words that it needs root, the levels page states the
// rule, and every page carries the front matter the website's docs index lists it by.

const (
	// levelsPage is the page that states what the root tiers need.
	levelsPage = "docs/site/tiers.md"
	// rootRule is the levels page's statement of what Plus and Max need.
	rootRule = "Plus and Max need root"
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
// "root is needed", "as root", "with root", "sudo". Only prose counts (saysNeedsRoot drops code spans), so a command
// in backticks does not say it, and the bare noun in "the root tiers" does not either; `sudo` alone in backticks, as
// in "through `sudo`", is a word of the prose.
var needsRootRe = regexp.MustCompile(`(?i)\b(?:needs?|needed|requires?|required|requiring)\s+(?:to\s+(?:run|be|start)\s+(?:as\s+)?)?(?:the\s+)?root\b` +
	`|\broot\s+(?:is\s+)?(?:needed|required)\b` +
	`|\b(?:as|with|run by|started by)\s+root\b` +
	`|\bsudo\b`)

// saysNeedsRoot reports whether the prose of a paragraph says it needs root.
func saysNeedsRoot(text string) bool {
	return needsRootRe.MatchString(withoutCode(strings.ReplaceAll(text, "`sudo`", "sudo")))
}

// frontMatterRe matches a page's front matter: the website reads it as the page's title, summary and place in the
// docs index, not as a paragraph of the page.
var frontMatterRe = regexp.MustCompile(`(?s)\A---\n(.*?)\n---\n`)

// withoutFrontMatter blanks a page's front matter, keeping its newlines so line numbers stay the page's.
func withoutFrontMatter(text string) string {
	m := frontMatterRe.FindStringIndex(text)
	if m == nil {
		return text
	}
	return strings.Repeat("\n", strings.Count(text[:m[1]], "\n")) + text[m[1]:]
}

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

// userDocPages returns the page paths of pages (every key is a path like docs/site/x.md), sorted.
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
		visible := visibleText(withoutFrontMatter(pages[p]))
		for _, para := range paragraphs(visible) {
			if strings.Contains(para.text, staleLabel) {
				out = append(out, fmt.Sprintf("%s:%d: carries the label %q, which is no longer true: the release binary has the root tiers", p, para.line, staleLabel))
			}
			m := rootTierRe.FindString(para.text)
			if m == "" || saysNeedsRoot(para.text) {
				continue
			}
			out = append(out, fmt.Sprintf("%s:%d: names %q without saying in words, in the same paragraph, that it needs root", p, para.line, m))
		}
	}
	return out
}

// indexSections are the sections of the website's docs index; a page's front matter names one.
var indexSections = map[string]bool{"Get started": true, "Core concepts": true, "Agents": true, "Advanced usage": true,
	"Production": true, "Reference": true}

// indexFindings reports a levels page that does not state the root rule in its prose, and each page whose front
// matter lacks what the website's docs index lists it by: a title, a summary, a known section and an order.
func indexFindings(pages map[string]string) []string {
	var out []string
	if text, ok := pages[levelsPage]; !ok {
		out = append(out, levelsPage+" does not exist")
	} else {
		stated := false
		for _, para := range paragraphs(visibleText(withoutFrontMatter(text))) {
			if strings.Contains(withoutCode(para.text), rootRule) {
				stated = true
			}
		}
		if !stated {
			out = append(out, fmt.Sprintf("%s does not state %q in its prose", levelsPage, rootRule))
		}
	}
	for _, p := range userDocPages(pages) {
		m := frontMatterRe.FindStringSubmatch(pages[p])
		if m == nil {
			out = append(out, fmt.Sprintf("%s has no front matter, so the docs index does not list it", p))
			continue
		}
		fields := map[string]string{}
		for _, line := range strings.Split(m[1], "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok {
				fields[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
			}
		}
		for _, k := range []string{"title", "summary", "section", "order"} {
			if fields[k] == "" {
				out = append(out, fmt.Sprintf("%s has no %s: in its front matter, so the docs index does not list it", p, k))
			}
		}
		if s := fields["section"]; s != "" && !indexSections[s] {
			out = append(out, fmt.Sprintf("%s names section %q, which the docs index does not have", p, s))
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
	files, err := filepath.Glob(filepath.Join(root, "docs", "site", "*.md"))
	if err != nil {
		t.Fatal(err)
	}
	pages := map[string]string{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		pages["docs/site/"+filepath.Base(f)] = string(b)
	}
	if _, ok := pages[levelsPage]; !ok {
		t.Fatal(levelsPage + " does not exist")
	}
	return pages
}

// TestUserDocsNameRootRequirement: every paragraph of docs/site/*.md that names tier cgroup, tier bpflsm, adopt or
// the root tiers says in words that it needs root, and no page carries the old "not in the v0.1.0 binary" label.
func TestUserDocsNameRootRequirement(t *testing.T) {
	for _, f := range requirementFindings(loadUserDocs(t)) {
		t.Error(f)
	}
}

// TestUserDocsReadmeStatesRuleAndIndexesPages: the levels page states the root rule, and the docs index lists every
// page.
func TestUserDocsReadmeStatesRuleAndIndexesPages(t *testing.T) {
	for _, f := range indexFindings(loadUserDocs(t)) {
		t.Error(f)
	}
}

// TestUserDocsIndexListsEveryPage is the index's check under the name its text gives.
func TestUserDocsIndexListsEveryPage(t *testing.T) {
	pages := loadUserDocs(t)
	for _, f := range indexFindings(pages) {
		if strings.Contains(f, "docs index") {
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
		"docs/site/a.md": "# A\n\nRun `tego run --tier cgroup agent.yaml` for a cgroup limit.\n\n" +
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
		"docs/site/b.md": "# B\n\nTier cgroup needs root. Run `tego run --tier cgroup agent.yaml`.\n\n" +
			"The default tier is landlock and needs no privilege.\n\n" +
			"Not built yet. The adopt command is planned.\n\n" +
			"```sh\ntego adopt 1234\n\nsudo tego run --tier cgroup\n```\n\n" +
			"Run `sudo tego run --tier cgroup`.\n\n" +
			"Run tier 3 here. <!--\n\nneeds root\n\n-->\n\n" +
			"Use `needs root` to adopt it.\n\n" +
			"Tier bpflsm: root is required, and so is `bpf` in the boot list.\n\n" +
			"Adopt needs to run as root.\n\n" +
			"Tiers 2 and 3 require root.\n\n" +
			"Plus (`--tier cgroup`) runs through `sudo`.\n\n" +
			"With sudo, adopt moves a process in.\n\n" +
			"The tier of a rule is its priority.\n",
		"docs/site/e.md": "---\ntitle: E\ndescription: \"Govern a running agent with tego adopt.\"\n---\n\nTier cgroup runs with root.\n",
		"docs/site/c.md": "# C\n\nThe **cgroup** tier needs root, and tier-2 too.\n\n" +
			"Run `tego adopt 1`. <!-- needs root -->\n\n" +
			"```md\n<!-- not a comment: it is code -->\n```\n\n" +
			"<!-- tier 2 is commented out -->\n",
		"docs/site/d.md": "# D\n\nTier cgroup needs root, but it is " + staleLabel + ".\n",
	}
	want := []string{
		`docs/site/a.md:3: names "tier cgroup"`,
		`docs/site/a.md:5: names "tier: bpflsm"`,
		`docs/site/a.md:7: names "cgroup tier"`,
		`docs/site/a.md:9: names "adopt"`,
		`docs/site/a.md:11: names "Tiers 2"`,
		`docs/site/a.md:13: names "cgroup** tier"`,
		`docs/site/a.md:15: names "BPF LSM"`,
		`docs/site/a.md:17: names "bpflsm"`,
		`docs/site/a.md:19: names "tier-2"`,
		`docs/site/a.md:21: names "tier three"`,
		`docs/site/a.md:23: names "Adopting"`,
		`docs/site/a.md:25: names "adopted"`,
		`docs/site/b.md:7: names "adopt"`,
		`docs/site/b.md:9: names "adopt"`,
		`docs/site/b.md:15: names "tier cgroup"`,
		`docs/site/b.md:17: names "tier 3"`,
		`docs/site/b.md:23: names "adopt"`,
		`docs/site/c.md:5: names "adopt"`,
		`docs/site/d.md:3: carries the label "` + staleLabel + `"`,
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

// TestUserDocsIndexCheckFindsPlantedBreakage: a levels page without the root rule in its prose, a page with no front
// matter, one without a section or order, and one with a section the index lacks are each reported; pages that do
// everything are not.
func TestUserDocsIndexCheckFindsPlantedBreakage(t *testing.T) {
	fm := func(section, order string) string {
		return "---\ntitle: T\nsummary: \"S\"\nsection: " + section + "\norder: " + order + "\n---\n\n"
	}
	good := map[string]string{
		levelsPage:           fm("Core concepts", "3") + "Basic needs no root. " + rootRule + " through `sudo`.\n",
		"docs/site/rules.md": fm("Reference", "1") + "# R\n",
	}
	if got := indexFindings(good); len(got) != 0 {
		t.Errorf("complete pages were reported: %v", got)
	}
	bad := map[string]string{
		levelsPage:           fm("Core concepts", "3") + "Levels.\n\n`" + rootRule + "`\n",
		"docs/site/none.md":  "# N\n",
		"docs/site/half.md":  "---\ntitle: H\nsummary: S\n---\n\n# H\n",
		"docs/site/other.md": fm("Blog", "1") + "# O\n",
	}
	got := strings.Join(indexFindings(bad), "\n")
	for _, want := range []string{
		levelsPage + ` does not state "` + rootRule + `"`,
		"docs/site/none.md has no front matter",
		"docs/site/half.md has no section:",
		"docs/site/half.md has no order:",
		`docs/site/other.md names section "Blog"`,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("findings lack %q:\n%s", want, got)
		}
	}
	if got := indexFindings(map[string]string{"docs/site/rules.md": fm("Reference", "1")}); len(got) != 1 {
		t.Errorf("a missing levels page gave %v", got)
	}
}
