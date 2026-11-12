// SPDX-License-Identifier: Apache-2.0

// Command rulecheck reads the rule IDs of the P0 component specs (docs/p0/*.md) and checks the references to
// them: the first step of ADR 0030's tools/rulecheck, before its rename to prefixed IDs.
//
// A document defines its rules in three sections: business rules (R) in §5, edge cases (E) in §6 and invariants
// (I) in §8. A definition is a bold ID at the start of a line (`**R15 — ...**`, `- **R36.**`, `1. **E1**`,
// `**R-cap**`), a bold ID opening a run-in rule (`**R8a**: ...`), an ID opening a sentence in a run-on paragraph
// (`I6. ...`, agent-contract.md's form), or, in §6 and §8, a numbered item (`20. ...`), which is E20 or I20. A
// rule's body runs to the next definition or the section's end; its lettered parts are the `(a)`, `(b)`, ... in
// it, other rules' parts it cites left out.
//
// Findings that fail, in the specs and in the other docs/**/*.md and spec/**/*.md: an ID defined twice in one
// document; a reference to a lettered part the rule does not have (`R29 (l)` in its own document, or another
// document's name, an ID and a letter); a reference that names a P0 document and an ID or `§6 case N` that
// document does not define, the document named by its bare name, as a Markdown link's target or in backquotes;
// a bare numbered R ID, outside a Changes list, that the document itself does not define and no other source
// (FEATURES.md, supervisor) names just before it. The same references in Go comments are reported, not
// failed. Reported, never failing: every rule no test mentions, where a test mentions a rule when its body names a test function that
// exists, or a _test.go file names both the document and the ID.
//
// A rule whose first line carries "(withdrawn)" stays defined (references to it resolve) but is left out of every
// coverage count.
//
// With -strict the report adds the stricter measure: a rule is strictly covered only when a _test.go file that
// names its document has, in the doc comment of a Test or Fuzz function (or in the name given to one of its
// t.Run calls), the ID. Report only, like the file-level count.
//
// The stale-status check (ticketstatus.go) fails a tier-3 ticket that docs/p0/TIER3-PLAN.md marks built and
// docs/FEATURES.md or spec/backend/CAPABILITIES.md lists as not built.
//
// The link check (links.go) fails a relative Markdown link, in any documentation file but the agents' working
// notes, whose target does not exist or whose #anchor the target Markdown file does not define.
//
// The bare-name check (mdnames.go) fails a Markdown file named by its bare name, in those documents or in a Go
// comment, that no Markdown file of the repository has: a citation of a working note outside the tree.
//
// Usage: go run ./tools/rulecheck [-v] [-strict] [root]   (root defaults to the working directory; -v lists the
// untested rules by ID, not only their count; -strict adds the strict count and, always, its list). Exit: 0 when nothing fails, 1 when something does, 2 on a read error.
//
// Imports: standard library only.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Rule is one defined rule.
type Rule struct {
	Doc, ID string
	Line    int
	// Body is the rule's text, from its definition to the next one or the section's end.
	Body string
	// Parts are the lettered parts the body holds, "a" for (a).
	Parts map[string]bool
	// Withdrawn is set when the definition's first line carries the marker "(withdrawn)" (`33. *(withdrawn)
	// 2026-09-24.*`, `**E33 (withdrawn).**`). A withdrawn rule stays defined, so references to it still
	// resolve, but no coverage count includes it.
	Withdrawn bool
}

// withdrawnRe is the marker on a definition's first line.
var withdrawnRe = regexp.MustCompile(`(?i)\(withdrawn\)`)

// Live returns the number of the document's rules that are not withdrawn.
func (d *Doc) Live() int {
	n := 0
	for _, r := range d.Rules {
		if !r.Withdrawn {
			n++
		}
	}
	return n
}

// Doc is one spec document's rules.
type Doc struct {
	Name  string // file name, "runtime-launch.md"
	Base  string // "runtime-launch"
	Rules map[string]*Rule
	// Dups are the IDs defined more than once, with the lines of every definition.
	Dups map[string][]int
	text string
}

var (
	sectionRe = regexp.MustCompile(`(?m)^## (\d+)\. `)
	// idForm is an ID: R/E/I and a number with optional letters, or R and a hyphenated name (R-cap).
	idForm = `[RIE](?:\d+[a-z]*|-[a-z][a-z-]*[a-z])`
	// boldDef is a bold ID at a line's start, after an optional list marker: `**R15 — ...**`, `- **R36.**`.
	boldDef = regexp.MustCompile(`(?m)^[ \t]*(?:[-*] |\d+\. )?\*\*(` + idForm + `)(?:\*\*|[ .:—(])`)
	// runInDef is a bold ID opening a run-in rule inside a paragraph: `**R8a**: ...`, `**R14 — title**`,
	// `**R13b (unconnected):**`. A bold ID followed by anything else (`**R27** assigns`) is a reference.
	runInDef = regexp.MustCompile(`\*\*(` + idForm + `)(?:\*\*:|:| —| \([^)]{1,40}\):?\*\*)`)
	// inlineDef is an ID opening a sentence, at a line's start or after ". ": "I6. This package", "E29 (new). A".
	inlineDef = regexp.MustCompile(`(?m)(?:^|\. )([IE]\d+[a-z]?)(?: \([^)]{1,20}\))?\. [A-Z*(` + "`" + `]`)
	// caseDef is a numbered item of §6 or §8 at a line's start.
	caseDef = regexp.MustCompile(`(?m)^(\d+)\. `)
	partRe  = regexp.MustCompile(`\(([a-z])\)`)
	// refParts is a reference to another rule's parts, `R1 (e), (f)`, which is no part of the rule it sits in.
	refParts = regexp.MustCompile(idForm + ` ?\([a-z]\)(?:,? (?:and |or )?\([a-z]\))*`)
)

// kindOf is the ID letter each section defines.
var kindOf = map[string]byte{"5": 'R', "6": 'E', "8": 'I'}

// ParseDoc reads the rules of one document's text.
func ParseDoc(name, text string) *Doc {
	d := &Doc{Name: name, Base: strings.TrimSuffix(name, ".md"), Rules: map[string]*Rule{}, Dups: map[string][]int{}, text: text}
	secs := sectionRe.FindAllStringSubmatchIndex(text, -1)
	spans := changesSpans(text)
	blanked := withoutChanges(text)
	for i, s := range secs {
		num := text[s[2]:s[3]]
		kind, ok := kindOf[num]
		if !ok {
			continue
		}
		start, end := s[1], len(text)
		if i+1 < len(secs) {
			end = secs[i+1][0]
		}
		// The trailing "Changes." list and the flagged-conflict sections are history, not definitions.
		body := blanked[start:end]
		type def struct {
			id  string
			pos int
		}
		var defs []def
		seen := map[int]bool{}
		add := func(id string, pos int) {
			if id[0] != kind || seen[pos] {
				return
			}
			seen[pos] = true
			defs = append(defs, def{id, start + pos})
		}
		for _, m := range boldDef.FindAllStringSubmatchIndex(body, -1) {
			add(body[m[2]:m[3]], m[2]-2)
		}
		for _, m := range runInDef.FindAllStringSubmatchIndex(body, -1) {
			add(body[m[2]:m[3]], m[2]-2)
		}
		for _, m := range inlineDef.FindAllStringSubmatchIndex(body, -1) {
			add(body[m[2]:m[3]], m[2])
		}
		if kind == 'E' || kind == 'I' {
			for _, m := range caseDef.FindAllStringSubmatchIndex(body, -1) {
				line := body[m[0]:]
				if nl := strings.IndexByte(line, '\n'); nl >= 0 {
					line = line[:nl]
				}
				if boldDef.MatchString(line) {
					continue // "1. **E1** ..." is the bold form, already read
				}
				add(string(kind)+body[m[2]:m[3]], m[0])
			}
		}
		sort.Slice(defs, func(a, b int) bool { return defs[a].pos < defs[b].pos })
		for j, df := range defs {
			bend := end
			if j+1 < len(defs) {
				bend = defs[j+1].pos
			}
			// A Changes list inside the definition's span is history, not part of the rule.
			for _, sp := range spans {
				if sp[0] > df.pos && sp[0] < bend {
					bend = sp[0]
					break
				}
			}
			line := 1 + strings.Count(text[:df.pos], "\n")
			if prev, dup := d.Rules[df.id]; dup {
				if len(d.Dups[df.id]) == 0 {
					d.Dups[df.id] = []int{prev.Line}
				}
				d.Dups[df.id] = append(d.Dups[df.id], line)
				// Parts of every definition count, so a reference to either is not reported twice.
				for _, p := range partRe.FindAllStringSubmatch(refParts.ReplaceAllString(text[df.pos:bend], ""), -1) {
					prev.Parts[p[1]] = true
				}
				continue
			}
			r := &Rule{Doc: name, ID: df.id, Line: line, Body: text[df.pos:bend], Parts: map[string]bool{}}
			for _, p := range partRe.FindAllStringSubmatch(refParts.ReplaceAllString(r.Body, ""), -1) {
				r.Parts[p[1]] = true
			}
			first := r.Body
			if nl := strings.IndexByte(first, '\n'); nl >= 0 {
				first = first[:nl]
			}
			r.Withdrawn = withdrawnRe.MatchString(first)
			d.Rules[df.id] = r
		}
	}
	return d
}

// Finding is one failing check.
type Finding struct {
	Doc  string
	Line int
	What string
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.Doc, f.Line, f.What) }

// Check returns the failing findings over a set of documents: duplicates, and references (from the documents
// themselves and from the extra sources, name to text) to lettered parts or IDs that do not exist.
func Check(docs map[string]*Doc, extra map[string]string) []Finding {
	var out []Finding
	for _, d := range docs {
		for id, lines := range d.Dups {
			out = append(out, Finding{d.Name, lines[0], fmt.Sprintf("%s is defined %d times (lines %v)", id, len(lines), lines)})
		}
	}
	sources := map[string]string{}
	for _, d := range docs {
		sources[d.Name] = d.text
	}
	for n, t := range extra {
		sources[n] = t
	}
	return sortFindings(append(out, CheckRefs(docs, sources)...))
}

// CheckRefs returns the references in sources (name to text) to lettered parts or IDs that do not exist. A
// source named like a document (runtime-launch.md) is that document, whose bare lettered references are checked
// against its own rules as well.
func CheckRefs(docs map[string]*Doc, sources map[string]string) []Finding {
	var out []Finding
	names := make([]string, 0, len(docs))
	for _, d := range docs {
		names = append(names, regexp.QuoteMeta(d.Base))
	}
	sort.Strings(names)
	// A named reference: a P0 document, optionally its section, then an ID or "case N", optionally a part.
	// The name may be a Markdown link's target, `[x](supervisor.md#anchor) R1`, or in backquotes.
	crossRe := regexp.MustCompile(`\b(` + strings.Join(names, "|") + `)(?:\.md)?(?:#[\w.-]*)?(?:\)|` + "`" + `)?(?:'s)?,? ` +
		`(?:§\s?(\d+)(?:\.\d+)?,? )?` +
		`(?:case (\d+)|(` + idForm + `))\b(?: ?\(([a-z])\))?`)
	// A bare reference with a part, in the document that defines the ID.
	localRe := regexp.MustCompile(`(^|[^\w.-])(` + idForm + `) ?\(([a-z])\)`)
	// otherRe ends in an ID named with a source: a document (FEATURES.md, a P0 name, SEMANTICS), maybe as a link
	// or in backquotes, its section, then a run of IDs (FEATURES.md E13, E50, E51; supervisor E10/E11).
	otherRe := regexp.MustCompile(`(?:[\w-]+\.md(?:#[\w.-]*)?|\b[A-Z][A-Z0-9-]{2,}|\b(?:` + strings.Join(names, "|") + `))` +
		"[`)]?(?:'s)?,? (?:§\\s?\\d+(?:\\.\\d+)*,? )?(?:(?:" + idForm + `)(?: ?\([a-z0-9]\))?(?:,|/| and| or|;)?\s+)*` +
		`(?:` + idForm + `)$`)
	// bareRe is a business rule's ID with no source named, which in a spec is that spec's own rule. Only numbered
	// R IDs: the specs cite FEATURES.md's E and I numbers bare often enough that a bare E or I is no local claim.
	bareRe := regexp.MustCompile(`(^|[^\w.\-/#])(R\d+[a-z]*)\b`)
	for src, text := range sources {
		self := docs[src]
		for _, m := range crossRe.FindAllStringSubmatchIndex(text, -1) {
			target := docs[text[m[2]:m[3]]+".md"]
			if target == nil {
				continue
			}
			var id string
			switch {
			case m[6] >= 0:
				if m[4] >= 0 && text[m[4]:m[5]] != "6" {
					continue // "case N" names an edge case only in §6
				}
				id = "E" + text[m[6]:m[7]]
			case m[8] >= 0:
				id = text[m[8]:m[9]]
			}
			line := 1 + strings.Count(text[:m[0]], "\n")
			r := target.Rules[id]
			if r == nil {
				out = append(out, Finding{src, line, fmt.Sprintf("%q names %s, which %s does not define", text[m[0]:m[1]], id, target.Name)})
				continue
			}
			if m[10] >= 0 {
				if p := text[m[10]:m[11]]; !r.Parts[p] {
					out = append(out, Finding{src, line, fmt.Sprintf("%q: %s %s has no part (%s)", text[m[0]:m[1]], target.Name, id, p)})
				}
			}
		}
		if self == nil {
			continue
		}
		for _, m := range localRe.FindAllStringSubmatchIndex(text, -1) {
			id, p := text[m[4]:m[5]], text[m[6]:m[7]]
			// A reference named with another document is the cross check's.
			if namedBefore(crossRe, text[max(0, m[0]-80):m[4]]+id) {
				continue
			}
			r := self.Rules[id]
			if r == nil || r.Parts[p] {
				continue
			}
			line := 1 + strings.Count(text[:m[0]], "\n")
			out = append(out, Finding{src, line, fmt.Sprintf("%s (%s): %s has no part (%s)", id, p, id, p)})
		}
		// A bare ID the document does not define, outside its Changes lists (history names removed rules).
		body := withoutChanges(text)
		for _, m := range bareRe.FindAllStringSubmatchIndex(body, -1) {
			id := body[m[4]:m[5]]
			if self.Rules[id] != nil || (m[5] < len(body) && body[m[5]] == '-') {
				continue
			}
			before := body[max(0, m[4]-160):m[5]]
			if namedBefore(crossRe, before) || otherRe.MatchString(before) {
				continue
			}
			line := 1 + strings.Count(text[:m[4]], "\n")
			out = append(out, Finding{src, line, fmt.Sprintf("%s names no rule this document defines", id)})
		}
	}
	return sortFindings(out)
}

// changesSpans finds each "**Changes.**" list as a byte range. A list ends at the section's end or at the first
// blank line followed by something that is neither a list item nor an indented continuation, so a rule defined
// after the list (a mid-section Changes list) is not swallowed.
func changesSpans(text string) [][2]int {
	var out [][2]int
	for i := 0; ; {
		c := strings.Index(text[i:], "\n**Changes.**")
		if c < 0 {
			break
		}
		c += i
		end := len(text)
		if n := strings.Index(text[c+1:], "\n## "); n >= 0 {
			end = c + 1 + n
		}
		// Walk the lines after the marker.
		pos := c + 1
		if nl := strings.IndexByte(text[pos:end], '\n'); nl >= 0 {
			pos += nl + 1
		} else {
			pos = end
		}
		blank := false
		for pos < end {
			ln := text[pos:end]
			nl := strings.IndexByte(ln, '\n')
			next := end
			if nl >= 0 {
				ln, next = ln[:nl], pos+nl+1
			}
			if strings.TrimSpace(ln) == "" {
				blank = true
			} else {
				if blank && !strings.HasPrefix(ln, "- ") && !strings.HasPrefix(ln, " ") && !strings.HasPrefix(ln, "\t") {
					end = pos - 1 // keep the newline before the definition
					break
				}
				blank = false
			}
			pos = next
		}
		out = append(out, [2]int{c, end})
		i = end
	}
	return out
}

// withoutChanges blanks each "**Changes.**" list, keeping every offset.
func withoutChanges(text string) string {
	b := []byte(text)
	for _, sp := range changesSpans(text) {
		for j := sp[0]; j < sp[1]; j++ {
			if b[j] != '\n' {
				b[j] = ' '
			}
		}
	}
	return string(b)
}

// sortFindings orders findings by source and line.
func sortFindings(out []Finding) []Finding {
	sort.Slice(out, func(a, b int) bool {
		if out[a].Doc != out[b].Doc {
			return out[a].Doc < out[b].Doc
		}
		return out[a].Line < out[b].Line
	})
	return out
}

// namedBefore reports whether s ends in a named reference: the ID at its end follows a document's name.
func namedBefore(crossRe *regexp.Regexp, s string) bool {
	for _, m := range crossRe.FindAllStringIndex(s, -1) {
		if m[1] == len(s) {
			return true
		}
	}
	return false
}

// testFuncRe is a test function's name in text.
var testFuncRe = regexp.MustCompile(`\b(Test[A-Z0-9]\w*|Fuzz[A-Z]\w*|Benchmark[A-Z]\w*)\b`)

// Untested returns the rules no test mentions, by document. tests maps a _test.go file's path to its text.
func Untested(docs map[string]*Doc, tests map[string]string) map[string][]string {
	funcs := map[string]bool{}
	declRe := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)\w*)\(`)
	for _, t := range tests {
		for _, m := range declRe.FindAllStringSubmatch(t, -1) {
			funcs[m[1]] = true
		}
	}
	out := map[string][]string{}
	for _, d := range docs {
		var mentioning []string
		for _, t := range tests {
			if strings.Contains(t, d.Base) {
				mentioning = append(mentioning, t)
			}
		}
		for id, r := range d.Rules {
			if r.Withdrawn {
				continue
			}
			tested := false
			for _, m := range testFuncRe.FindAllString(r.Body, -1) {
				if funcs[m] {
					tested = true
					break
				}
			}
			if !tested {
				idRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`)
				for _, t := range mentioning {
					if idRe.MatchString(t) {
						tested = true
						break
					}
				}
			}
			if !tested {
				out[d.Name] = append(out[d.Name], id)
			}
		}
		sort.Slice(out[d.Name], func(a, b int) bool { return idLess(out[d.Name][a], out[d.Name][b]) })
	}
	return out
}

// testDeclRe is a Test or Fuzz function declaration, with the comment lines just above it captured.
var testDeclRe = regexp.MustCompile(`(?m)((?:^//.*\n)*)^func ((?:Test|Fuzz)[A-Z0-9_]\w*)\(`)

// tRunRe is the name a t.Run call gives its subtest.
var tRunRe = regexp.MustCompile(`\.Run\("([^"]*)"`)

// StrictCited returns, for one _test.go file's text, the text each Test or Fuzz function cites rules in: its doc
// comment and the names of its t.Run subtests (its body up to the next top-level function).
func StrictCited(text string) []string {
	var out []string
	locs := testDeclRe.FindAllStringSubmatchIndex(text, -1)
	for i, m := range locs {
		cited := text[m[2]:m[3]]
		end := len(text)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		for _, r := range tRunRe.FindAllStringSubmatch(text[m[1]:end], -1) {
			cited += "\n" + r[1]
		}
		out = append(out, cited)
	}
	return out
}

// UntestedStrict returns the rules no Test or Fuzz function cites strictly (see StrictCited), by document, in
// files that name the document.
func UntestedStrict(docs map[string]*Doc, tests map[string]string) map[string][]string {
	out := map[string][]string{}
	for _, d := range docs {
		var cites []string
		for _, t := range tests {
			if strings.Contains(t, d.Base) {
				cites = append(cites, StrictCited(t)...)
			}
		}
		for id, r := range d.Rules {
			if r.Withdrawn {
				continue
			}
			idRe := regexp.MustCompile(`\b` + regexp.QuoteMeta(id) + `\b`)
			found := false
			for _, c := range cites {
				if idRe.MatchString(c) {
					found = true
					break
				}
			}
			if !found {
				out[d.Name] = append(out[d.Name], id)
			}
		}
		sort.Slice(out[d.Name], func(a, b int) bool { return idLess(out[d.Name][a], out[d.Name][b]) })
	}
	return out
}

// idLess orders IDs by letter, then number.
func idLess(a, b string) bool {
	if a[0] != b[0] {
		return a[0] > b[0] // R, I, E
	}
	var na, nb int
	_, _ = fmt.Sscanf(a[1:], "%d", &na)
	_, _ = fmt.Sscanf(b[1:], "%d", &nb)
	if na != nb {
		return na < nb
	}
	return a < b
}

// nonSpecDocs are the docs/p0 files that carry no rules of their own.
var nonSpecDocs = map[string]bool{"README.md": true, "STEPS.md": true}

// Load reads every docs/p0/*.md under root that has a §5, the extra reference sources (docs/**/*.md outside
// docs/p0, spec/**/*.md), every .go file (code) and, among them, every _test.go file (tests).
func Load(root string) (docs map[string]*Doc, extra, code, tests map[string]string, err error) {
	docs, extra, code, tests = map[string]*Doc{}, map[string]string{}, map[string]string{}, map[string]string{}
	paths, err := filepath.Glob(filepath.Join(root, "docs", "p0", "*.md"))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, nil, nil, nil, err
		}
		if !strings.Contains(string(b), "\n## 5. ") {
			if nonSpecDocs[filepath.Base(p)] {
				continue // no rules of their own
			}
			// A spec whose "## 5. " heading was renamed would otherwise drop out of every check silently.
			return nil, nil, nil, nil, fmt.Errorf("%s has no \"## 5. \" section and is not one of the docs without rules (%s)", p, "README.md, STEPS.md")
		}
		d := ParseDoc(filepath.Base(p), string(b))
		docs[d.Name] = d
	}
	err = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			switch e.Name() {
			case ".git", "node_modules", "bin", ".claude":
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		switch {
		case strings.HasSuffix(p, ".go") && filepath.Dir(rel) != filepath.Join("tools", "rulecheck"):
			// This tool's own examples of a bad reference are not references.
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			code[rel] = string(b)
			if strings.HasSuffix(p, "_test.go") {
				tests[rel] = string(b)
			}
		case strings.HasSuffix(p, ".md") && (strings.HasPrefix(rel, "docs"+string(filepath.Separator)) ||
			strings.HasPrefix(rel, "spec"+string(filepath.Separator))) && filepath.Dir(rel) != filepath.Join("docs", "p0"):
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			extra[rel] = string(b)
		}
		return nil
	})
	return docs, extra, code, tests, err
}

// citedTestRe is a Test, Fuzz or Benchmark name in backquotes, with the `*` a prefix citation ends in.
var citedTestRe = regexp.MustCompile("`((?:Test|Fuzz|Benchmark)[A-Z0-9_]\\w*)(\\*?)`")

// CheckCitedTests returns a finding for each backquoted Test, Fuzz or Benchmark name in texts (path to text: the
// README, docs and spec files) that no function in tests declares; a name ending in `*` needs one function with
// that prefix. Evidence a spec cites must not rot silently when a test is renamed or removed. A name inside a
// line that says it was renamed, removed, replaced or withdrawn is history and is not checked.
func CheckCitedTests(texts, tests map[string]string) []Finding {
	var funcs []string
	declRe := regexp.MustCompile(`(?m)^func ((?:Test|Fuzz|Benchmark)\w*)\(`)
	for _, t := range tests {
		for _, m := range declRe.FindAllStringSubmatch(t, -1) {
			funcs = append(funcs, m[1])
		}
	}
	exact := map[string]bool{}
	for _, f := range funcs {
		exact[f] = true
	}
	histRe := regexp.MustCompile(`(?i)\b(renamed|removed|replaced|withdrawn|deleted|formerly)\b`)
	var out []Finding
	for path, text := range texts {
		for i, line := range strings.Split(text, "\n") {
			if histRe.MatchString(line) {
				continue
			}
			for _, m := range citedTestRe.FindAllStringSubmatch(line, -1) {
				ok := exact[m[1]]
				if m[2] == "*" {
					ok = false
					for _, f := range funcs {
						if strings.HasPrefix(f, m[1]) {
							ok = true
							break
						}
					}
				}
				if !ok {
					out = append(out, Finding{Doc: path, Line: i + 1, What: fmt.Sprintf("cites %s%s, which no test declares", m[1], m[2])})
				}
			}
		}
	}
	sort.Slice(out, func(a, b int) bool {
		if out[a].Doc != out[b].Doc {
			return out[a].Doc < out[b].Doc
		}
		return out[a].Line < out[b].Line
	})
	return out
}

// loadCiting reads the text that cites tests: README.md and every .md under docs and spec.
func loadCiting(root string) map[string]string {
	out := map[string]string{}
	add := func(p string) {
		if b, err := os.ReadFile(p); err == nil {
			rel, _ := filepath.Rel(root, p)
			out[rel] = string(b)
		}
	}
	add(filepath.Join(root, "README.md"))
	for _, d := range []string{"docs", "spec"} {
		_ = filepath.WalkDir(filepath.Join(root, d), func(p string, e os.DirEntry, err error) error {
			if err == nil && !e.IsDir() && strings.HasSuffix(p, ".md") {
				add(p)
			}
			return nil
		})
	}
	return out
}

func main() {
	verbose := flag.Bool("v", false, "list every untested rule")
	strict := flag.Bool("strict", false, "also report the rules no Test or Fuzz doc comment or t.Run name cites")
	flag.Parse()
	root := "."
	if flag.NArg() > 0 {
		root = flag.Arg(0)
	}
	os.Exit(run(root, *verbose, *strict, os.Stdout))
}

// run is main's body: it prints the report and returns the exit code.
func run(root string, verbose, strict bool, w *os.File) int {
	docs, extra, code, tests, err := Load(root)
	if err != nil {
		fmt.Fprintln(w, "rulecheck:", err)
		return 2
	}
	if len(docs) == 0 {
		fmt.Fprintf(w, "rulecheck: no spec documents (docs/p0/*.md with a \"## 5. \" section) under %s\n", root)
		return 2
	}
	untested := Untested(docs, tests)
	names := make([]string, 0, len(docs))
	for n := range docs {
		names = append(names, n)
	}
	sort.Strings(names)
	total, missing := 0, 0
	for _, n := range names {
		total += docs[n].Live()
		missing += len(untested[n])
		fmt.Fprintf(w, "rulecheck: %-28s %3d rules, %3d no test mentions", n, docs[n].Live(), len(untested[n]))
		if verbose && len(untested[n]) > 0 {
			fmt.Fprintf(w, ": %s", strings.Join(untested[n], " "))
		}
		fmt.Fprintln(w)
	}
	fmt.Fprintf(w, "rulecheck: %d rules, %d that no test mentions (report only)\n", total, missing)
	if strict {
		st := UntestedStrict(docs, tests)
		sm := 0
		for _, n := range names {
			sm += len(st[n])
			if len(st[n]) > 0 {
				fmt.Fprintf(w, "rulecheck: strict %-28s %3d uncovered: %s\n", n, len(st[n]), strings.Join(st[n], " "))
			}
		}
		fmt.Fprintf(w, "rulecheck: strict: %d of %d rules with no Test/Fuzz doc comment or t.Run name citing them (report only)\n", sm, total)
	}
	findings := append(Check(docs, extra), CheckCitedTests(loadCiting(root), tests)...)
	if plan, notes := loadTicketStatus(root); plan != "" {
		findings = append(findings, CheckTicketStatus(plan, notes)...)
	}
	links, err := checkLinksUnder(root)
	if err != nil {
		fmt.Fprintln(w, "rulecheck:", err)
		return 2
	}
	findings = append(findings, links...)
	bare, err := checkBareMDNamesUnder(root)
	if err != nil {
		fmt.Fprintln(w, "rulecheck:", err)
		return 2
	}
	findings = append(findings, bare...)
	for _, f := range findings {
		fmt.Fprintln(w, "rulecheck: FAIL", f)
	}
	// References in Go comments are reported, not failed: a comment's reference is a pointer for its reader,
	// and the specs are the normative text this check holds (ADR 0030 (4) makes test citations gating later).
	for _, f := range CheckRefs(docs, code) {
		fmt.Fprintln(w, "rulecheck: code", f)
	}
	if len(findings) > 0 {
		fmt.Fprintf(w, "rulecheck: %d failing findings\n", len(findings))
		return 1
	}
	return 0
}
