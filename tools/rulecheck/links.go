// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
)

// The link check: every relative Markdown link in the repository's documentation names a file or directory that
// exists, and a link's #anchor into a Markdown file names one of its headings (GitHub's slug) or an explicit
// id/name anchor. A link with a scheme (https:, mailto:) is not checked. Links inside fenced code blocks and code
// spans are text, not links. Added 2026-10-05 after two broken links (ADR 0035 to a CAPABILITIES.md that never
// existed in docs/, gate.md to an anchor agent-contract.md does not have) passed every gate.

// linkSkipDirs are the directories the check does not read: tool and build state, test data, the agents'
// working notes, which are not project documentation, and archive/, where retired docs keep
// the links they had when they were current.
var linkSkipDirs = map[string]bool{".git": true, "node_modules": true, "bin": true, "dist": true, ".claude": true,
	"testdata": true, "archive": true}

// linkSkipFiles are single working-note files, relative to the root, the check does not read.
var linkSkipFiles = map[string]bool{}

var (
	inlineLinkRe = regexp.MustCompile(`!?\[(?:[^\[\]]|\[[^\[\]]*\])*\]\(\s*<?([^\s()<>]+(?:\([^\s()]*\)[^\s()<>]*)*)>?(?:\s+"[^"]*")?\s*\)`)
	refLinkRe    = regexp.MustCompile(`^ {0,3}\[[^\]]+\]:\s*<?(\S+?)>?(?:\s+"[^"]*")?\s*$`)
	headingRe    = regexp.MustCompile(`^ {0,3}#{1,6}\s+(.*?)(?:\s+#+)?\s*$`)
	htmlAnchorRe = regexp.MustCompile(`<a\s[^>]*(?:id|name)="([^"]+)"`)
	schemeRe     = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9+.-]*:`)
	headingLink  = regexp.MustCompile(`!?\[([^\]]*)\]\([^)]*\)`)
)

// LoadLinked reads every Markdown file under root the link check covers, path relative to root to text.
func LoadLinked(root string) (map[string]string, error) {
	out := map[string]string{}
	err := filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			if p != root && linkSkipDirs[e.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		rel, _ := filepath.Rel(root, p)
		if !strings.HasSuffix(p, ".md") || linkSkipFiles[rel] {
			return nil
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		out[rel] = string(b)
		return nil
	})
	return out, err
}

// Slug is GitHub's anchor for a heading's text: lower case, the markup of code spans, emphasis and links dropped,
// every character but a letter, digit, underscore, hyphen or space dropped, and each space a hyphen.
func Slug(heading string) string {
	heading = headingLink.ReplaceAllString(heading, "$1")
	var sb strings.Builder
	for _, r := range strings.ToLower(heading) {
		switch {
		case r == ' ':
			sb.WriteByte('-')
		case r == '-' || r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r) || unicode.Is(unicode.Mn, r):
			sb.WriteRune(r)
		}
	}
	return sb.String()
}

// mdLines returns a Markdown text's lines with each fenced code block's lines blanked, so neither its links nor
// its headings count.
func mdLines(text string) []string {
	lines := strings.Split(text, "\n")
	fence := ""
	for i, line := range lines {
		t := strings.TrimLeft(line, " ")
		if fence == "" {
			if strings.HasPrefix(t, "```") || strings.HasPrefix(t, "~~~") {
				fence = t[:3]
				lines[i] = ""
			}
			continue
		}
		if strings.HasPrefix(t, fence) {
			fence = ""
		}
		lines[i] = ""
	}
	return lines
}

// withoutCodeSpans returns line with its code spans removed: a run of backticks up to the next run of the same
// length. A run with no closing run is text.
func withoutCodeSpans(line string) string {
	var sb strings.Builder
	for i := 0; i < len(line); {
		if line[i] != '`' {
			sb.WriteByte(line[i])
			i++
			continue
		}
		n := 0
		for i+n < len(line) && line[i+n] == '`' {
			n++
		}
		closed := false
		for j := i + n; j < len(line); {
			if line[j] != '`' {
				j++
				continue
			}
			m := 0
			for j+m < len(line) && line[j+m] == '`' {
				m++
			}
			if m == n {
				i, closed = j+m, true
				break
			}
			j += m
		}
		if !closed {
			sb.WriteString(line[i : i+n])
			i += n
		}
	}
	return sb.String()
}

// anchors returns the anchors a Markdown text defines: its headings' slugs (a repeated slug gets -1, -2, ... as on
// GitHub) and its explicit <a id="..."> or <a name="..."> anchors.
func anchors(text string) map[string]bool {
	out, seen := map[string]bool{}, map[string]int{}
	for _, line := range mdLines(text) {
		for _, m := range htmlAnchorRe.FindAllStringSubmatch(line, -1) {
			out[m[1]] = true
		}
		m := headingRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		s := Slug(m[1])
		if n := seen[s]; n > 0 {
			out[s+"-"+strconv.Itoa(n)] = true
		} else {
			out[s] = true
		}
		seen[s]++
	}
	return out
}

// CheckLinks returns a finding for each relative link in docs (path relative to root to text) whose target does
// not exist under root, or whose #anchor the target Markdown file (or the document itself, for a bare #anchor)
// does not define. exists answers for a path relative to root; the Markdown texts of docs serve the anchors, and
// a Markdown target outside docs is read through readMD.
func CheckLinks(docs map[string]string, exists func(rel string) bool, readMD func(rel string) (string, bool)) []Finding {
	anchorCache := map[string]map[string]bool{}
	anchorsOf := func(rel string) (map[string]bool, bool) {
		if a, ok := anchorCache[rel]; ok {
			return a, a != nil
		}
		text, ok := docs[rel]
		if !ok {
			text, ok = readMD(rel)
		}
		if !ok {
			anchorCache[rel] = nil
			return nil, false
		}
		anchorCache[rel] = anchors(text)
		return anchorCache[rel], true
	}
	var out []Finding
	for path, text := range docs {
		for i, line := range mdLines(text) {
			line = withoutCodeSpans(line)
			var targets []string
			for _, m := range inlineLinkRe.FindAllStringSubmatch(line, -1) {
				targets = append(targets, m[1])
			}
			if m := refLinkRe.FindStringSubmatch(line); m != nil {
				targets = append(targets, m[1])
			}
			for _, target := range targets {
				if what := checkLink(path, target, exists, anchorsOf); what != "" {
					out = append(out, Finding{Doc: path, Line: i + 1, What: what})
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

// checkLink returns what is wrong with one link target in the document at path, or "".
func checkLink(path, target string, exists func(string) bool, anchorsOf func(string) (map[string]bool, bool)) string {
	if schemeRe.MatchString(target) || strings.HasPrefix(target, "//") {
		return ""
	}
	file, frag, _ := strings.Cut(target, "#")
	if i := strings.IndexByte(file, '?'); i >= 0 {
		file = file[:i]
	}
	if f, err := url.PathUnescape(file); err == nil {
		file = f
	}
	rel := path
	if file != "" {
		if strings.HasPrefix(file, "/") {
			rel = filepath.Clean(strings.TrimPrefix(file, "/"))
		} else {
			rel = filepath.Clean(filepath.Join(filepath.Dir(path), file))
		}
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return fmt.Sprintf("links %s, outside the repository", target)
		}
		if !exists(rel) {
			return fmt.Sprintf("links %s, which does not exist", target)
		}
	}
	if frag == "" || !strings.HasSuffix(rel, ".md") {
		return ""
	}
	a, ok := anchorsOf(rel)
	if !ok {
		return ""
	}
	if f, err := url.PathUnescape(frag); err == nil {
		frag = f
	}
	if !a[strings.ToLower(frag)] && !a[frag] {
		return fmt.Sprintf("links %s, but %s has no heading or anchor #%s", target, rel, frag)
	}
	return ""
}

// checkLinksUnder runs the link check over the Markdown files under root.
func checkLinksUnder(root string) ([]Finding, error) {
	docs, err := LoadLinked(root)
	if err != nil {
		return nil, err
	}
	exists := func(rel string) bool {
		_, err := os.Stat(filepath.Join(root, rel))
		return err == nil
	}
	readMD := func(rel string) (string, bool) {
		b, err := os.ReadFile(filepath.Join(root, rel))
		return string(b), err == nil
	}
	return CheckLinks(docs, exists, readMD), nil
}
