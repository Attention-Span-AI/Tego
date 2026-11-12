// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"go/scanner"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// The bare-name check: a Markdown file named by its bare name (a file name with no directory before it), in a
// document the link check reads or in a Go comment, names a file the repository holds somewhere. The link check sees only
// Markdown links, so a bare name in prose, in a code span or in a comment passed it even when the file was a
// working note that never entered the tree. Added 2026-11-11 after ADR 0048's amendment and the multicall test
// comments cited a working report by its file name, a report that was never in the repository; a reader of the
// repository (or of the public tree) cannot follow such a citation.
//
// A name with a directory in front of it (`docs/GAPS.md`, `out/report.md`) is a path, not a bare name: the link
// check holds the links among them, and an example path in a test is not a citation. Fenced code blocks are left
// out; code spans are read, since a citation in backquotes is still a citation.

// bareMDRe is a candidate bare name. The bytes around a match are checked by bareNameAt.
var bareMDRe = regexp.MustCompile(`[A-Za-z0-9_][A-Za-z0-9_-]*\.md`)

// bareMDAllowed are the bare names that are not Tego's files and are allowed to be absent in any file, each with why.
var bareMDAllowed = map[string]string{
	// Agent instruction files: the files an agent such as Claude Code or Codex reads from a project or a home
	// directory. Tego's docs name them as the agent's files; this repository has none.
	"AGENTS.md": "an agent's instruction file in the user's project, not a file of this repository",
	"CLAUDE.md": "an agent's instruction file in the user's project or home, not a file of this repository",
}

// bareMDAllowedAt are the bare names allowed to be absent only in the files listed for them (paths from the
// repository root, with /), each with why. A name allowed here still fails in any other file, so a later citation of
// a working note that happens to share the name is caught. Names that only private documents use are added by a
// file that stays private with them.
var bareMDAllowedAt = map[string]struct {
	why   string
	paths []string
}{
	"report.md": {"the file tools/deadcodereport writes into its -dir, and the stock example of a file an agent writes " +
		"in the contract test table", []string{"tools/deadcodereport/main.go", "tools/deadcodereport/main_test.go",
		"pkg/spec/agent/testtable.go", "pkg/spec/agent/testtable_paths_test.go"}},
}

// bareMDAllowedIn reports whether name may be absent in the file at path.
func bareMDAllowedIn(name, path string) bool {
	if bareMDAllowed[name] != "" {
		return true
	}
	for _, p := range bareMDAllowedAt[name].paths {
		if p == filepath.ToSlash(path) {
			return true
		}
	}
	return false
}

// bareNameAt reports whether the match [i, j) of bareMDRe in s stands alone as a file name: not the tail of a
// path, a URL, a template or a variable (`/`, `.`, `~`, `%`, `$`, `@` just before it), and not the head of a
// longer name or path (`x.md.golden`, `x.md/`).
func bareNameAt(s string, i, j int) bool {
	if i > 0 && strings.IndexByte("/.~%$@\\", s[i-1]) >= 0 {
		return false
	}
	if j < len(s) {
		c := s[j]
		if c == '/' || c == '\\' || isNameByte(c) {
			return false
		}
		if c == '.' && j+1 < len(s) && isNameByte(s[j+1]) {
			return false
		}
	}
	return true
}

func isNameByte(c byte) bool {
	return c == '_' || c == '-' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// bareNames returns the bare Markdown names in one line of text.
func bareNames(line string) []string {
	var out []string
	for _, m := range bareMDRe.FindAllStringIndex(line, -1) {
		if bareNameAt(line, m[0], m[1]) {
			out = append(out, line[m[0]:m[1]])
		}
	}
	return out
}

// CheckBareMDNames returns a finding for each bare Markdown name, in docs (path to Markdown text) and in comments
// (path to the Go comments' lines, line number to text), that no file of known (the base names of the repository's
// Markdown files) has and the allow lists do not hold for that path.
func CheckBareMDNames(docs map[string]string, comments map[string]map[int]string, known map[string]bool) []Finding {
	var out []Finding
	check := func(path string, line int, text string) {
		for _, name := range bareNames(text) {
			if known[name] || bareMDAllowedIn(name, path) {
				continue
			}
			out = append(out, Finding{Doc: path, Line: line, What: fmt.Sprintf(
				"names %s, which is no Markdown file of this repository (cite the in-tree test, table or section that holds the fact, or state it with its date)", name)})
		}
	}
	for path, text := range docs {
		for i, line := range mdLines(text) {
			check(path, i+1, line)
		}
	}
	for path, lines := range comments {
		for n, text := range lines {
			check(path, n, text)
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

// goCommentLines returns the comment text of a Go source by line number (a block comment's lines each under
// their own number). A file that does not scan cleanly still gives the comments read before the error.
func goCommentLines(src []byte) map[int]string {
	out := map[int]string{}
	fset := token.NewFileSet()
	file := fset.AddFile("", fset.Base(), len(src))
	var s scanner.Scanner
	s.Init(file, src, func(token.Position, string) {}, scanner.ScanComments)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			return out
		}
		if tok != token.COMMENT {
			continue
		}
		line := fset.Position(pos).Line
		for k, l := range strings.Split(lit, "\n") {
			out[line+k] += l
		}
	}
}

// namesFromSkippedDirs are the directories the link check skips whose Markdown files still count as the
// repository's: test data, retired docs and tool state are in the tree. The other skipped directories (the agents'
// working notes) and the skipped files are not the repository's, so a name only they hold does not count.
var namesFromSkippedDirs = map[string]bool{"testdata": true, "archive": true, "bin": true, "dist": true, ".claude": true}

// loadBareMDInputs walks root for the check's inputs: the base names of every Markdown file the repository holds,
// and the comments of every Go file outside the directories the link check skips.
func loadBareMDInputs(root string) (known map[string]bool, comments map[string]map[int]string, err error) {
	known, comments = map[string]bool{}, map[string]map[int]string{}
	err = filepath.WalkDir(root, func(p string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		if e.IsDir() {
			if p != root && (e.Name() == ".git" || e.Name() == "node_modules" ||
				linkSkipDirs[e.Name()] && !namesFromSkippedDirs[e.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		switch {
		case strings.HasSuffix(p, ".md"):
			if !linkSkipFiles[rel] {
				known[e.Name()] = true
			}
		case strings.HasSuffix(p, ".go") && !inLinkSkipDir(rel):
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			if c := goCommentLines(b); len(c) > 0 {
				comments[rel] = c
			}
		}
		return nil
	})
	return known, comments, err
}

// inLinkSkipDir reports whether a path relative to the root lies under a directory the link check skips.
func inLinkSkipDir(rel string) bool {
	for _, d := range strings.Split(filepath.Dir(rel), string(filepath.Separator)) {
		if linkSkipDirs[d] {
			return true
		}
	}
	return false
}

// checkBareMDNamesUnder runs the bare-name check over the documents the link check reads and the Go comments
// under root.
func checkBareMDNamesUnder(root string) ([]Finding, error) {
	docs, err := LoadLinked(root)
	if err != nil {
		return nil, err
	}
	known, comments, err := loadBareMDInputs(root)
	if err != nil {
		return nil, err
	}
	return CheckBareMDNames(docs, comments, known), nil
}
