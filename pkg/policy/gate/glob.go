// SPDX-License-Identifier: Apache-2.0

package gate

import (
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

// readPattern is an `fs.read matches` pattern read as the clean paths it can match (ADR 0007, fourth 2026-10-20
// note). A pattern with no '/' outside a character class matches a base name.
// One with such a '/' is a path pattern: a sequence of component globs separated by '/', each a filepath.Match
// pattern that matches exactly one name, absolute when it starts with '/' and otherwise matched against the path from
// the worktree. A path matches it when the two have as many components and each name matches its glob; a move's end
// lies above a path it matches when the end's components are fewer and each matches its glob. Both questions run
// filepath.Match itself on one name at a time, so they cannot read a glob differently.
type readPattern struct {
	path  bool     // the pattern holds a '/' outside a class
	abs   bool     // it starts with '/'
	comps []string // a path pattern's component globs, without the leading "" of an absolute one
	// up is how many leading components of a relative path pattern match ".." and no name, so every path it matches
	// starts with at least as many ".." (CheckWorktree).
	up int
}

// parseGlob checks p against filepath.Match's whole grammar, which filepath.Match(p, "") does not (it stops at the
// first chunk that fails to match, so "a*[" was accepted and then never matched anything), and splits it at each
// '/' outside a class. slash reports a class that can match '/', escaped a '\/'.
func parseGlob(p string) (comps []string, slash, escaped bool, err error) {
	start := 0
	for i := 0; i < len(p); {
		switch p[i] {
		case '\\':
			r, n := utf8.DecodeRuneInString(p[i+1:])
			if n == 0 {
				return nil, false, false, filepath.ErrBadPattern
			}
			escaped = escaped || r == filepath.Separator
			i += 1 + n
		case '[':
			c, end, ok := scanClass(p, i+1)
			if !ok {
				return nil, false, false, filepath.ErrBadPattern
			}
			slash = slash || c.matches(filepath.Separator)
			i = end
		case filepath.Separator:
			comps = append(comps, p[start:i])
			i++
			start = i
		default:
			i++
		}
	}
	return append(comps, p[start:]), slash, escaped, nil
}

// class is a character class: the runes it lists as lo, hi pairs, and whether it is negated.
type class struct {
	neg    bool
	ranges []rune
}

func (c *class) matches(r rune) bool {
	in := false
	for i := 0; i < len(c.ranges); i += 2 {
		in = in || c.ranges[i] <= r && r <= c.ranges[i+1]
	}
	return in != c.neg
}

// scanClass reads the class whose '[' is just before p[i] as filepath.Match's matchChunk does: an optional '^', one or
// more ranges lo or lo-hi, each end one character or an escaped one, closed by a ']' after the first range. It
// returns the index past the ']'.
func scanClass(p string, i int) (c class, end int, ok bool) {
	if c.neg = i < len(p) && p[i] == '^'; c.neg {
		i++
	}
	for {
		if i < len(p) && p[i] == ']' && len(c.ranges) > 0 {
			return c, i + 1, true
		}
		lo, j, ok := classChar(p, i)
		if !ok {
			return c, 0, false
		}
		hi := lo
		if i = j; p[i] == '-' {
			if hi, i, ok = classChar(p, i+1); !ok {
				return c, 0, false
			}
		}
		c.ranges = append(c.ranges, lo, hi)
	}
}

// classChar is filepath.Match's getEsc: one class character at p[i], escaped or not; a character must follow it.
func classChar(p string, i int) (rune, int, bool) {
	if i >= len(p) || p[i] == '-' || p[i] == ']' {
		return 0, 0, false
	}
	if p[i] == '\\' {
		if i++; i >= len(p) {
			return 0, 0, false
		}
	}
	r, n := utf8.DecodeRuneInString(p[i:])
	if r == utf8.RuneError && n == 1 || i+n >= len(p) {
		return 0, 0, false
	}
	return r, i + n, true
}

// nameChar is a rune a class matches that a name can hold, '.' only when no other one is matched (a name is never
// "." or ".."); false when the class matches none. The runes a class leaves out of a name form intervals, so a rune
// it matches lies next to an end of one of its ranges, or is one of the name's extremes.
func (c *class) nameChar() (rune, bool) {
	cand := []rune{'a', '.', 1, utf8.MaxRune}
	for i := 0; i < len(c.ranges); i += 2 {
		cand = append(cand, c.ranges[i], c.ranges[i]-1, c.ranges[i+1], c.ranges[i+1]+1)
	}
	dot := false
	for _, r := range cand {
		if r < 1 || r > utf8.MaxRune || r == filepath.Separator || !utf8.ValidRune(r) || !c.matches(r) {
			continue
		}
		if r != '.' {
			return r, true
		}
		dot = true
	}
	return '.', dot
}

// witness is a name the component glob comp matches, never "." or ".." (nor ""), as filepath.Match itself confirms;
// false when comp matches no name.
func witness(comp string) (string, bool) {
	var b strings.Builder
	star := -1
	for i := 0; i < len(comp); {
		switch comp[i] {
		case '*':
			if star < 0 {
				star = b.Len()
			}
			i++
		case '?':
			b.WriteByte('a')
			i++
		case '\\':
			_, n := utf8.DecodeRuneInString(comp[i+1:])
			b.WriteString(comp[i+1 : i+1+n])
			i += 1 + n
		case '[':
			c, end, ok := scanClass(comp, i+1)
			if !ok {
				return "", false
			}
			r, ok := c.nameChar()
			if !ok {
				return "", false
			}
			b.WriteRune(r)
			i = end
		default:
			b.WriteByte(comp[i])
			i++
		}
	}
	w := b.String()
	if (w == "" || w == "." || w == "..") && star >= 0 {
		w = w[:star] + "a" + w[star:]
	}
	if w == "" || w == "." || w == ".." {
		return "", false
	}
	m, err := filepath.Match(comp, w)
	return w, m && err == nil
}

// newReadPattern reads arg as a readPattern. It accepts a pattern only when filepath.Match's grammar accepts the
// whole of it and some clean path matches it: compile refuses, rather than accepts to never fire, an empty component
// (a doubled or a trailing '/'), a "." component, a ".." after a name (a relative pattern may start with ".."
// components, as the path from the worktree to a file outside it does; an absolute one may not), and a class or a
// glob that matches no name. It refuses a path pattern the component reading would read otherwise than filepath.Match
// reads the whole string: an escaped '/', and a class that can match '/' (filepath.Match lets a class match the
// separator, where '*' and '?' cannot; a path's '/' is matched here by a '/' of the pattern alone). Those two fired
// before the component reading, which matched any pattern holding '/' as filepath.Match does, so their refusals say
// why they are refused and name the spelling to write.
func newReadPattern(arg string) (readPattern, error) {
	comps, slash, escaped, err := parseGlob(arg)
	if err != nil {
		return readPattern{}, err
	}
	rp := readPattern{path: len(comps) > 1}
	if escaped {
		// filepath.Match reads "a\/x" as "a/x" and so matched a/x: the pattern is refused
		// because the component reading would read it otherwise, not because it never fired.
		const why = "an escaped '/' splits no component here, where filepath.Match matches it across a separator"
		if fix := plainSlash(arg); fix != arg {
			if _, err := newReadPattern(fix); err == nil {
				return readPattern{}, fmt.Errorf("%s; write %q", why, fix)
			}
		}
		return readPattern{}, fmt.Errorf("%s; write '/'", why)
	}
	if !rp.path {
		if _, ok := witness(arg); !ok && slash {
			return readPattern{}, fmt.Errorf("a '/' inside a character class makes no path pattern, and a base name never holds '/'; a path pattern holds '/' outside a class")
		} else if !ok {
			return readPattern{}, fmt.Errorf("the pattern matches no file's base name")
		}
		return rp, nil
	}
	if slash {
		return readPattern{}, fmt.Errorf("a character class in a pattern holding '/' can match '/', which only a '/' of the pattern matches here; leave '/' out of it (a negated class lists it: [^x/])")
	}
	if rp.abs = comps[0] == ""; rp.abs {
		comps = comps[1:]
	}
	if rp.abs && len(comps) == 1 && comps[0] == "" {
		return rp, nil // "/", the root
	}
	// Some clean path matches: the leading components a relative pattern can match ".." with stand for the path out
	// of the worktree, and every later one matches a name.
	up := 0
	for !rp.abs && up < len(comps) {
		if m, _ := filepath.Match(comps[up], ".."); !m {
			break
		}
		up++
	}
	for _, c := range comps[up:] {
		if _, ok := witness(c); !ok {
			return readPattern{}, unclean(arg, rp.abs, comps)
		}
	}
	// Of the leading components that can match "..", those after the last one matching no name may match names
	// instead, so a path from a worktree with fewer ancestors can still match.
	for rp.up = up; rp.up > 0; rp.up-- {
		if _, ok := witness(comps[rp.up-1]); !ok {
			break
		}
	}
	rp.comps = comps
	return rp, nil
}

// beyond is the refusal of a relative path pattern no path from worktree matches: such a path starts with at most as
// many ".." components as worktree has names, and the pattern needs more. When those
// components are each "..", it names the absolute pattern the agent's own path resolves to, since the parent of the
// root is the root. nil when some path from worktree can match, and when worktree is not absolute, which leaves the
// read unscored as incomplete (Action.Complete) rather than scored by a guess.
func (rp *readPattern) beyond(arg, worktree string) error {
	if !rp.path || rp.abs || rp.up == 0 || !filepath.IsAbs(worktree) {
		return nil
	}
	names := 0
	for _, c := range strings.Split(filepath.Clean(worktree), string(filepath.Separator)) {
		if c != "" {
			names++
		}
	}
	if rp.up <= names {
		return nil
	}
	err := fmt.Errorf("no path from the worktree %s starts with more than %d \"..\" components, and the pattern's first %d must each match \"..\", so it matches nothing in this worktree", worktree, names, rp.up)
	for _, c := range rp.comps[:rp.up] {
		if c != ".." {
			return err
		}
	}
	if fix := filepath.Join(worktree, arg); fix != arg {
		if _, e := newReadPattern(fix); e == nil {
			return fmt.Errorf("%w; write %q", err, fix)
		}
	}
	return err
}

// plainSlash is p with each escaped '/' outside a class written as a plain '/', the spelling the refusal of an escaped
// '/' names.
func plainSlash(p string) string {
	var b strings.Builder
	for i := 0; i < len(p); {
		switch {
		case p[i] == '\\' && i+1 < len(p) && p[i+1] == filepath.Separator:
			b.WriteByte(filepath.Separator)
			i += 2
		case p[i] == '\\' && i+1 < len(p):
			_, n := utf8.DecodeRuneInString(p[i+1:])
			b.WriteString(p[i : i+1+n])
			i += 1 + n
		case p[i] == '[':
			end := len(p)
			if _, e, ok := scanClass(p, i+1); ok {
				end = e
			}
			b.WriteString(p[i:end])
			i = end
		default:
			b.WriteByte(p[i])
			i++
		}
	}
	return b.String()
}

// unclean is the refusal of a path pattern no clean path matches, naming the pattern without its empty and "."
// components when that one is accepted: "./secrets/*" is "secrets/*".
func unclean(arg string, abs bool, comps []string) error {
	var kept []string
	for _, c := range comps {
		if c != "" && c != "." {
			kept = append(kept, c)
		}
	}
	fix := strings.Join(kept, string(filepath.Separator))
	if abs {
		fix = string(filepath.Separator) + fix
	}
	if fix == arg {
		return fmt.Errorf("a pattern holding '/' is matched against a clean path, which no misplaced \"..\" component, nor a glob matching no name, matches")
	}
	if rp, err := newReadPattern(fix); err == nil && rp.path {
		return fmt.Errorf("a pattern holding '/' is matched against a clean path, which no empty, \".\" or misplaced \"..\" component matches; write %q", fix)
	}
	return fmt.Errorf("a pattern holding '/' is matched against a clean path, which no empty, \".\" or misplaced \"..\" component, nor a glob matching no name, matches")
}

// above walks name's components against the pattern's from the first: ok when each matched the component glob at
// its place (filepath.Match) and the pattern had one for each; n is the number of name components. An empty or "."
// component of name is skipped, as the kernel's walk skips it. A name matches the pattern when ok and n ==
// len(comps), and lies above a path it matches when ok and n < len(comps).
func (rp *readPattern) above(name string) (n int, ok bool) {
	for name != "" {
		c, rest, _ := strings.Cut(name, string(filepath.Separator))
		name = rest
		if c == "" || c == "." {
			continue
		}
		if n == len(rp.comps) {
			return n, false
		}
		if m, _ := filepath.Match(rp.comps[n], c); !m {
			return n, false
		}
		n++
	}
	return n, true
}

// match reports whether the path pattern matches name, as filepath.Match on the whole string does for a clean name.
// The root "/" is the one clean path whose last name is empty, so it matches an absolute pattern of one component
// that matches "": "/*" as well as "/".
func (rp *readPattern) match(name string) bool {
	n, ok := rp.above(name)
	if ok && n == 0 && rp.abs && len(rp.comps) == 1 {
		m, _ := filepath.Match(rp.comps[0], "")
		return m
	}
	return ok && n == len(rp.comps)
}

// target is the name a path pattern is matched against for the absolute path p: p itself for an absolute pattern,
// the path from the worktree for a relative one; false when p is not absolute or no path from the worktree is taken.
func (rp *readPattern) target(p, worktree string) (string, bool) {
	if rp.abs {
		return p, filepath.IsAbs(p)
	}
	rel, err := filepath.Rel(worktree, p)
	return rel, err == nil
}

// holdsMatch reports whether end, an end of a move that leaves its name, could be a directory beneath which r's
// `fs.read matches` pattern matches a path: the move renames every file beneath it, so a later read of one is
// scored under a name the pattern may not match. Only a path pattern names a directory (a
// name-only pattern matches a base name, which a directory's move leaves as it was). A relative pattern is matched
// against the path from the worktree, so an end that is the worktree or holds it renames every path such a pattern
// can match. The caller asks it only of an end that may be a directory (Action.PathNotDir, DestNotDir).
func holdsMatch(r *compiledRule, end, worktree string) bool {
	if r.Predicate != ReadMatches || !r.read.path {
		return false
	}
	if !r.read.abs {
		e, w := filepath.Clean(end), filepath.Clean(worktree)
		if e == w || strings.HasPrefix(w, strings.TrimSuffix(e, string(filepath.Separator))+string(filepath.Separator)) {
			return true
		}
	}
	name, ok := r.read.target(end, worktree)
	if !ok {
		return true // no path from the worktree: fail closed
	}
	n, ok := r.read.above(name)
	return ok && n < len(r.read.comps)
}
