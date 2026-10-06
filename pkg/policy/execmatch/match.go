// SPDX-License-Identifier: Apache-2.0

package execmatch

import "strings"

// Match is how a pattern matched an invocation.
type Match uint8

// Matches.
const (
	// MatchNone is no match.
	MatchNone Match = iota
	// MatchDefinite is a match under every reading.
	MatchDefinite
	// MatchAmbiguous is a deny or ask match under some readings only (an unknown option's two readings, git's
	// autocorrection, an unlocatable interpretation).
	MatchAmbiguous
)

// String is the match as the record's command_match spells it.
func (m Match) String() string {
	switch m {
	case MatchNone:
		return "none"
	case MatchDefinite:
		return "definite"
	case MatchAmbiguous:
		return "ambiguous"
	}
	return "unknown"
}

// Match reports how p matches inv (ADR 0048 (1), (2)). A deny or ask pattern matches when any reading matches, and
// an unlocatable reading matches every one; a constrained allow pattern matches only when every reading matches, and
// never an unlocatable one. A bare pattern matches every invocation of its tool. It allocates nothing.
func (p *Pattern) Match(inv *Invocation) Match {
	if inv == nil || inv.Tool != p.Tool {
		return MatchNone
	}
	if p.Bare {
		return MatchDefinite
	}
	if p.Runtime != "" {
		if p.exactly(inv) {
			return MatchDefinite
		}
		return MatchNone
	}
	deny := p.List != ListAllow
	if p.Row == nil || inv.Row == nil || inv.Row != p.Row {
		var ok bool
		if deny {
			ok = p.genericDeny(inv.Tokens)
		} else {
			ok = p.genericAllow(inv.Tokens)
		}
		if ok {
			return MatchDefinite
		}
		return MatchNone
	}
	n, m, unloc := 0, 0, false
	for i := range inv.Readings {
		r := &inv.Readings[i]
		n++
		switch {
		case r.Unlocatable:
			unloc = true
			if deny {
				m++
			}
		case deny && p.denyReading(r):
			m++
		case !deny && p.allowReading(r):
			m++
		}
	}
	switch {
	case n == 0 || m == 0:
		return MatchNone
	case deny && (m < n || unloc):
		return MatchAmbiguous
	case m == n:
		return MatchDefinite
	}
	return MatchNone
}

// pathMatches reports whether a reading's subcommand path starts with the pattern's.
func (p *Pattern) pathMatches(r *Reading) bool {
	if len(r.Path) < len(p.Path) {
		return false
	}
	for i, w := range p.Path {
		if !Glob(w, r.Path[i]) {
			return false
		}
	}
	return true
}

// allowReading is a constrained allow pattern against one reading: the path starts with the pattern's, every named
// option is present where the tool reads it as one, and the operands equal the named ones (a trailing * allows
// more). An option the row does not list before the subcommand, or anywhere when the pattern names options or
// operands, means no match: either reading could change what they bind.
func (p *Pattern) allowReading(r *Reading) bool {
	if r.UnknownBefore || !p.pathMatches(r) {
		return false
	}
	if (len(p.Opts) > 0 || len(p.Operands) > 0) && r.Unknown {
		return false
	}
	for i := range p.Opts {
		po := &p.Opts[i]
		found := false
		for j := range r.Hits {
			h := &r.Hits[j]
			if h.Opt == nil || h.Neg != po.Neg || po.Opt == nil || h.Opt.Name != po.Opt.Name {
				continue
			}
			if !po.Opt.Persistent && h.Depth != po.Depth {
				continue
			}
			if po.HasValue && !(h.HasValue && Glob(po.Value, h.Value)) {
				continue
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	if len(p.Operands) > 0 {
		if len(r.Operands) < len(p.Operands) || !p.Rest && len(r.Operands) != len(p.Operands) {
			return false
		}
		for i, w := range p.Operands {
			if !Glob(w, r.Operands[i]) {
				return false
			}
		}
	}
	return true
}

// denyReading is a deny or ask pattern against one reading: the path starts with the pattern's, each named option is
// present anywhere the tool could read it as one (an option the row does not list counts by its spelling: the same
// long name or an abbreviation of it, the same letter), and the named operands are an ordered subsequence.
func (p *Pattern) denyReading(r *Reading) bool {
	if !p.pathMatches(r) {
		return false
	}
	for i := range p.Opts {
		if !p.optPresent(&p.Opts[i], r) {
			return false
		}
	}
	j := 0
	for _, op := range r.Operands {
		if j < len(p.Operands) && Glob(p.Operands[j], op) {
			j++
		}
	}
	return j == len(p.Operands)
}

// optPresent reports whether a deny pattern's option word is present in a reading.
func (p *Pattern) optPresent(po *PatOpt, r *Reading) bool {
	for j := range r.Hits {
		h := &r.Hits[j]
		if h.Neg != po.Neg {
			continue
		}
		var same bool
		switch {
		case h.Opt != nil && po.Opt != nil:
			same = h.Opt == po.Opt || h.Opt.Name == po.Opt.Name
		case h.Opt != nil:
			same = optSpells(h.Opt, po.Long, po.Short)
		case po.Opt != nil:
			same = rawCouldBe(h.Raw, po.Opt.Long, po.Opt.Short, "", 0)
		default:
			same = rawCouldBe(h.Raw, nil, "", po.Long, po.Short)
		}
		if !same {
			continue
		}
		if po.HasValue && !(h.HasValue && Glob(po.Value, h.Value)) {
			continue
		}
		return true
	}
	return false
}

// optSpells reports whether a row option has the long name or the letter a raw pattern word spells.
func optSpells(o *Opt, long string, short byte) bool {
	if short != 0 {
		return strings.IndexByte(o.Short, short) >= 0
	}
	for _, l := range o.Long {
		if l == long {
			return true
		}
	}
	return false
}

// rawCouldBe reports whether an option spelling the row does not list could be an option with these long names or
// letters (longs and shorts, plus one more long name and letter): an equal long name or an abbreviation of one (at
// least one letter), or a short cluster holding a letter. It allocates nothing.
func rawCouldBe(raw string, longs []string, shorts, long string, short byte) bool {
	isLong := func(l string) bool {
		return l != "" && (strings.HasPrefix(raw, "--") && len(raw) > 2 && strings.HasPrefix(l, raw[2:]) || len(raw) > 1 && raw[0] == '-' && raw[1:] == l)
	}
	for _, l := range longs {
		if isLong(l) {
			return true
		}
	}
	if isLong(long) {
		return true
	}
	if len(raw) < 2 || raw[1] == '-' {
		return false
	}
	for i := 1; i < len(raw); i++ {
		if strings.IndexByte(shorts, raw[i]) >= 0 || short != 0 && raw[i] == short {
			return true
		}
	}
	return false
}

// genericAllow is the generic fallback for an allow pattern: an exact token prefix (Codex's prefix_rule), each word a
// glob over one token. An option before the pattern's words means no match.
func (p *Pattern) genericAllow(toks []string) bool {
	if len(toks) < len(p.Words) {
		return false
	}
	for i, w := range p.Words {
		if !Glob(w, toks[i]) {
			return false
		}
	}
	return true
}

// genericDeny is the generic fallback for a deny or ask pattern, before the first `--`: its non-option words as an
// ordered subsequence of the tokens, a long option as an equal token, one starting with it and "=", or an
// abbreviation of it; a one-letter short option as -x, -x<value>, or a single-dash token of letters holding x. It
// over-matches by design: `mytool -r` refuses `mytool -prefix`.
func (p *Pattern) genericDeny(toks []string) bool {
	end := len(toks)
	for i, t := range toks {
		if t == "--" {
			end = i
			break
		}
	}
	toks = toks[:end]
	j := 0
	for _, t := range toks {
		if j < len(p.genWords) && Glob(p.genWords[j], t) {
			j++
		}
	}
	if j < len(p.genWords) {
		return false
	}
	for _, w := range p.genOpts {
		if !genericOptPresent(w, toks) {
			return false
		}
	}
	return true
}

// isOptionWord reports whether a pattern word is an option word.
func isOptionWord(w string) bool { return len(w) > 1 && w[0] == '-' }

// genericOptPresent reports whether a generic option word is present in tokens.
func genericOptPresent(w string, toks []string) bool {
	if strings.HasPrefix(w, "--") {
		name, value, hasEq := strings.Cut(w[2:], "=")
		for i, t := range toks {
			if !strings.HasPrefix(t, "--") || len(t) < 3 {
				continue
			}
			tn, tv, tEq := strings.Cut(t[2:], "=")
			if tn != name && !strings.HasPrefix(name, tn) {
				continue
			}
			if !hasEq {
				return true
			}
			if tEq && Glob(value, tv) || !tEq && i+1 < len(toks) && Glob(value, toks[i+1]) {
				return true
			}
		}
		return false
	}
	letters := w[1:]
	if len(letters) >= 2 && letters[1] == '=' {
		c, value := letters[0], letters[2:]
		for i, t := range toks {
			if len(t) < 2 || t[0] != '-' || t[1] != c {
				continue
			}
			v, attached := t[2:], len(t) > 2
			if attached && v[0] == '=' {
				v = v[1:]
			}
			if attached && Glob(value, v) || !attached && i+1 < len(toks) && Glob(value, toks[i+1]) {
				return true
			}
		}
		return false
	}
	for i := 0; i < len(letters); i++ {
		if !genericShortPresent(letters[i], toks) {
			return false
		}
	}
	return true
}

// genericShortPresent reports whether a short option letter is present: -x, -x<value>, or a single-dash token of
// letters holding x.
func genericShortPresent(c byte, toks []string) bool {
	for _, t := range toks {
		if len(t) < 2 || t[0] != '-' || t[1] == '-' {
			continue
		}
		if t[1] == c {
			return true
		}
		letters := true
		for k := 1; k < len(t); k++ {
			if !(t[k] >= 'a' && t[k] <= 'z' || t[k] >= 'A' && t[k] <= 'Z') {
				letters = false
				break
			}
		}
		if letters && strings.IndexByte(t[1:], c) >= 0 {
			return true
		}
	}
	return false
}

// Glob matches a pattern word against one token: * (any bytes), ? (one byte) and [...] classes ([!...] and [^...]
// negate, a-b ranges), with no special / and no escape. A malformed class matches its bytes literally. It allocates
// nothing.
func Glob(pattern, s string) bool {
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == s
	}
	px, sx := 0, 0
	nextPx, nextSx := -1, -1
	for px < len(pattern) || sx < len(s) {
		if px < len(pattern) {
			switch c := pattern[px]; c {
			case '*':
				nextPx, nextSx = px, sx+1
				px++
				continue
			case '?':
				if sx < len(s) {
					px++
					sx++
					continue
				}
			case '[':
				if sx < len(s) {
					if ok, n := classMatch(pattern[px:], s[sx]); n > 0 {
						if ok {
							px += n
							sx++
							continue
						}
					} else if s[sx] == '[' {
						px++
						sx++
						continue
					}
				}
			default:
				if sx < len(s) && s[sx] == c {
					px++
					sx++
					continue
				}
			}
		}
		if nextSx > 0 && nextSx <= len(s) {
			px, sx = nextPx, nextSx
			continue
		}
		return false
	}
	return true
}

// classMatch matches one byte against a [...] class at the start of p; n is the class's length, 0 when it is not
// closed (then [ is literal).
func classMatch(p string, c byte) (ok bool, n int) {
	i := 1
	neg := false
	if i < len(p) && (p[i] == '!' || p[i] == '^') {
		neg = true
		i++
	}
	start := i
	for ; i < len(p); i++ {
		if p[i] == ']' && i > start {
			return ok != neg, i + 1
		}
		lo := p[i]
		hi := lo
		if i+2 < len(p) && p[i+1] == '-' && p[i+2] != ']' {
			hi = p[i+2]
			i += 2
		}
		if lo <= c && c <= hi {
			ok = true
		}
	}
	return false, 0
}
