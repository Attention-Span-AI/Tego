// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"slices"
	"strings"
)

// MaxReadings bounds the readings one interpretation keeps. Each option the row does not list, standing where a
// subcommand could still be, doubles them; past the bound the interpretation is unlocatable, which matches every
// deny and ask entry naming its tool and no constrained allow entry (the fail-closed direction).
const MaxReadings = 16

// Hit is one option a reading found.
type Hit struct {
	// Opt is the row's option, nil for one the row does not list.
	Opt *Opt
	// Raw is the spelling as written, without its value: "--forc", "-x", "--newopt". On a level whose Syntax reads
	// Underscores it is the spelling the tool reads, `_` as `-` ("--build-snapshot" for --build_snapshot).
	Raw string
	// Value is the option's value when HasValue.
	Value    string
	HasValue bool
	// Neg is git parse-options' --no-<name>: the option turned off.
	Neg bool
	// Depth is the subcommand depth the option was read at: 0 before the first subcommand word.
	Depth int
}

// Reading is one way the tool can read its tokens.
type Reading struct {
	// Path is the subcommand path, canonical names where the row knows them and the token itself where it does not.
	Path []string
	// Hits are the options read, in order.
	Hits []Hit
	// Operands are the operand tokens in order.
	Operands []string
	// UnknownBefore is set when an option the row does not list stood where a subcommand could still be.
	UnknownBefore bool
	// Unknown is set when an option the row does not list stood anywhere before `--`.
	Unknown bool
	// Located is set when the reading reached a level without subcommands: later tokens cannot move its path.
	Located bool
	// Corrected is set when the first subcommand word is git's autocorrection of the token, not the token.
	Corrected bool
	// Unlocatable is set by a visible rewrite trigger (cargo --config alias.*, gcloud --flags-file).
	Unlocatable bool
	// Dispatch is the token index of the first operand at the top level (an interpreter's script), -1 when none;
	// DispatchAfter is the index of the first token after a Stop option's value (python -m's module arguments), -1
	// when none.
	Dispatch, DispatchAfter int
}

// parseState is one reading in progress.
type parseState struct {
	lv      *Level
	depth   int
	i       int
	afterDD bool
	opsOnly bool
	r       Reading
}

// fork copies a state for a second reading; the copy shares nothing it could append to.
func (s *parseState) fork() parseState {
	c := *s
	c.r.Path = append([]string(nil), s.r.Path...)
	c.r.Hits = append([]Hit(nil), s.r.Hits...)
	c.r.Operands = append([]string(nil), s.r.Operands...)
	return c
}

// located reports whether later tokens can still move the reading's subcommand path.
func (s *parseState) located() bool { return s.lv == nil || s.lv.Subs == nil }

// undecided reports whether an option the row does not list is still read both ways: a later token can move the
// reading's subcommand path, or, on an interpreter row, its script. An interpreter's script is its subcommand, and an
// option in front of it picks which token that is: a value reading there does not only remove words (ADR 0048 R4).
func (nz *Normalizer) undecided(s *parseState) bool {
	return !s.located() || nz.row.Interp != nil && s.r.Dispatch < 0 && s.r.DispatchAfter < 0
}

// Normalizer parses tokens with a row. It holds no state between calls and is safe for concurrent use.
type Normalizer struct {
	row  *Row
	cand *Candidates
}

// NewNormalizer returns a normalizer for row. cand is git's autocorrect candidate set for a row with Autocorrect,
// nil for the row's own built-in list.
func NewNormalizer(row *Row, cand *Candidates) *Normalizer {
	row.ready()
	if cand == nil && row.Autocorrect {
		cand = NewCandidates(row.Builtins, row.Common)
	}
	return &Normalizer{row: row, cand: cand}
}

// Normalize parses tokens (argv after the command word) into every reading the tool could make, at most
// MaxReadings; past that, one Unlocatable reading. The tokens are the whole vector.
func (nz *Normalizer) Normalize(tokens []string) []Reading { return nz.NormalizeOpen(tokens, false) }

// NormalizeOpen is Normalize of tokens that are the whole vector (open false) or only a prefix of it (open true: a
// staged read stopped there, ADR 0048 (3)). The end of a prefix is not the end of the command line, so a level's
// default subcommand is not entered there: `git stash` cut after stash may be `git stash drop`, and the reading stays
// at stash, not Located, until more of the vector is read.
func (nz *Normalizer) NormalizeOpen(tokens []string, open bool) []Reading {
	stack := []parseState{{lv: nz.row.Root, r: Reading{Dispatch: -1, DispatchAfter: -1}}}
	var out []Reading
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		forks := nz.run(&s, tokens, open)
		if len(out)+len(stack)+len(forks)+1 > MaxReadings {
			return []Reading{{Unlocatable: true, Dispatch: -1, DispatchAfter: -1}}
		}
		stack = append(stack, forks...)
		if s.located() {
			s.r.Located = true
		}
		out = append(out, s.r)
	}
	return out
}

// run parses s to the end of tokens and returns the readings it forked on the way. open says the tokens are a prefix
// of the vector: their end enters no default subcommand.
func (nz *Normalizer) run(s *parseState, toks []string, open bool) []parseState {
	var forks []parseState
	for s.i < len(toks) {
		tok := toks[s.i]
		switch {
		case s.afterDD || s.opsOnly:
			nz.operand(s, tok)
		case tok == "-" && s.lv != nil && s.lv.Syntax.DashEnds:
			s.afterDD = true
			s.i++
			continue
		case tok == "--":
			if s.lv != nil && s.lv.Syntax.DashDashUnknown {
				s.r.Hits = append(s.r.Hits, Hit{Raw: tok, Depth: s.depth})
				nz.unknown(s)
			} else {
				nz.defaultSub(s)
				s.afterDD = true
			}
			s.i++
			continue
		case len(tok) > 1 && tok[0] == '-' && tok[1] == '-':
			nz.defaultSub(s)
			if f, ok := nz.long(s, toks, tok[2:]); ok {
				forks = append(forks, f)
			}
			continue
		case len(tok) > 1 && tok[0] == '-' && s.lv != nil && s.lv.Syntax.SingleDashLong:
			nz.defaultSub(s)
			if f, ok := nz.long(s, toks, tok[1:]); ok {
				forks = append(forks, f)
			}
			continue
		case len(tok) > 1 && (tok[0] == '-' || tok[0] == '+' && s.lv != nil && s.lv.Syntax.PlusOptions):
			nz.defaultSub(s)
			if f, ok := nz.short(s, toks, tok); ok {
				forks = append(forks, f)
			}
			continue
		default:
			forks = append(forks, nz.word(s, tok)...)
		}
		s.i++
	}
	if !open {
		nz.defaultSub(s)
	}
	return forks
}

// defaultSub enters a level's default subcommand when an option, `--` or the end of the tokens comes where its
// subcommand would stand: `git stash -m x` and `git stash` are `git stash push`. The end of a prefix is not the end
// of the tokens (NormalizeOpen).
func (nz *Normalizer) defaultSub(s *parseState) {
	if s.lv != nil && s.lv.Subs != nil && s.lv.Default != "" && !s.afterDD && !s.opsOnly {
		nz.descend(s, s.lv.Default, s.lv.Subs[s.lv.Default])
	}
}

// operand records an operand.
func (nz *Normalizer) operand(s *parseState, tok string) {
	if s.depth == 0 && s.r.Dispatch < 0 && s.r.DispatchAfter < 0 {
		s.r.Dispatch = s.i
	}
	s.r.Operands = append(s.r.Operands, tok)
	if s.lv == nil || !s.lv.Syntax.Permute {
		s.opsOnly = true
	}
}

// word handles a token that is not an option: a subcommand while the level has them, else an operand. It returns
// the readings a SubPrefix ambiguity or git's autocorrection added.
func (nz *Normalizer) word(s *parseState, tok string) []parseState {
	lv := s.lv
	if lv == nil || lv.Subs == nil {
		nz.operand(s, tok)
		return nil
	}
	if lv.skip(tok) {
		return nil
	}
	if path, child, ok := lv.sub(tok); ok {
		nz.descendPath(s, path, child)
		return nil
	}
	var forks []parseState
	if lv.SubPrefix {
		var buf [8]string
		var first []string
		var firstLv *Level
		for _, c := range lv.prefixes(buf[:0], tok) {
			path, child, ok := lv.sub(c)
			if !ok {
				continue
			}
			if first == nil {
				first, firstLv = path, child
				continue
			}
			f := s.fork()
			nz.descendPath(&f, path, child)
			f.i++
			forks = append(forks, f)
		}
		if first != nil {
			nz.descendPath(s, first, firstLv)
			return forks
		}
	}
	if s.depth == 0 && nz.row.Autocorrect && nz.cand != nil {
		if target, ok := Autocorrect(tok, nz.cand); ok {
			if child, found := lv.Subs[target]; found {
				f := s.fork()
				f.r.Corrected = true
				nz.descend(&f, target, child)
				f.i++
				forks = append(forks, f)
			}
		}
	}
	if lv.Wild != nil {
		nz.descend(s, tok, lv.Wild)
		return forks
	}
	// An unknown subcommand (a plugin, an external command, an alias that re-execs): its token is the path, and
	// the level below it reads only the options persistent above it.
	s.r.Path = append(s.r.Path, tok)
	s.lv = &Level{parent: lv, Syntax: lv.Syntax}
	s.depth++
	return forks
}

// descend enters a subcommand's level.
func (nz *Normalizer) descend(s *parseState, name string, child *Level) {
	s.r.Path = append(s.r.Path, name)
	if child == nil {
		child = &Level{parent: s.lv, Syntax: s.lv.Syntax}
	}
	s.lv = child
	s.depth++
}

// descendPath enters the level an alias path ends at, every name of the path on the reading's path.
func (nz *Normalizer) descendPath(s *parseState, path []string, child *Level) {
	s.r.Path = append(s.r.Path, path...)
	if child == nil {
		child = &Level{parent: s.lv, Syntax: s.lv.Syntax}
	}
	s.lv = child
	s.depth += len(path)
}

// unknown marks an option the row does not list.
func (nz *Normalizer) unknown(s *parseState) {
	s.r.Unknown = true
	if !s.located() {
		s.r.UnknownBefore = true
	}
}

// long parses --name[=value] (or -name under SingleDashLong) at s.i and advances past it. It returns a fork when an
// unknown option may take the next token where a subcommand could still be.
func (nz *Normalizer) long(s *parseState, toks []string, body string) (parseState, bool) {
	tok := toks[s.i]
	name, value, hasEq := strings.Cut(body, "=")
	raw := tok
	if hasEq {
		raw = tok[:len(tok)-len(value)-1]
	}
	lv := s.lv
	if lv == nil {
		lv = &Level{}
	}
	if lv.Syntax.Underscores && strings.Contains(name, "_") {
		// node reads the name with `_` as `-` before it looks for the option or its negation (Syntax.Underscores).
		name = strings.ReplaceAll(name, "_", "-")
		raw = raw[:len(raw)-len(name)] + name
	}
	o := lv.long(name)
	neg := false
	if o == nil && lv.Syntax.Negatable && strings.HasPrefix(name, "no-") {
		if o = lv.long(name[3:]); o != nil {
			neg = true
		}
	}
	if o == nil && lv.Syntax.LongPrefix && name != "" {
		if c, ok := lv.longPrefix(name); ok {
			o = c
		} else if lv.Syntax.Negatable && strings.HasPrefix(name, "no-") {
			if c, ok := lv.longPrefix(name[3:]); ok {
				o, neg = c, true
			}
		}
	}
	if o == nil {
		h := Hit{Raw: raw, Value: value, HasValue: hasEq, Depth: s.depth}
		s.r.Hits = append(s.r.Hits, h)
		before := nz.undecided(s)
		nz.unknown(s)
		s.i++
		if !hasEq && before && s.i < len(toks) {
			// Either reading: a flag (this one), or an option that takes the next token as its value.
			f := s.fork()
			f.r.Hits[len(f.r.Hits)-1].Value, f.r.Hits[len(f.r.Hits)-1].HasValue = toks[f.i], true
			f.i++
			return f, true
		}
		return parseState{}, false
	}
	s.i++
	h := Hit{Opt: o, Raw: raw, Value: value, HasValue: hasEq, Neg: neg, Depth: s.depth}
	if o.Arg == ArgNextWord {
		// Neither an attached value nor the negation settles it: only the next token does (ArgNextWord).
		h.Value, h.HasValue = "", false
		return nz.separate(s, toks, h)
	}
	if hasEq || neg || o.Arg == ArgRequired && !(lv.Syntax.LongSep || o.SepOnly || lv.Syntax.SingleDashLong) {
		nz.hit(s, h)
		return parseState{}, false
	}
	return nz.separate(s, toks, h)
}

// separate records a known option written without an attached value, taking the next token as its value as the
// option's kind says, and returns the fork of an ArgMaybe option's other reading.
func (nz *Normalizer) separate(s *parseState, toks []string, h Hit) (parseState, bool) {
	o := h.Opt
	next, has := "", s.i < len(toks)
	if has {
		next = toks[s.i]
	}
	switch o.Arg {
	case ArgRequired:
		if has {
			h.Value, h.HasValue = next, true
			s.i++
		}
	case ArgMaybe:
		if len(o.Values) > 0 {
			for _, v := range o.Values {
				if has && next == v {
					h.Value, h.HasValue = next, true
					s.i++
					break
				}
			}
			break
		}
		before := nz.undecided(s)
		nz.hit(s, h)
		if !before || !has {
			return parseState{}, false
		}
		f := s.fork()
		f.r.Hits[len(f.r.Hits)-1].Value, f.r.Hits[len(f.r.Hits)-1].HasValue = next, true
		f.i++
		return f, true
	case ArgNone:
		if s.lv != nil && s.lv.Syntax.BoolValues && has && (next == "true" || next == "false") {
			h.Value, h.HasValue = next, true
			s.i++
		}
	case ArgNextWord:
		if has && next != "" && next[0] != '-' {
			h.Value, h.HasValue = next, true
			s.i++
			if o.WordTo == "" {
				break
			}
			if to := s.lv.long(o.WordTo); to != nil {
				// The word is the WordTo option's value as well: node's -p x is --print --eval x.
				nz.hit(s, h)
				nz.hit(s, Hit{Opt: to, Raw: h.Raw, Value: next, HasValue: true, Depth: s.depth})
				return parseState{}, false
			}
		}
	case ArgOptional:
	}
	nz.hit(s, h)
	return parseState{}, false
}

// short parses a single-dash token at s.i (a cluster where the level clusters) and advances past it.
func (nz *Normalizer) short(s *parseState, toks []string, tok string) (parseState, bool) {
	lv := s.lv
	if lv == nil {
		lv = &Level{}
	}
	s.i++
	if lv.Syntax.ShortWords && len(tok) > 2 && tok[0] == '-' {
		if o := lv.long(tok[1:]); o != nil {
			if o.Arg == ArgNone || o.Arg == ArgOptional {
				nz.hit(s, Hit{Opt: o, Raw: tok, Depth: s.depth})
				return parseState{}, false
			}
			return nz.separate(s, toks, Hit{Opt: o, Raw: tok, Depth: s.depth})
		}
	}
	if !lv.Syntax.Clusters && len(tok) > 2 && !slices.Contains(lv.Syntax.ClusterWords, tok) {
		// A level that does not cluster reads -abc as one option it does not list, unless -a takes an attached value.
		if o := lv.shortOpt(tok[1]); o != nil && o.Arg != ArgNone && o.Arg != ArgNextWord && !o.SepOnly && (lv.Syntax.ShortAttach || o.Arg == ArgOptional || lv.Syntax.ShortEquals && tok[2] == '=') {
			v := tok[2:]
			if lv.Syntax.ShortEquals && v[0] == '=' {
				v = v[1:]
			}
			nz.hit(s, Hit{Opt: o, Raw: tok[:2], Value: v, HasValue: true, Depth: s.depth})
			return parseState{}, false
		}
		s.r.Hits = append(s.r.Hits, Hit{Raw: tok, Depth: s.depth})
		before := nz.undecided(s)
		nz.unknown(s)
		return nz.maybeValueFork(s, toks, before)
	}
	for j := 1; j < len(tok); j++ {
		c := tok[j]
		o := lv.shortOpt(c)
		if o == nil {
			s.r.Hits = append(s.r.Hits, Hit{Raw: string([]byte{tok[0], c}), Depth: s.depth})
			before := nz.undecided(s)
			nz.unknown(s)
			if j == len(tok)-1 {
				return nz.maybeValueFork(s, toks, before)
			}
			// Letters follow: the flag reading keeps them as options, which is the reading a deny entry takes; the
			// reading where they are this option's value moves no subcommand.
			continue
		}
		if o.Arg == ArgNone || o.Arg == ArgNextWord {
			// An ArgNextWord letter takes no attached value: letters after it are options, and a word after the
			// cluster is its value.
			if j == len(tok)-1 {
				return nz.separate(s, toks, Hit{Opt: o, Raw: string([]byte{tok[0], c}), Depth: s.depth})
			}
			nz.hit(s, Hit{Opt: o, Raw: string([]byte{tok[0], c}), Depth: s.depth})
			continue
		}
		rest := tok[j+1:]
		if rest != "" {
			if o.SepOnly {
				// git's -C. is an unknown option, not -C with ".".
				s.r.Hits = append(s.r.Hits, Hit{Raw: tok, Depth: s.depth})
				before := nz.undecided(s)
				nz.unknown(s)
				return nz.maybeValueFork(s, toks, before)
			}
			if lv.Syntax.ShortEquals && rest[0] == '=' {
				rest = rest[1:]
			}
			nz.hit(s, Hit{Opt: o, Raw: string([]byte{tok[0], c}), Value: rest, HasValue: true, Depth: s.depth})
			return parseState{}, false
		}
		h := Hit{Opt: o, Raw: string([]byte{tok[0], c}), Depth: s.depth}
		if o.Arg == ArgOptional {
			nz.hit(s, h)
			return parseState{}, false
		}
		return nz.separate(s, toks, h)
	}
	return parseState{}, false
}

// maybeValueFork forks the reading in which an unknown option takes the next token, when it stood where a
// subcommand or an interpreter's script could still be (undecided).
func (nz *Normalizer) maybeValueFork(s *parseState, toks []string, before bool) (parseState, bool) {
	if !before || s.i >= len(toks) {
		return parseState{}, false
	}
	f := s.fork()
	f.r.Hits[len(f.r.Hits)-1].Value, f.r.Hits[len(f.r.Hits)-1].HasValue = toks[f.i], true
	f.i++
	return f, true
}

// hit records a known option and applies what it does to the parse.
func (nz *Normalizer) hit(s *parseState, h Hit) {
	o := h.Opt
	if o.Rewrite != nil && !h.Neg && o.Rewrite(h.Value) {
		s.r.Unlocatable = true
	}
	if o.AsSub != "" && s.lv != nil && s.lv.Subs != nil {
		if child, ok := s.lv.Subs[o.AsSub]; ok {
			s.r.Hits = append(s.r.Hits, h)
			nz.descend(s, o.AsSub, child)
			return
		}
	}
	s.r.Hits = append(s.r.Hits, h)
	if o.ends(h.HasValue, h.Value) {
		s.afterDD = true
	}
	if o.Stop {
		s.opsOnly = true
		if s.depth == 0 {
			s.r.DispatchAfter = s.i
		}
	}
}
