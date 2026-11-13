// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"slices"
	"strings"
)

// MaxReadings bounds the readings one interpretation keeps. Unknown options,
// unestablished value bindings and separator vocabularies can multiply them;
// past the bound the interpretation is unlocatable, which matches every
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
	// UnknownBefore is set when an unlisted option precedes command selection.
	// A default parent's alternative instead retains Unknown: its immediate-default
	// reading and both arities already bound its paths within that parent scope.
	UnknownBefore bool
	// Unknown is set when an option the row does not list stood anywhere before `--`.
	Unknown bool
	// Located is set when the reading reached a level without subcommands: later tokens cannot move its path.
	Located bool
	// Corrected is set when the first subcommand word is git's autocorrection of the token, not the token.
	Corrected bool
	// Unlocatable is set by a visible rewrite trigger (cargo --config alias.*,
	// gcloud --flags-file), an exceeded parse bound, or a rejected required value
	// whose parser cannot successfully select a command (argparse).
	Unlocatable bool
	// Pending is set, on a prefix only (NormalizeOpen with open true), when later tokens can still change the reading
	// beyond adding options and operands to it (ADR 0048 (3), staged reads): an option at the prefix's end waits for its
	// value (python's -m, whose value is the module it runs), or later options could
	// fork it past MaxReadings, reject a required value, exhaust an assignment-splice
	// bound, or make it unlocatable through Opt.Rewrite (cargo's --config after the
	// subcommand). These conditions also matter after a path has been located.
	// A decision that reads a pending reading is not final.
	Pending bool
	// Dispatch is the token index of the first operand at the top level (an interpreter's script), -1 when none;
	// DispatchAfter is the index of the first token after a Stop option's value (python -m's module arguments), -1
	// when none.
	Dispatch, DispatchAfter int
}

// parseState is one reading in progress.
type parseState struct {
	lv                *Level
	depth             int
	i                 int
	afterDD           bool
	commandAfterDD    bool
	flagsAfterCommand bool
	// optionBoundary is an ended parser whose options no later parser inherits.
	optionBoundary *Level
	tokens         []string // immutable per-reading token stream after a parser splice
	expansions     int
	// terminatorPending preserves the historical staged-read hold after command-position terminators.
	terminatorPending bool
	// explicitOptions retains command-level option parsing before an explicit child,
	// alongside the historical reading which entered the default immediately.
	explicitOptions bool
	opsOnly         bool
	// wants is set when the tokens ended where an option takes the next token as its value (separate).
	wants bool
	r     Reading
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

// pending reports whether more tokens can still change a reading whose tokens ended at s (Reading.Pending): an option
// at the end waits for its value, or the reading still reads options and a later one could fork it or rewrite it.
func (nz *Normalizer) pending(s *parseState) bool {
	if s.wants {
		return true
	}
	if s.afterDD || s.opsOnly {
		return s.commandAfterDD && !s.located()
	}
	return nz.undecided(s) || s.lv.rewrites() || nz.optionsMayUnlocate(s)
}

// optionsMayUnlocate preserves the staged-read hold while later options can
// reject a required value or exhaust a parse bound, even after an unrelated
// command path has been selected. Ended ancestor vocabularies do not count.
func (nz *Normalizer) optionsMayUnlocate(s *parseState) bool {
	lv := nz.options(s)
	if lv.Syntax.SplitEquals || lv.Syntax.NoptShorthands {
		return true
	}
	for l := lv; l != nil; l = l.parent {
		for _, o := range l.Opts {
			if l != lv && !o.Persistent {
				continue
			}
			if o.Arg == ArgMaybe && len(o.Values) == 0 {
				return true
			}
			if o.Arg != ArgRequired {
				continue
			}
			mode := o.NextOption
			if mode == NextOptionDefault {
				mode = lv.Syntax.NextOption
			}
			if mode == NextOptionArgparse || mode == NextOptionDefault || mode == NextOptionBoth {
				return true
			}
		}
	}
	return false
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
		s.r.Pending = open && (s.terminatorPending || nz.pending(&s))
		out = append(out, s.r)
	}
	return out
}

// splitEquals models nopt's splice at the point that an option is read. Doing
// this lazily matters: a preceding numeric/path option may consume the entire
// assignment as its value. Each fork keeps its own immutable token stream.
func (nz *Normalizer) splitEquals(s *parseState, toks []string, tok string) bool {
	if s.afterDD || s.opsOnly || s.lv == nil || !s.lv.Syntax.SplitEquals {
		return false
	}
	name, value, eq := strings.Cut(tok, "=")
	if !eq || len(name) < 2 || name[0] != '-' {
		return false
	}
	lv := nz.options(s)
	lookup := name
	if lv.Syntax.TrimOptionDashes && strings.HasPrefix(lookup, "--") {
		lookup = "--" + strings.TrimLeft(lookup, "-")
	}
	known := false
	switch {
	case strings.HasPrefix(lookup, "--"):
		known = lv.long(lookup[2:]) != nil
		if !known {
			known = noptShort(lv, lookup[2:]) != nil
		}
		if !known && lv.Syntax.LongPrefix {
			_, known = lv.longPrefix(lookup[2:])
		}
	case len(name) == 2:
		known = lv.shortOpt(name[1]) != nil
	case lv.Syntax.ShortWords:
		known = lv.long(name[1:]) != nil
	}
	if !known {
		return false // unknown assignments retain their attached-value reading
	}
	s.expansions++
	// The released attached-value reading could still reach a pending option
	// later in this prefix. A splice must not make its earlier stop final.
	s.terminatorPending = true
	if s.expansions > MaxReadings {
		s.r.Unlocatable = true
		s.i = len(toks)
		return false
	}
	next := make([]string, 0, len(toks)+1)
	next = append(next, toks[:s.i]...)
	next = append(next, name, value)
	next = append(next, toks[s.i+1:]...)
	s.tokens = next
	return true
}

// noptShort applies resolveShort's exact shorthand precedence before a long
// abbreviation. Only the source-audited one-to-one aliases have a real long
// target here; d/q/s/n retain the existing row's pseudo-option representation.
func noptShort(lv *Level, name string) *Opt {
	if !lv.Syntax.NoptShorthands || len(name) != 1 {
		return nil
	}
	if o := lv.shortOpt(name[0]); o != nil && len(o.Long) > 0 && o.Long[0] == o.Name {
		return o
	}
	return nil
}

// expandShorthands models nopt's source-established simple short compounds.
// Long words emitted by a compound are visible to the preceding value reader:
// -Cc expands to --prefix --call, so prefix consumes the literal --call.
// Emitted option hits use those long spellings; exact single short hits retain
// their original spelling. Work is bounded before allocating a replacement.
func (nz *Normalizer) expandShorthands(s *parseState, toks []string, tok string) bool {
	if s.afterDD || s.opsOnly || s.lv == nil || !s.lv.Syntax.NoptShorthands || len(tok) < 2 || tok[0] != '-' {
		return false
	}
	raw, value, eq := strings.Cut(tok, "=")
	name := strings.TrimLeft(raw, "-")
	lv := nz.options(s)
	if name == "" || lv.long(name) != nil || len(name) == 1 && (len(raw) == 2 || noptShort(lv, name) != nil) {
		return false
	}
	// An ordinary long option or unknown word is not a compound. Only a
	// word of declared short aliases needs the expansion below.
	for i := range name {
		if lv.shortOpt(name[i]) == nil {
			return false
		}
	}
	if len(name) > MaxReadings {
		s.r.Unlocatable, s.i = true, len(toks)
		return false
	}
	var expanded []string
	for i := range name {
		o := noptShort(lv, name[i:i+1])
		if o == nil {
			// A pseudo/multiword alias can expose an inserted operand when a
			// preceding value consumes its option. Do not invent a command.
			s.r.Unlocatable, s.i = true, len(toks)
			return false
		}
		expanded = append(expanded, "--"+o.Long[0])
	}
	s.expansions += len(expanded)
	s.terminatorPending = true
	if s.expansions > MaxReadings {
		s.r.Unlocatable, s.i = true, len(toks)
		return false
	}
	next := make([]string, 0, len(toks)+len(expanded))
	next = append(next, toks[:s.i]...)
	next = append(next, expanded...)
	if eq {
		next = append(next, value)
	}
	next = append(next, toks[s.i+1:]...)
	s.tokens = next
	return true
}

// run parses s to the end of tokens and returns the readings it forked on the way. open says the tokens are a prefix
// of the vector: their end enters no default subcommand.
func (nz *Normalizer) run(s *parseState, toks []string, open bool) []parseState {
	var forks []parseState
	if s.tokens != nil {
		toks = s.tokens
	}
	for s.i < len(toks) {
		if len(forks) >= MaxReadings {
			return forks // NormalizeOpen replaces an over-budget set with an unlocatable reading.
		}
		tok := toks[s.i]
		if nz.expandShorthands(s, toks, tok) {
			toks = s.tokens
			continue
		}
		if s.r.Unlocatable && s.i >= len(toks) {
			break
		}
		if nz.splitEquals(s, toks, tok) {
			toks = s.tokens
			continue
		}
		if s.r.Unlocatable && s.i >= len(toks) {
			break
		}
		switch {
		case s.afterDD && s.commandAfterDD && !s.located():
			forks = append(forks, nz.word(s, tok)...)
			if s.flagsAfterCommand {
				s.afterDD, s.commandAfterDD, s.flagsAfterCommand = false, false, false
			}
		case s.afterDD || s.opsOnly:
			nz.operand(s, tok)
		case tok == "-" && s.lv != nil && s.lv.Syntax.DashEnds:
			s.afterDD = true
			s.i++
			continue
		case tok == "--" || s.lv != nil && s.lv.Syntax.AllDashTerminator && len(tok) > 2 && strings.Trim(tok, "-") == "":
			syn := Syntax{}
			if s.lv != nil {
				syn = s.lv.Syntax
			}
			if tok != "--" || !s.located() && !syn.DashDashUnknown {
				// Keep the old staged-read hold at command levels. Newly recognized
				// all-dash forms also retain it: the old unknown-option reading could
				// still reach a value-taking option at the end of this prefix.
				s.terminatorPending = true
			}
			if syn.DashDashUnknown || !s.located() && syn.Terminator == TerminatorUnknown {
				s.r.Hits = append(s.r.Hits, Hit{Raw: tok, Depth: s.depth})
				before := nz.undecided(s)
				nz.unknown(s)
				s.i++
				if f, ok := nz.maybeValueFork(s, toks, before); ok {
					forks = append(forks, f)
				}
				continue
			}
			mode := syn.Terminator
			if !s.located() && mode == TerminatorBoth {
				// The historical operand reading remains. Unestablished dispatch may also
				// select a child; neither reading can erase a refusal (ADR 0048 (2)).
				f := s.fork()
				nz.defaultSub(&f)
				f.afterDD = true
				f.i++
				forks = append(forks, f)
				// Some dispatchers also scan this token as a value-taking unknown
				// option (cobra Traverse). Keep that reading until established.
				f = s.fork()
				f.r.Hits = append(f.r.Hits, Hit{Raw: tok, Depth: f.depth})
				nz.unknown(&f)
				f.i++
				if f.i < len(toks) {
					f.r.Hits[len(f.r.Hits)-1].Value, f.r.Hits[len(f.r.Hits)-1].HasValue = toks[f.i], true
					f.i++
				}
				forks = append(forks, f)
			}
			if !s.located() && mode != TerminatorOperands {
				s.commandAfterDD = true
				s.flagsAfterCommand = mode == TerminatorCommandFlags || mode == TerminatorBoth
				if s.flagsAfterCommand {
					switch syn.TerminatorOptions {
					case TerminatorOptionsBoth:
						f := s.fork()
						f.afterDD, f.flagsAfterCommand = true, false
						f.i++
						forks = append(forks, f)
						f = s.fork()
						f.afterDD, f.optionBoundary = true, s.lv
						f.i++
						forks = append(forks, f)
					case TerminatorOptionsNone:
						s.flagsAfterCommand = false
					case TerminatorOptionsChild:
						s.optionBoundary = s.lv
					case TerminatorOptionsInherit:
						// The ordinary inherited vocabulary already applies.
					}
				}
			} else {
				nz.defaultSub(s)
			}
			s.afterDD = true
			s.i++
			continue
		case len(tok) > 1 && tok[0] == '-' && tok[1] == '-':
			nz.defaultOption(s, toks, &forks)
			if f, ok := nz.long(s, toks, tok[2:]); ok {
				forks = append(forks, f)
			}
			continue
		case len(tok) > 1 && tok[0] == '-' && s.lv != nil && s.lv.Syntax.SingleDashLong:
			nz.defaultOption(s, toks, &forks)
			if f, ok := nz.long(s, toks, tok[1:]); ok {
				forks = append(forks, f)
			}
			continue
		case len(tok) > 1 && (tok[0] == '-' || tok[0] == '+' && s.lv != nil && s.lv.Syntax.PlusOptions):
			nz.defaultOption(s, toks, &forks)
			if f, ok := nz.short(s, toks, tok, &forks); ok {
				forks = append(forks, f)
			}
			continue
		default:
			if (tok == "-" || tok == "") && !s.located() {
				f := s.fork()
				nz.unknown(&f)
				f.i++
				forks = append(forks, f)
			}
			forks = append(forks, nz.word(s, tok)...)
		}
		s.i++
	}
	if !open {
		nz.defaultSub(s)
	}
	return forks
}

// defaultOption keeps both ways a command level can process an option: enter its
// default immediately, or parse options here and select an explicit child later.
// Git notes --ref NAME get-ref uses the latter; not every default dispatcher does.
func (nz *Normalizer) defaultOption(s *parseState, toks []string, forks *[]parseState) {
	if s.explicitOptions || s.lv == nil || s.lv.Subs == nil || s.lv.Default == "" {
		return
	}
	// A child-only option already selects the default. Treating it as unknown at
	// the parent would refuse a plain allow naming the default dispatcher.
	if !nz.listedOption(s, toks) {
		child := s.fork()
		nz.defaultSub(&child)
		if nz.listedOption(&child, toks) {
			nz.defaultSub(s)
			return
		}
	}
	f := s.fork()
	f.explicitOptions = true // consume this option on resumption, without forking it again
	*forks = append(*forks, f)
	nz.defaultSub(s)
}

// listedOption probes the existing option parser on an isolated state; option
// names, abbreviations and clusters have the same interpretation as the real read.
func (nz *Normalizer) listedOption(s *parseState, toks []string) bool {
	f := s.fork()
	n := len(f.r.Hits)
	tok := toks[f.i]
	switch {
	case strings.HasPrefix(tok, "--"):
		nz.long(&f, toks, tok[2:])
	case f.lv.Syntax.SingleDashLong:
		nz.long(&f, toks, tok[1:])
	default:
		var forks []parseState
		nz.short(&f, toks, tok, &forks)
	}
	if n == len(f.r.Hits) {
		return false
	}
	for _, h := range f.r.Hits[n:] {
		if h.Opt == nil {
			return false
		}
	}
	return true
}

// options makes a read-only view of the current vocabulary, cutting off an ended
// ancestor without changing the shared row or its prepared option indices.
func (nz *Normalizer) options(s *parseState) *Level {
	var view func(*Level) *Level
	view = func(lv *Level) *Level {
		if lv == nil || lv == s.optionBoundary {
			return nil
		}
		if s.optionBoundary == nil {
			return lv
		}
		c := *lv
		c.parent = view(lv.parent)
		return &c
	}
	if lv := view(s.lv); lv != nil {
		return lv
	}
	return &Level{}
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
			f := s.fork()
			f.r.Corrected = true
			if path, child, found := lv.sub(target); found {
				nz.descendPath(&f, path, child)
			} else {
				// Compile also supplies executable helpers absent from the row.
				// Keep their corrected unknown leaf and inherited grammar.
				nz.descend(&f, target, nil)
			}
			f.i++
			forks = append(forks, f)
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
	s.explicitOptions = false
	s.r.Path = append(s.r.Path, name)
	if child == nil {
		child = &Level{parent: s.lv, Syntax: s.lv.Syntax}
	}
	s.lv = child
	s.depth++
}

// descendPath enters the level an alias path ends at, every name of the path on the reading's path.
func (nz *Normalizer) descendPath(s *parseState, path []string, child *Level) {
	s.explicitOptions = false
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
	// The immediate-default reading already preserves the option's original
	// binding. A plain allow naming that parent covers every possible child;
	// Unknown still prevents an option/operand-constrained allow from using this
	// alternative. Unknowns above the named command retain UnknownBefore.
	if !s.located() && !(s.explicitOptions && s.lv.Default != "") {
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
	lv := nz.options(s)
	if lv.Syntax.TrimOptionDashes {
		name = strings.TrimLeft(name, "-")
	}
	if lv.Syntax.Underscores && strings.Contains(name, "_") {
		// node reads the name with `_` as `-` before it looks for the option or its negation (Syntax.Underscores).
		name = strings.ReplaceAll(name, "_", "-")
		raw = raw[:len(raw)-len(name)] + name
	}
	o := lv.long(name)
	if o == nil {
		o = noptShort(lv, name)
	}
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

// argparseKnownOption checks the lookups that precede _parse_optional's space
// fallback (CPython 3.13). An ambiguous prefix rejects too, before any command
// dispatch. Respect the current option boundary, including ended AWS globals.
func argparseKnownOption(lv *Level, word string) bool {
	name, _, _ := strings.Cut(word, "=")
	if strings.HasPrefix(name, "--") {
		name = name[2:]
		for l := lv; l != nil; l = l.parent {
			for _, o := range l.Opts {
				if l != lv && !o.Persistent {
					continue
				}
				for _, n := range o.Long {
					if strings.HasPrefix(n, name) {
						return true
					}
				}
			}
		}
		return false
	}
	return len(word) > 1 && lv.shortOpt(word[1]) != nil
}

// separate records a known option written without an attached value, taking the next token as its value as the
// option's kind says, and returns the fork of an ArgMaybe option's other reading.
func (nz *Normalizer) separate(s *parseState, toks []string, h Hit) (parseState, bool) {
	o := h.Opt
	next, has := "", s.i < len(toks)
	if has {
		next = toks[s.i]
	} else if o.Arg != ArgNone && o.Arg != ArgOptional {
		// The next token, past the end of a prefix, may be this option's value: python's `-m` cut there runs a module
		// no token names yet (Reading.Pending).
		s.wants = true
	}
	switch o.Arg {
	case ArgRequired:
		if has {
			mode := NextOptionValue
			argparseSpace := false
			if s.lv != nil && optionLooking(next, s.lv.Syntax.PlusOptions) {
				mode = s.lv.Syntax.NextOption
				if o.NextOption != NextOptionDefault {
					mode = o.NextOption
				}
				if mode == NextOptionNopt && !noptOption(next) {
					mode = NextOptionValue
				}
				if mode == NextOptionArgparse && strings.Contains(next, " ") {
					argparseSpace = true
					if !argparseKnownOption(nz.options(s), next) {
						// The row is not the complete argparse vocabulary. A name
						// absent here may still precede argparse's space fallback.
						mode = NextOptionBoth
					}
				}
				if mode == NextOptionNoptValue && strings.Trim(next, "-") != "" {
					mode = NextOptionValue
				}
			}
			if mode == NextOptionDefault || mode == NextOptionBoth || mode == NextOptionArgparse && len(next) > 1 && (next[1] >= '0' && next[1] <= '9' || next[1] == '.') {
				f := s.fork()
				f.terminatorPending = true
				if argparseSpace {
					f.r.Unlocatable = true
				}
				nz.hit(&f, h)
				h.Value, h.HasValue = next, true
				s.i++
				nz.hit(s, h)
				return f, true
			}
			if mode != NextOptionValue {
				s.terminatorPending = true
				if mode == NextOptionArgparse {
					// _match_argument rejects a required value when the next
					// token is another option. Do not invent successful dispatch
					// after that parser error or erase an older refusal.
					s.r.Unlocatable = true
				}
				break
			}
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
		if o.NextOption == NextOptionNoptMaybe && has && optionLooking(next, false) {
			// nopt's Boolean/String union returns before its generic all-dash
			// guard. The String arm consumes everything except /^-[^-]/.
			if len(next) < 2 || next[0] != '-' || next[1] == '-' {
				h.Value, h.HasValue = next, true
				s.i++
			}
			nz.hit(s, h)
			return parseState{}, false
		}
		nz.hit(s, h)
		if !has {
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

func optionLooking(tok string, plus bool) bool {
	return len(tok) > 1 && (tok[0] == '-' || plus && tok[0] == '+')
}

// nopt's exact String guard is /^-{1,2}[^-]+/ or an all-dash marker.
// Three dashes followed by a name are a value, unlike --name and -name.
func noptOption(tok string) bool {
	if len(tok) < 2 || tok[0] != '-' {
		return false
	}
	if strings.Trim(tok, "-") == "" || tok[1] != '-' {
		return true
	}
	return len(tok) > 2 && tok[2] != '-'
}

// short parses a single-dash token at s.i (a cluster where the level clusters) and advances past it.
func (nz *Normalizer) short(s *parseState, toks []string, tok string, forks *[]parseState) (parseState, bool) {
	lv := nz.options(s)
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
			if before {
				// Consuming the rest as a value can prevent a later letter from consuming
				// the next word. That word can then select a different subcommand.
				f := s.fork()
				f.r.Hits[len(f.r.Hits)-1].Value, f.r.Hits[len(f.r.Hits)-1].HasValue = tok[j+1:], true
				*forks = append(*forks, f)
				if len(*forks) >= MaxReadings {
					// Bound work within one arbitrarily long cluster too, before another copy.
					s.i = len(toks)
					return parseState{}, false
				}
			}
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
		if j > 1 && !s.located() && !lv.Syntax.BundleValuesSettle && s.i < len(toks) {
			// Cobra's command search can extract the next token before pflag
			// takes this letter's value, rebinding later flags and nested commands.
			// Until that separate scanner is fully modeled, keep an unresolved
			// alternative as well as the ordinary option-parser reading.
			f := s.fork()
			f.r.Unlocatable = true
			*forks = append(*forks, f)
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
