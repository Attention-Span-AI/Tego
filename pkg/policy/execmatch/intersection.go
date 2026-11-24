// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"slices"
	"sort"
	"strings"
)

// IntersectionKind distinguishes a proof of disjointness, a checked common
// invocation, and a language that this bounded analysis cannot settle.
type IntersectionKind uint8

const (
	// IntersectionUnknown requires refusing a baseline contradiction check: the
	// analysis did not prove that the two languages are disjoint.
	IntersectionUnknown IntersectionKind = iota
	// IntersectionDisjoint proves no intended invocation satisfies both entries
	// in the supplied image context.
	IntersectionDisjoint
	// IntersectionOverlap supplies a common invocation checked by Index.Decide.
	IntersectionOverlap
)

// IntersectionOptions supplies the same vocabulary and identities as the real
// matcher. AllowImage optionally supplies the command grant's resolved image,
// identity and interpreter chain; argv is replaced by each candidate. A nil
// AllowImage means a direct image with the command's canonical names. It does
// not assert that an unresolved filesystem alias has a distinct identity.
type IntersectionOptions struct {
	IndexOptions
	AllowImage *Facts
	// MaxStates bounds the aggregate glob-product states and witness candidates.
	// Zero uses 100,000. Exhaustion produces UNKNOWN, never disjointness.
	MaxStates int
}

// IntersectionResult is a baseline command contradiction check. Witness is set
// only for Overlap and contains no environment or other secret-bearing facts.
type IntersectionResult struct {
	Kind    IntersectionKind
	Witness *Facts
	Reason  string
}

// Intersect conservatively compares one deny and one command allow with the
// actual parser, row normalization, helper closures and image interpretations
// (ADR 0144). Inputs must be parsed by Parse with the supplied rows. Callers
// exclude bare image/directory grants, which are not command exceptions.
//
// This compares the grant's intended invocation language in its resolved image
// context. Arbitrarily inventing unrelated requested names, images or argv[0]
// is not a proof that two distinct tools perform the same action. Known aliases
// belong in AllowImage. Unsupported dispatch or exhausted bounds is UNKNOWN;
// only Disjoint permits compile to continue.
func Intersect(rows *Rows, deny, allow *Pattern, opts IntersectionOptions) IntersectionResult {
	unknown := func(reason string) IntersectionResult {
		return IntersectionResult{Kind: IntersectionUnknown, Reason: reason}
	}
	if rows == nil || deny == nil || allow == nil || deny.List == ListAllow || allow.List != ListAllow {
		return unknown("intersection requires parsed deny and allow entries and their tool rows")
	}
	limit := opts.MaxStates
	if limit == 0 {
		limit = 100000
	}
	s := intersectionSearch{left: limit}
	di := NewIndex(rows, []*Pattern{deny}, opts.IndexOptions)
	// An unrelated implicit grant must not lift this one entry's constraints.
	aiOpts := opts.IndexOptions
	aiOpts.Unconstrained = nil
	ai := NewIndex(rows, []*Pattern{allow}, aiOpts)
	image := Facts{Requested: allow.Command, Image: allow.Command, Argv0: allow.Command, Form: FormDirect}
	if opts.AllowImage != nil {
		image = *opts.AllowImage
		image.Interp = slices.Clone(opts.AllowImage.Interp)
	}
	if image.Argv0 == "" {
		image.Argv0 = allow.Command
	}
	check := func(tokens []string) *Facts {
		if !s.spend() {
			return nil
		}
		f := image
		f.Argv = append([]string{image.Argv0}, tokens...)
		f.ArgvComplete = true
		if LoaderName(f.Requested) || LoaderName(f.Image) || f.HasID && opts.Loaders[f.ID] {
			if i, argv, out := LoaderProgram(f.Argv); out == LoaderRuns {
				f.Loaded = &Loaded{Path: f.Argv[i], Image: base(f.Argv[i]), Argv: argv}
			}
		}
		ar, dr := ai.Decide(&f), di.Decide(&f)
		// Bare entries do not constrain Index; their direct Match still admits
		// all arguments, useful to callers validating generated grants.
		accepted := ar.Outcome == OutcomeAllowed || allow.Bare && ar.Outcome != OutcomeRefused && ai.Guarded(&f)
		if accepted && dr.Pattern == deny {
			return &f
		}
		return nil
	}
	overlap := func(f *Facts) IntersectionResult {
		return IntersectionResult{Kind: IntersectionOverlap, Witness: f, Reason: "the real matcher accepts a common invocation"}
	}

	// Start with the written languages, not joined command strings. The generic
	// deny is a subsequence, so a generic allow prefix may be extended by it.
	aTokens, aok := s.patternTokens(allow)
	dTokens, dok := s.patternTokens(deny)
	for _, tokens := range [][]string{aTokens, dTokens, append(slices.Clone(aTokens), dTokens...)} {
		if f := check(tokens); f != nil {
			return overlap(f)
		}
	}
	if s.exhausted {
		return unknown("command intersection analysis exhausted its state bound")
	}

	// A command rule also admits the transitive helper closure. Each helper has
	// unconstrained options/operands, exactly as Index.allowedBy reads it.
	variants := []*Pattern{allow}
	if allow.Row != nil && len(allow.Path) > 0 && !allow.Bare && allow.Runtime == "" {
		var helpers []string
		for helper := range Closure(allow.Row, allow.Path[0]) {
			helpers = append(helpers, helper)
		}
		sort.Strings(helpers)
		for _, helper := range helpers {
			variants = append(variants, &Pattern{Tool: allow.Tool, Row: allow.Row, Path: strings.Fields(helper), List: ListAllow})
		}
	}
	allDisjoint := true
	for _, variant := range variants {
		proof := s.rowIntersection(deny, variant)
		if !proof.disjoint {
			allDisjoint = false
		}
		if proof.tokens != nil {
			if f := check(proof.tokens); f != nil {
				return overlap(f)
			}
		}
	}
	if s.exhausted {
		return unknown("command intersection analysis exhausted its state bound")
	}
	if !aok || !dok {
		return unknown("a command word constraint could not be interpreted")
	}
	// Every possible known interpretation matters. Non-direct images, loaders,
	// interpreter/multicall dispatch and identity aliases cannot inherit a
	// direct row proof, even when no candidate above exposed the contradiction.
	if image.Form != FormDirect || image.Loaded != nil || LoaderName(image.Requested) || LoaderName(image.Image) || image.HasID && opts.Loaders[image.ID] {
		return unknown("the image can dispatch through a loader or interpreter")
	}
	if allow.Row != nil && (allow.Row.Interp != nil || allow.Row.Multicall) {
		if deny.Tool != allow.Tool && s.fixedDispatchDisjoint(di, allow, &image) {
			return IntersectionResult{Kind: IntersectionDisjoint, Reason: "every fixed operand suffix is disjoint through the complete dispatcher vocabulary"}
		}
		if s.exhausted {
			return unknown("command intersection analysis exhausted its state bound")
		}
		return unknown("the interpreter or multicall invocation language is not proven disjoint")
	}
	for _, inv := range di.Interpretations(&Facts{
		Requested: image.Requested, Image: image.Image, Argv0: image.Argv0, ID: image.ID, HasID: image.HasID,
		Argv: []string{image.Argv0}, ArgvComplete: true,
	}) {
		if inv.Tool == deny.Tool && deny.Tool != allow.Tool {
			return unknown("the resolved command has another denied tool interpretation")
		}
		if inv.Row != nil && (inv.Row.Interp != nil || inv.Row.Multicall) {
			return unknown("the resolved command has a dispatcher interpretation")
		}
	}
	if deny.Tool != allow.Tool {
		return IntersectionResult{Kind: IntersectionDisjoint, Reason: "the resolved direct tools have distinct identities and no known dispatch relation"}
	}
	if allDisjoint {
		return IntersectionResult{Kind: IntersectionDisjoint, Reason: "normalized paths or operand constraints are contradictory, including every helper closure"}
	}
	return unknown("cannot rule out a command-language intersection with the supported interpretations")
}

// A constrained fixed operand vector gives a finite over-approximation of an
// interpreter's dispatched arguments. A module receives all operands; a script
// or preload receives a suffix; a loader receives none. Test every suffix against
// every tool in the real vocabulary, including recursive dispatch and the denied
// generic tool. Extra interpreter option values may select a tool but cannot add
// arguments outside these vectors. No-operand allow patterns are unconstrained,
// so they do not qualify. This also covers fixed multicall applet vectors.
func (s *intersectionSearch) fixedDispatchDisjoint(di *Index, allow *Pattern, image *Facts) bool {
	patterns := []*Pattern{allow}
	if allow.fallback != nil {
		patterns = append(patterns, allow.fallback)
	}
	names := []string{di.order[0].Tool}
	for _, row := range di.rows.All() {
		names = append(names, row.Tool)
	}
	for _, p := range patterns {
		if p.Rest || len(p.Operands) == 0 {
			return false
		}
		for _, word := range p.Operands {
			if strings.ContainsAny(word, "*?[") {
				return false
			}
		}
		for at := 0; at <= len(p.Operands); at++ {
			for _, name := range names {
				if !s.spend() {
					return false
				}
				b := builder{ix: di, argv0: image.Argv0, scanArgv0: image.Argv0, nodeVersion: image.NodeVersion}
				b.add2(di, name, ViaInterpreter, p.Operands[at:])
				invs := di.resolve(&b)
				for _, inv := range invs {
					if inv.Via == ViaOverflow {
						return false
					}
				}
				if _, matched := di.firstMatch(invs, ListDeny); matched {
					return false
				}
			}
		}
	}
	return true
}

type intersectionSearch struct {
	left      int
	exhausted bool
}

func (s *intersectionSearch) spend() bool {
	if s.left <= 0 {
		s.exhausted = true
		return false
	}
	s.left--
	return true
}

type rowIntersection struct {
	disjoint bool
	tokens   []string
}

func (s *intersectionSearch) rowIntersection(d, a *Pattern) rowIntersection {
	if d.Tool != a.Tool || d.Row == nil || a.Row == nil || d.Row != a.Row || a.Runtime != "" {
		return rowIntersection{}
	}
	path := make([]string, max(len(d.Path), len(a.Path)))
	for i := range path {
		dw, aw := "*", "*"
		if i < len(d.Path) {
			dw = d.Path[i]
		}
		if i < len(a.Path) {
			aw = a.Path[i]
		}
		w, ok := s.globIntersection(dw, aw)
		if !ok {
			return rowIntersection{disjoint: !s.exhausted}
		}
		path[i] = w
	}
	ops := slices.Clone(a.Operands)
	if len(ops) == 0 || a.Rest {
		ops = append(ops, d.Operands...)
	} else {
		// Deny operands form a subsequence. Greedy placement is sound for
		// existence: consuming the earliest compatible position leaves the
		// largest suffix for every remaining required operand.
		j := 0
		for i, word := range ops {
			if j < len(d.Operands) {
				w, ok := s.globIntersection(word, d.Operands[j])
				if ok {
					ops[i] = w
					j++
					continue
				}
			}
			w, ok := s.globIntersection(word, "*")
			if !ok {
				return rowIntersection{}
			}
			ops[i] = w
		}
		if j != len(d.Operands) {
			return rowIntersection{disjoint: !s.exhausted}
		}
	}
	for i, word := range ops {
		w, ok := s.globIntersection(word, "*")
		if !ok {
			return rowIntersection{}
		}
		ops[i] = w
	}
	var tokens []string
	for depth := 0; depth <= len(path); depth++ {
		for _, ps := range [][]PatOpt{a.Opts, d.Opts} {
			for _, po := range ps {
				if po.Depth == depth {
					words, ok := s.optionTokens(po)
					if !ok {
						return rowIntersection{}
					}
					tokens = append(tokens, words...)
				}
			}
		}
		if depth < len(path) {
			tokens = append(tokens, path[depth])
		}
	}
	tokens = append(tokens, ops...)
	return rowIntersection{tokens: tokens}
}

func (s *intersectionSearch) patternTokens(p *Pattern) ([]string, bool) {
	if p.Runtime != "" {
		return slices.Clone(p.Words), true
	}
	words, _, err := SplitWords(p.Entry)
	if err != nil || len(words) == 0 {
		return nil, false
	}
	words = slices.Clone(words[1:])
	if p.Rest && len(words) > 0 {
		words = words[:len(words)-1]
	}
	for i, word := range words {
		v, ok := s.globIntersection(word, "*")
		if !ok {
			return nil, false
		}
		words[i] = v
	}
	return words, true
}

func (s *intersectionSearch) optionTokens(po PatOpt) ([]string, bool) {
	if !po.HasValue {
		return []string{po.Raw}, true
	}
	v, ok := s.globIntersection(po.Value, "*")
	if !ok {
		return nil, false
	}
	if po.Opt != nil && (po.Opt.SepOnly || po.Opt.Arg == ArgNextWord || po.Short != 0 && po.Opt.Arg == ArgRequired) {
		return []string{po.Raw, v}, true
	}
	return []string{po.Raw + "=" + v}, true
}

type globAtom struct {
	star  bool
	chars [4]uint64
}

func globAtoms(pattern string) []globAtom {
	var atoms []globAtom
	for i := 0; i < len(pattern); i++ {
		a := globAtom{}
		switch pattern[i] {
		case '*', '?':
			a.star = pattern[i] == '*'
			for c := 1; c < 256; c++ {
				a.chars[c/64] |= uint64(1) << (c % 64)
			}
		case '[':
			_, n := classMatch(pattern[i:], 1)
			if n > 0 {
				for c := 1; c < 256; c++ {
					if ok, _ := classMatch(pattern[i:], byte(c)); ok {
						a.chars[c/64] |= uint64(1) << (c % 64)
					}
				}
				i += n - 1
			} else {
				a.chars['['/64] |= uint64(1) << ('[' % 64)
			}
		default:
			c := pattern[i]
			if c != 0 {
				a.chars[c/64] |= uint64(1) << (c % 64)
			}
		}
		atoms = append(atoms, a)
	}
	return atoms
}

// globIntersection explores the product of the exact byte-glob automata used
// by Glob, including malformed classes. An empty queue proves disjointness;
// the state bound does not. NUL is excluded because exec argv cannot carry it.
func (s *intersectionSearch) globIntersection(p, q string) (string, bool) {
	if !strings.ContainsAny(p, "*?[") {
		return p, Glob(q, p)
	}
	if !strings.ContainsAny(q, "*?[") {
		return q, Glob(p, q)
	}
	a, b := globAtoms(p), globAtoms(q)
	type state struct{ i, j, prev, char int }
	queue := []state{{prev: -1, char: -1}}
	seen := map[[2]int]bool{{}: true}
	add := func(i, j, prev, char int) {
		key := [2]int{i, j}
		if !seen[key] {
			seen[key] = true
			queue = append(queue, state{i, j, prev, char})
		}
	}
	for head := 0; head < len(queue); head++ {
		if !s.spend() {
			return "", false
		}
		x := queue[head]
		if x.i == len(a) && x.j == len(b) {
			var word []byte
			for at := head; at >= 0; at = queue[at].prev {
				if queue[at].char >= 0 {
					word = append(word, byte(queue[at].char))
				}
			}
			slices.Reverse(word)
			return string(word), true
		}
		if x.i < len(a) && a[x.i].star {
			add(x.i+1, x.j, head, -1)
		}
		if x.j < len(b) && b[x.j].star {
			add(x.i, x.j+1, head, -1)
		}
		if x.i == len(a) || x.j == len(b) {
			continue
		}
		if c, ok := globCommonByte(a[x.i], b[x.j]); ok {
			i, j := x.i, x.j
			if !a[i].star {
				i++
			}
			if !b[j].star {
				j++
			}
			add(i, j, head, int(c))
		}
	}
	return "", false
}

func globCommonByte(a, b globAtom) (byte, bool) {
	// Readable witnesses make diagnostics useful; byte semantics still cover
	// all other non-NUL argv bytes when none of these is common.
	for _, c := range []byte("ax0/-. _") {
		if a.chars[c/64]&b.chars[c/64]&(uint64(1)<<(c%64)) != 0 {
			return c, true
		}
	}
	for c := 1; c < 256; c++ {
		if a.chars[c/64]&b.chars[c/64]&(uint64(1)<<(c%64)) != 0 {
			return byte(c), true
		}
	}
	return 0, false
}
