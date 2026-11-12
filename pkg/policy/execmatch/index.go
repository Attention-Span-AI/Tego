// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"sort"
	"strings"
)

// toolRules are the patterns of one tool.
type toolRules struct {
	deny, ask, allow []*Pattern
	// constrained: some allow entry names the tool with words, and no bare name entry or implicit grant lifts it.
	constrained bool
	// closure maps each constraining allow pattern to the subcommand paths its helper closure admits.
	closure map[*Pattern][][]string
	// grant is the first runtime grant's pattern (ExactPattern) of a tool no contract allow entry constrains: an
	// unlisted invocation of it is refused under that grant's rule, which is the one that constrains it.
	grant *Pattern
}

// IndexOptions are what compile adds to the patterns.
type IndexOptions struct {
	// Candidates is git's autocorrect candidate set (the exec-path listing, else the row's built-ins); nil for the
	// row's own list.
	Candidates *Candidates
	// Identities maps the (dev, ino) of a ruled command's resolved file of one link to its tool (interpretation 2).
	Identities map[ID]string
	// Loaders are the (dev, ino) of the host's dynamic loaders (ADR 0048 (3)): a hard link to one
	// under another name is a loader by its identity, as a symlink to one is by the walked file's name.
	Loaders map[ID]bool
	// Unconstrained are tools an implicit grant names (the contract's command, an MCP server's, a #! interpreter of
	// either, the run command): they keep "any arguments" whatever allow entries say.
	Unconstrained map[string]bool
}

// Index is the compiled command rules of one contract: patterns indexed by tool (ADR 0048 (4)). Built once,
// immutable, read concurrently.
type Index struct {
	rows  *Rows
	tools map[string]*toolRules
	ids   map[ID]string
	lds   map[ID]bool
	nz    map[*Row]*Normalizer
	order []*Pattern
}

// NewIndex builds an index over patterns, in the order the contract lists them. A bare allow entry naming the tool by
// name lifts its constraint; one naming a path does not.
func NewIndex(rows *Rows, patterns []*Pattern, opts IndexOptions) *Index {
	ix := &Index{rows: rows, tools: map[string]*toolRules{}, ids: opts.Identities, lds: opts.Loaders, nz: map[*Row]*Normalizer{}, order: patterns}
	lifted := map[string]bool{}
	for t := range opts.Unconstrained {
		lifted[t] = true
	}
	for _, p := range patterns {
		tr := ix.tools[p.Tool]
		if tr == nil {
			tr = &toolRules{}
			ix.tools[p.Tool] = tr
		}
		switch p.List {
		case ListDeny:
			tr.deny = append(tr.deny, p)
		case ListAsk:
			tr.ask = append(tr.ask, p)
		case ListAllow:
			if p.Bare {
				if !strings.Contains(p.Command, "/") {
					lifted[p.Tool] = true
				}
				continue
			}
			tr.allow = append(tr.allow, p)
		}
	}
	for tool, tr := range ix.tools {
		tr.constrained = len(tr.allow) > 0 && !lifted[tool]
		if !tr.constrained {
			continue
		}
		tr.grant = runtimeOnly(tr.allow)
		tr.closure = map[*Pattern][][]string{}
		for _, p := range tr.allow {
			if p.Row == nil || len(p.Path) == 0 {
				continue
			}
			var paths [][]string
			for e := range Closure(p.Row, p.Path[0]) {
				paths = append(paths, strings.Fields(e))
			}
			sort.Slice(paths, func(i, j int) bool { return strings.Join(paths[i], " ") < strings.Join(paths[j], " ") })
			tr.closure[p] = paths
		}
	}
	for _, r := range rows.All() {
		if r.Interp != nil {
			ix.nz[r] = NewNormalizer(r, nil)
		}
		if _, ok := ix.tools[r.Tool]; ok {
			ix.nz[r] = NewNormalizer(r, opts.Candidates)
		}
	}
	return ix
}

// runtimeOnly is the first of allow when every pattern in it is a runtime grant's (ExactPattern), nil otherwise.
func runtimeOnly(allow []*Pattern) *Pattern {
	for _, p := range allow {
		if p.Runtime == "" {
			return nil
		}
	}
	return allow[0]
}

// Closure is the transitive helper closure of a subcommand: the subcommand paths and dashed helpers the tool runs for
// itself (ADR 0048 (2)), each written as its words ("worktree prune"), the subcommand itself excluded. A helper's own
// closure is taken by its first word.
func Closure(row *Row, sub string) map[string]bool {
	out := map[string]bool{}
	var walk func(string)
	walk = func(s string) {
		for _, h := range row.Closure[s] {
			if !out[h] {
				out[h] = true
				first, _, _ := strings.Cut(h, " ")
				walk(first)
			}
		}
	}
	walk(sub)
	delete(out, sub)
	return out
}

// inClosure reports whether a reading's subcommand path starts with one of a closure's paths.
func inClosure(paths [][]string, r *Reading) bool {
	for _, p := range paths {
		if len(r.Path) < len(p) {
			continue
		}
		ok := true
		for i, w := range p {
			if r.Path[i] != w {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	return false
}

// normalizer is the row's normalizer; a row the index holds no rule for gets one on the fly.
func (ix *Index) normalizer(r *Row) *Normalizer {
	if nz := ix.nz[r]; nz != nil {
		return nz
	}
	return NewNormalizer(r, nil)
}

// Rows is the row set the index was built with.
func (ix *Index) Rows() *Rows { return ix.rows }

// Patterns lists the index's patterns in contract order.
func (ix *Index) Patterns() []*Pattern { return ix.order }

// Empty reports whether the index holds no command rule.
func (ix *Index) Empty() bool { return ix == nil || len(ix.tools) == 0 }

// Ruled reports whether some pattern names the tool.
func (ix *Index) Ruled(tool string) bool {
	if ix == nil {
		return false
	}
	_, ok := ix.tools[tool]
	return ok
}

// Constrained reports whether the tool is constrained by allow entries.
func (ix *Index) Constrained(tool string) bool {
	if ix == nil {
		return false
	}
	tr := ix.tools[tool]
	return tr != nil && tr.constrained
}

// ConstrainedTools lists the constrained tools, sorted.
func (ix *Index) ConstrainedTools() []string {
	var out []string
	if ix == nil {
		return nil
	}
	for t, tr := range ix.tools {
		if tr.constrained {
			out = append(out, t)
		}
	}
	sort.Strings(out)
	return out
}

// Guarded reports, from an exec's names and identity alone (no argv beyond argv[0]), whether a command rule could
// apply to it: some interpretation's tool is ruled, or a multicall binary or interpreter could dispatch to one, or a
// script's #! chain reaches a ruled tool. An image whose form is unknown is guarded: any ruled tool can be a #!
// interpreter, and its header was not read. An exec that is not guarded needs no more argv (ADR 0048 (3)).
func (ix *Index) Guarded(f *Facts) bool {
	if ix.Empty() {
		return false
	}
	names := [...]string{base(f.Requested), base(f.Image), base(f.Argv0), undashed(base(f.Argv0))}
	for _, n := range names {
		if n == "" {
			continue
		}
		if ix.nameGuarded(n) {
			return true
		}
	}
	if f.HasID {
		if _, ok := ix.ids[f.ID]; ok {
			return true
		}
	}
	if f.Form == FormScript {
		for _, st := range f.Interp {
			// A stage is read by its #! path, by the walked interpreter's name and by its identity: an interpreter
			// reached through a symlink is the file the link names.
			if ix.nameGuarded(base(st.Path)) || (st.Image != "" && ix.nameGuarded(st.Image)) {
				return true
			}
			if st.HasID {
				if _, ok := ix.ids[st.ID]; ok {
					return true
				}
			}
		}
	}
	if f.Loaded != nil {
		lf := f.loadedFacts()
		if ix.Guarded(&lf) {
			return true
		}
	}
	return f.Form == FormUnknown
}

// nameGuarded reports whether one name leads to a ruled tool, or to a dispatcher that could reach one.
func (ix *Index) nameGuarded(n string) bool {
	if ix.Ruled(n) {
		return true
	}
	if r := ix.rows.Lookup(n); r != nil {
		if ix.Ruled(r.Tool) || r.Multicall || r.Interp != nil {
			return true
		}
	}
	if ix.rows.dispatcherNamed(n) != nil {
		return true
	}
	if r, _, ok := ix.argv0Sub(n); ok && ix.Ruled(r.Tool) {
		return true
	}
	if i := strings.IndexByte(n, '-'); i > 0 {
		if r := ix.rows.Lookup(n[:i]); r != nil && r.Dashed && ix.Ruled(r.Tool) {
			return true
		}
	}
	return false
}

// Outcome is what the command rules decided.
type Outcome uint8

// Outcomes.
const (
	// OutcomeNone: no command rule applies; the image floor's verdict stands.
	OutcomeNone Outcome = iota
	// OutcomeAllowed: a constrained tool's allow entry (or its helper closure) admitted the exec.
	OutcomeAllowed
	// OutcomeRefused: a deny or ask entry matched, or a constrained tool's invocation is unlisted.
	OutcomeRefused
)

// String is the outcome's name.
func (o Outcome) String() string {
	switch o {
	case OutcomeNone:
		return "none"
	case OutcomeAllowed:
		return "allowed"
	case OutcomeRefused:
		return "refused"
	}
	return "unknown"
}

// Result is a command-rule decision (ADR 0048 (4)).
type Result struct {
	Outcome Outcome
	// Pattern is the entry that decided; nil for an unlisted refusal and for OutcomeNone.
	Pattern *Pattern
	// List is the deciding list; Unlisted marks a refusal of a constrained tool's unlisted invocation.
	List     List
	Unlisted bool
	// Overflow marks a fail-closed refusal: the matcher could not resolve a dispatcher's dispatch within the depth
	// or interpretation bounds, so the exec could still reach a ruled tool (ADR 0048 (2)). The
	// rule is command-unresolved and command_via is overflow.
	Overflow bool
	// Tool, Via and Match describe the interpretation that decided.
	Tool  string
	Via   Via
	Match Match
	// ClosureOf is the allowed entry whose helper closure admitted the exec.
	ClosureOf *Pattern
	// Grant is, on an unlisted refusal, the runtime grant that alone constrains the tool (ExactPattern): the refusal
	// carries its rule.
	Grant *Pattern
	// Guarded reports whether any interpretation's tool is ruled.
	Guarded bool
	// Final reports whether the decision cannot change with argv past what was read; always true for complete argv.
	Final bool
	// K is the number of argv elements the decision read.
	K int
}

// Rule is the decision's rule name in the ledger: exec.deny[git push], exec.ask[npm install], exec.args[git] for an
// unlisted invocation of a constrained tool (the runtime grant's exec.<kind>[<argv[0]>] when only it constrains the
// tool), exec.allow[git status] for an admitting entry; "" when no rule applies.
func (r Result) Rule() string {
	switch {
	case r.Overflow:
		return RuleCommandUnresolved
	case r.Unlisted && r.Grant != nil:
		return r.Grant.Rule()
	case r.Unlisted:
		return "exec.args[" + r.Tool + "]"
	case r.Pattern != nil:
		return r.Pattern.Rule()
	case r.ClosureOf != nil:
		return r.ClosureOf.Rule()
	}
	return ""
}

// RuleCommandUnresolved is the ledger rule of a fail-closed exec refusal where the matcher could not resolve a
// dispatcher's dispatch within the bounds (ADR 0048 (2)): reason exec-not-allowed, like
// args-unreadable, a sentinel the closed reason set needs no code for.
const RuleCommandUnresolved = "command-unresolved"

// ListName is the record's command_list: deny, ask, allow or unlisted.
func (r Result) ListName() string {
	if r.Unlisted {
		return "unlisted"
	}
	if r.Pattern == nil && r.ClosureOf == nil {
		return ""
	}
	return r.List.String()
}

// MatchName is the record's command_match: definite or ambiguous for an entry that matched, and empty, never
// written, for an unlisted refusal, which no entry matched.
func (r Result) MatchName() string {
	if r.Match == MatchNone {
		return ""
	}
	return r.Match.String()
}

// Decide applies the command rules to an exec's facts (ADR 0048 (1) precedence, step 2): any deny match refuses,
// else any ask match refuses as a reserved ask, else a constrained tool's invocation that no allow entry matches
// definitely and no allowed entry's helper closure admits is refused as unlisted, else the exec is allowed (by an
// entry, when a constrained tool's entry admitted it). The image floor decides before, and the gate after.
func (ix *Index) Decide(f *Facts) Result {
	res := Result{K: len(f.Argv), Final: true}
	if ix.Empty() || !ix.Guarded(f) {
		// No name, identity or #! stage leads to a ruled tool or a dispatcher that could reach one: an index lookup
		// per name, and nothing to normalize (ADR 0048 C8).
		return res
	}
	invs := ix.Interpretations(f)
	overflow := false
	for i := range invs {
		switch {
		case invs[i].Via == ViaOverflow:
			overflow = true
		case ix.Ruled(invs[i].Tool):
			res.Guarded = true
		}
	}
	// A concrete deny or ask match names its entry, whether or not the dispatch overflowed.
	if res.Guarded {
		for _, list := range [...]List{ListDeny, ListAsk} {
			if r, ok := ix.firstMatch(invs, list); ok {
				r.Guarded, r.Final, r.K = true, true, len(f.Argv)
				return r
			}
		}
	}
	// A dispatcher the bounds left unresolved could still reach any ruled tool, so the exec is refused before any
	// allow or unmatched verdict (ADR 0048 (2)): fail closed, command-unresolved, via overflow.
	if overflow {
		return Result{Outcome: OutcomeRefused, Overflow: true, Via: ViaOverflow, Guarded: true, Final: true, K: len(f.Argv)}
	}
	if !res.Guarded {
		res.Final = f.ArgvComplete || ix.dispatchSettled(invs)
		return res
	}
	var allowed *Result
	for i := range invs {
		inv := &invs[i]
		tr := ix.tools[inv.Tool]
		if tr == nil || !tr.constrained {
			continue
		}
		r, ok := ix.allowedBy(tr, inv)
		if !ok {
			out := Result{Outcome: OutcomeRefused, Unlisted: true, List: ListAllow, Tool: inv.Tool, Via: inv.Via, Guarded: true, K: len(f.Argv), Grant: tr.grant}
			out.Final = f.ArgvComplete || ix.settled(invs, nil)
			return out
		}
		if allowed == nil {
			allowed = &r
		}
	}
	if allowed != nil {
		allowed.Guarded, allowed.K = true, len(f.Argv)
		allowed.Final = f.ArgvComplete || ix.settled(invs, allowed)
		return *allowed
	}
	res.Final = f.ArgvComplete || ix.settled(invs, nil)
	return res
}

// firstMatch is the first entry of list matching some interpretation: a definite match before an ambiguous one, then
// interpretation order, then contract order.
func (ix *Index) firstMatch(invs []Invocation, list List) (Result, bool) {
	var amb *Result
	for i := range invs {
		inv := &invs[i]
		tr := ix.tools[inv.Tool]
		if tr == nil {
			continue
		}
		ps := tr.deny
		if list == ListAsk {
			ps = tr.ask
		}
		for _, p := range ps {
			switch m := p.Match(inv); m {
			case MatchDefinite:
				return Result{Outcome: OutcomeRefused, Pattern: p, List: list, Tool: inv.Tool, Via: inv.Via, Match: m}, true
			case MatchAmbiguous:
				if amb == nil {
					amb = &Result{Outcome: OutcomeRefused, Pattern: p, List: list, Tool: inv.Tool, Via: inv.Via, Match: m}
				}
			case MatchNone:
			}
		}
	}
	if amb != nil {
		return *amb, true
	}
	return Result{}, false
}

// allowedBy finds the allow entry, or the helper closure of one, that admits a constrained tool's invocation.
func (ix *Index) allowedBy(tr *toolRules, inv *Invocation) (Result, bool) {
	for _, p := range tr.allow {
		if p.Match(inv) == MatchDefinite {
			return Result{Outcome: OutcomeAllowed, Pattern: p, List: ListAllow, Tool: inv.Tool, Via: inv.Via, Match: MatchDefinite}, true
		}
	}
	if len(inv.Readings) == 0 {
		return Result{}, false
	}
	for _, p := range tr.allow {
		set := tr.closure[p]
		if len(set) == 0 {
			continue
		}
		all := true
		for i := range inv.Readings {
			r := &inv.Readings[i]
			if r.Unlocatable || r.UnknownBefore || !inClosure(set, r) {
				all = false
				break
			}
		}
		if all {
			return Result{Outcome: OutcomeAllowed, ClosureOf: p, List: ListAllow, Tool: inv.Tool, Via: ViaClosure, Match: MatchDefinite}, true
		}
	}
	return Result{}, false
}

// dispatchSettled reports whether no interpretation could still dispatch to another tool with more argv: every
// multicall invocation has its applet and every interpreter invocation its module, script or code.
func (ix *Index) dispatchSettled(invs []Invocation) bool {
	for i := range invs {
		inv := &invs[i]
		if inv.Row == nil {
			continue
		}
		if inv.Row.Multicall && len(inv.Tokens) == 0 {
			return false
		}
		if inv.Row.Interp != nil && !ix.interpSettled(inv) {
			return false
		}
	}
	return true
}

// interpSettled reports whether an interpreter invocation's every reading found its module, script or code, as
// dispatchInterp reads code (InterpSpec.runsCode): a prefix that ends at node's -p or -e has not read whether code
// follows. Code with no script yet settles nothing on a row with CodeUnless options, which may still follow it (node
// reads -i after -e's code, and then runs the script). A pending reading settles nothing either (Reading.Pending): a
// prefix cut at python's -m has not read the module, and sh's -c read before its code still reads options, which can
// fork the readings past MaxReadings, so that the whole vector is unresolved and refused.
func (ix *Index) interpSettled(inv *Invocation) bool {
	spec := inv.Row.Interp
	if inv.Open && spec.ArgvRewrite != nil {
		return false // a later token can load code even after the entry script
	}
	for _, r := range ix.normalizer(inv.Row).NormalizeOpen(inv.Tokens, inv.Open) {
		if r.Unlocatable || r.Pending {
			return false
		}
		if r.Dispatch >= 0 || r.DispatchAfter >= 0 {
			continue
		}
		if len(spec.CodeUnless) > 0 || !spec.runsCode(&r) {
			return false
		}
	}
	return true
}

// settled reports whether a decision made on an argv prefix cannot change with more of it (ADR 0048 (3), staged
// reads): dispatch is settled, every ruled reading has located its subcommand path and is not pending (Reading.Pending:
// cargo's --config after the subcommand can still make it unlocatable), no deny or ask entry whose path
// it matches names options or operands that later tokens could supply, and the admitting allow entry (if any) names
// no options or operands. A generic tool's deny entries can always still match later tokens, and its allow entries
// are settled once their words are read.
func (ix *Index) settled(invs []Invocation, allowed *Result) bool {
	if !ix.dispatchSettled(invs) {
		return false
	}
	if allowed != nil && allowed.Pattern != nil && allowed.Pattern.Row != nil && allowed.Pattern.NamesArgs() {
		return false
	}
	for i := range invs {
		inv := &invs[i]
		tr := ix.tools[inv.Tool]
		if tr == nil {
			continue
		}
		if inv.Row == nil {
			if len(tr.deny)+len(tr.ask) > 0 {
				return false
			}
			for _, p := range tr.allow {
				if len(inv.Tokens) < len(p.Words) {
					return false
				}
			}
			continue
		}
		for j := range inv.Readings {
			r := &inv.Readings[j]
			if r.Unlocatable || !r.Located || r.Pending {
				return false
			}
			for _, ps := range [...][]*Pattern{tr.deny, tr.ask, tr.allow} {
				for _, p := range ps {
					if !p.Bare && p.NamesArgs() && p.pathMatches(r) {
						return false
					}
				}
			}
		}
	}
	return true
}
