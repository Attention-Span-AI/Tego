// SPDX-License-Identifier: Apache-2.0

package execmatch

import (
	"sort"
	"strings"
)

// optSpelling is an option word as compile prints it: its long name (or letter) and its value glob.
func (po *PatOpt) optSpelling() string {
	s := po.Raw
	if po.Opt != nil {
		switch {
		case len(po.Opt.Long) > 0:
			s = "--" + po.Opt.Long[0]
			if po.Neg {
				s = "--no-" + po.Opt.Long[0]
			}
		case po.Opt.Short != "":
			s = "-" + po.Opt.Short[:1]
		}
	}
	if po.HasValue {
		s += "=" + po.Value
	}
	return s
}

// Reading is the pattern's exact reading, as compile prints it on the entry's line (ADR 0048 (9)): "subcommand push;
// any options and operands", "subcommand log; requires --oneline; every other option free".
func (p *Pattern) Reading() string {
	if p.Runtime != "" {
		return "runtime grant: argv is exactly " + strings.Join(append([]string{p.Argv0}, p.Words...), " ") + ", every element and no other"
	}
	if p.Bare {
		if p.List == ListAllow {
			return "any arguments"
		}
		return "every invocation"
	}
	deny := p.List != ListAllow
	if p.Row == nil {
		if deny {
			return "generic: " + strings.Join(p.genWords, " ") + " as an ordered subsequence before --, options " + strings.Join(p.genOpts, " ") + " anywhere"
		}
		s := "generic: argv starts " + strings.Join(p.Words, " ")
		if p.Rest {
			s += " *"
		}
		return s
	}
	var parts []string
	switch {
	case len(p.Path) > 0:
		parts = append(parts, "subcommand "+strings.Join(p.Path, " "))
	case p.Row.Root != nil && (p.Row.Root.Subs != nil || p.Row.Root.Wild != nil):
		parts = append(parts, "any subcommand")
	}
	var opts []string
	for i := range p.Opts {
		opts = append(opts, p.Opts[i].optSpelling())
	}
	switch {
	case len(opts) > 0 && deny:
		parts = append(parts, "with "+strings.Join(opts, " ")+" anywhere the tool reads them")
	case len(opts) > 0:
		parts = append(parts, "requires "+strings.Join(opts, " "))
	}
	switch {
	case len(p.Operands) > 0 && deny:
		parts = append(parts, "operands holding "+strings.Join(p.Operands, " ")+" in order")
	case len(p.Operands) > 0 && p.Rest:
		parts = append(parts, "operands start "+strings.Join(p.Operands, " "))
	case len(p.Operands) > 0:
		parts = append(parts, "operands exactly "+strings.Join(p.Operands, " "))
	}
	switch {
	case len(opts) == 0 && len(p.Operands) == 0:
		parts = append(parts, "any options and operands")
	case !deny:
		parts = append(parts, "every other option free")
	}
	return strings.Join(parts, "; ")
}

// Canonical is the pattern's spelling with every option by its canonical name, sorted: `rm -fr` and `rm -r -f` are
// both "rm --force --recursive". Coverage notes are looked up by it.
func (p *Pattern) Canonical() string {
	if p.Row == nil {
		return strings.TrimSpace(p.Tool + " " + strings.Join(p.Words, " "))
	}
	words := append([]string{p.Tool}, p.Path...)
	var opts []string
	for i := range p.Opts {
		opts = append(opts, p.Opts[i].optSpelling())
	}
	sort.Strings(opts)
	words = append(words, opts...)
	words = append(words, p.Operands...)
	if p.Rest {
		words = append(words, "*")
	}
	return strings.Join(words, " ")
}

// Coverage is the row's coverage note for the pattern, "" when the row has none.
func (p *Pattern) Coverage(rows *Rows) string {
	if p.Row == nil {
		return ""
	}
	want := p.Canonical()
	for k, note := range p.Row.Coverage {
		q, err := Parse(k, p.List, rows)
		if err == nil && q.Canonical() == want {
			return note
		}
	}
	return ""
}

// NearMisses are tokens the pattern also matches that its text does not show (ADR 0048 (9)): for a git pattern, the
// first-word spellings git autocorrects to its subcommand; for a row whose subcommands take unique prefixes (npm),
// the prefixes that name it. kind says which; at most max tokens, the closest first.
func (p *Pattern) NearMisses(cand *Candidates, max int) (kind string, toks []string) {
	if p.Row == nil || len(p.Path) == 0 {
		return "", nil
	}
	sub := p.Path[0]
	switch {
	case p.Row.Autocorrect && p.List != ListAllow:
		// An allow entry admits no autocorrected spelling: the token's own reading is another subcommand.
		if cand == nil {
			cand = NewCandidates(p.Row.Builtins, p.Row.Common)
		}
		seen := map[string]bool{}
		for _, t := range editsOf(sub) {
			if len(toks) >= max || seen[t] || cand.Has(t) {
				continue
			}
			seen[t] = true
			if got, ok := Autocorrect(t, cand); ok && got == sub {
				toks = append(toks, t)
			}
		}
		return "autocorrect", toks
	case p.Row.Root != nil && p.Row.Root.SubPrefix:
		for i := len(sub) - 1; i >= 1 && len(toks) < max; i-- {
			var buf [8]string
			c := p.Row.Root.prefixes(buf[:0], sub[:i])
			for _, n := range c {
				if path, _, ok := p.Row.Root.sub(n); ok && len(path) > 0 && path[0] == sub {
					toks = append(toks, sub[:i])
					break
				}
			}
		}
		return "prefix", toks
	}
	return "", nil
}

// editsOf are a word's single edits, in the order a reader would find them likeliest: deletions, adjacent swaps, a
// capitalised first letter, then substitutions and insertions of lowercase letters.
func editsOf(w string) []string {
	var out []string
	for i := 0; i < len(w); i++ {
		out = append(out, w[:i]+w[i+1:])
	}
	for i := 0; i+1 < len(w); i++ {
		out = append(out, w[:i]+string(w[i+1])+string(w[i])+w[i+2:])
	}
	if w != "" && w[0] >= 'a' && w[0] <= 'z' {
		out = append(out, string(w[0]-'a'+'A')+w[1:])
	}
	for i := 0; i < len(w); i++ {
		for c := byte('a'); c <= 'z'; c++ {
			if c != w[i] {
				out = append(out, w[:i]+string(c)+w[i+1:])
			}
		}
	}
	for i := 0; i <= len(w); i++ {
		for c := byte('a'); c <= 'z'; c++ {
			out = append(out, w[:i]+string(c)+w[i:])
		}
	}
	return out
}
