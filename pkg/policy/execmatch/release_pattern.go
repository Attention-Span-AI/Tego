// SPDX-License-Identifier: Apache-2.0

package execmatch

import "fmt"

func (p *Pattern) keepReleasePattern(words []string) error {
	q := &Pattern{Entry: p.Entry, List: p.List, Command: p.Command, Tool: p.Tool, Row: p.Row, Rest: p.Rest, genSeparator: -1}
	if p.Row == nil {
		q.Words = append([]string(nil), words...)
		for _, w := range words {
			if isOptionWord(w) {
				q.genOpts = append(q.genOpts, w)
			} else {
				q.genWords = append(q.genWords, w)
			}
		}
	} else if err := q.parseReleaseRow(words); err != nil {
		if p.List == ListAllow {
			return &SyntaxError{Entry: p.Entry, Msg: fmt.Sprintf("retained command reader cannot compile this allow entry: %v", err), Fix: "write the command and option values without --"}
		}
		return nil
	}
	if q.extraDashes && p.List != ListAllow {
		legacy := &Pattern{Entry: p.Entry, List: p.List, Command: p.Command, Tool: p.Tool, Row: p.Row, Rest: p.Rest, legacyDashes: true}
		if err := legacy.parseReleaseRow(words); err == nil {
			q.compat = legacy
		}
	}
	p.released = q
	return nil
}

func (p *Pattern) parseReleaseRow(words []string) error {
	lv := p.Row.Root
	depth := 0
	opsOnly := false
	for i := 0; i < len(words); i++ {
		w := words[i]
		switch {
		case opsOnly || w == "-" || len(w) < 2 || w[0] != '-' && !(w[0] == '+' && lv.Syntax.PlusOptions):
			if !opsOnly && lv.Subs != nil {
				if lv.skip(w) {
					if p.List == ListAllow {
						return &SyntaxError{Entry: p.Entry, Msg: fmt.Sprintf("row %s discards selector %q and cannot enforce it in an allow entry", p.Row.Tool, w), Fix: "remove the selector to admit the operation across variants"}
					}
					continue
				}
				if path, child, ok := lv.sub(w); ok {
					p.Path = append(p.Path, path...)
					if child == nil {
						child = &Level{parent: lv, Syntax: lv.Syntax}
					}
					lv, depth = child, depth+len(path)
					continue
				}
				if lv.Wild != nil {
					p.Path = append(p.Path, w)
					lv, depth = lv.Wild, depth+1
					continue
				}
				// An unknown subcommand word (a plugin, an external command): matched as written, and the level below it
				// reads only the options persistent above it.
				p.Path = append(p.Path, w)
				lv, depth = &Level{parent: lv, Syntax: lv.Syntax}, depth+1
				continue
			}
			p.Operands = append(p.Operands, w)
			if !lv.Syntax.Permute {
				opsOnly = true
			}
		case w == "--":
			opsOnly = true
		default:
			if lv.Subs != nil && lv.Default != "" {
				p.Path = append(p.Path, lv.Default)
				lv, depth = lv.Subs[lv.Default], depth+1
			}
			n, err := p.optionWord(lv, depth, words, i)
			if err != nil {
				return err
			}
			i += n
			if k := len(p.Opts); k > 0 && p.Opts[k-1].Opt != nil && p.Opts[k-1].Opt.ends(p.Opts[k-1].HasValue, p.Opts[k-1].Value) {
				opsOnly = true // the option ends the options, as `--` does (Opt.Ends, Opt.EndsAttached)
			}
		}
	}
	return nil
}
