// SPDX-License-Identifier: Apache-2.0

package conformance

import (
	"path"
	"strings"
)

// commandDenied is the command-rule invariant (ADR 0048 (1), ADR 0017 (c)): no exec runs a program an exec.deny
// entry names with the words the entry names (P1 refuses an exec.ask match as well; Model.ExecDeny holds both). It
// reads those entries and the cell alone, never the matcher (pkg/policy/execmatch) or the decision core: an
// over-approximation that knows no row, so it is held only to a fixture's own cells, written so that no allowed cell
// carries a denied entry's words.
//
// The program is the cell's Runs (a #! interpreter as its walk resolves it) or else the image it names, by its
// basename. Its arguments are what the kernel hands it: for a script, binfmt_script's [arg?, script, argv[1:]...];
// else argv[1:]. A program named <tool>-<sub> (git's dashed form) runs <sub> first. An entry's command word must be
// the program's name; each further word must be present: a short option word (-r) by each of its letters in some
// short-option token, a long one (--force) as a token or its --opt=value form, and any other word as a token. An
// option word is present by any of its spellings in sameOption.
//
// An allow list with words (Model.ExecAllowCommands, ADR 0048 (1)-(3)) constrains its tool: a program an entry's
// command word names runs only as some such entry names it, by the same reading, so a constrained tool's unlisted
// invocation is a violation too. A program no entry names is not held here (the image rules decide it).
func commandDenied(m Model, c *Cell) string {
	if (c.Op != OpExec && c.Op != OpRaceArgvExec) || len(c.Argv) == 0 || len(m.ExecDeny)+len(m.ExecAllowCommands) == 0 {
		return ""
	}
	prog := path.Base(c.canon())
	var args []string
	if c.Runs != "" {
		prog = path.Base(c.Runs)
	}
	if c.Script != "" {
		if c.ScriptArg != "" {
			args = append(args, c.ScriptArg)
		}
		args = append(args, c.Path)
	}
	args = append(args, c.Argv[1:]...)
	for _, e := range m.ExecDeny {
		if _, all := entryNames(prog, args, e); all {
			return "an exec an exec.deny entry names ran (" + e + ")"
		}
	}
	constrained, admitted := false, false
	for _, e := range m.ExecAllowCommands {
		tool, all := entryNames(prog, args, e)
		constrained, admitted = constrained || tool, admitted || all
	}
	if constrained && !admitted {
		return "a constrained tool ran as no exec.allow entry with words names it"
	}
	return ""
}

// entryNames reads one command entry against an exec's program and arguments (commandDenied): tool says the entry's
// command word is the program, all that each of its further words is present as well.
func entryNames(prog string, args []string, entry string) (tool, all bool) {
	words := strings.Fields(entry)
	if len(words) == 0 {
		return false, false
	}
	name, toks := prog, args
	if t, sub, ok := strings.Cut(prog, "-"); ok && t == words[0] && sub != "" {
		name, toks = t, append([]string{sub}, args...)
	}
	if name != words[0] {
		return false, false
	}
	for _, w := range words[1:] {
		found := hasWord(toks, w)
		for _, alt := range sameOption[name+" "+w] {
			found = found || hasWord(toks, alt)
		}
		if !found {
			return true, false
		}
	}
	return true, true
}

// sameOption lists the other spellings of an option word a fixture's deny entry names, from the tool's own manual
// (GNU coreutils' rm(1): -r, -R and --recursive are one option), keyed "<tool> <word>".
var sameOption = map[string][]string{
	"rm -r": {"-R", "--recursive"},
}

// hasWord reports whether a deny entry's word is present among an exec's arguments (commandDenied).
func hasWord(toks []string, w string) bool {
	short := len(w) > 1 && w[0] == '-' && w[1] != '-'
	for _, letter := range w {
		if !short {
			break
		}
		if letter == '-' {
			continue
		}
		found := false
		for _, t := range toks {
			if len(t) > 1 && t[0] == '-' && t[1] != '-' && strings.ContainsRune(t[1:], letter) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if short {
		return true
	}
	for _, t := range toks {
		if t == w || (strings.HasPrefix(w, "--") && strings.HasPrefix(t, w+"=")) {
			return true
		}
	}
	return false
}
