// SPDX-License-Identifier: Apache-2.0

package rules

import (
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/check/rule"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch"
	"github.com/attention-span-ai/tego/pkg/policy/execmatch/rows"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// implicitKey is the key of the contract's view (restOf) that lists the tools the run grants with any arguments by
// itself: the contract's command, each MCP server's command, the #! interpreters of either, and the command given to
// tego run. It is no list of the contract: rule.Entries never has it.
const implicitKey = "exec.implicit"

// The reasons a command entry has no live block (ADR 0171): each is a case the block could not be exact in.
const (
	whyCommandFolder = "a command entry whose program is written with its folder: a live block names the program by its bare name, " +
		"and would refuse other files of that name too"
	whyCommandImplicit = "the run's own command, an MCP server's or a script's interpreter is that program, which a run is granted with " +
		"any arguments whatever the allow entries say, so a live block would refuse more than the new rules do"
	whyCommandRest = "the contract's other entries are not known here, so it cannot be shown that none of them allows part of this command"
	// whyOldWords is a command block asked of a run whose launcher has not made the mark that it reads one
	// (liveblock.TakesWords): an older launcher refuses the whole overlay and ignores every later change, and a block on
	// the whole program would refuse more than the rules the person changed do.
	whyOldWords = "this run was started by an older tego that has no blocks on a command's words; its next run gets the change"
)

// wordsBlockOf is the live block a change to an exec entry that names a command with words has (exec.allow words
// removed, exec.deny words added): the block that refuses what the same text in exec.deny refuses (liveblock.IsWords),
// or why none does. It is offered only where it refuses nothing the new contract allows: the command names its
// program by its bare name, and, for an exec.allow entry removed, no other exec.allow entry of the contract after the
// change (rest) admits the program bare (which lifts the constraint) or may admit a command the block refuses
// (execmatch.Intersect must prove each entry of the same program disjoint from it; a bound it cannot settle counts as a
// common command). Two grants lift the constraint without a bare name: the run's own implicit grants (rest[implicitKey]),
// which keep any arguments whatever the entries say, and a path or folder entry when no entry with words of that program
// is left (compile makes command rules for a program only from its entries with words, so the grant of its image then
// allows every command). A folder entry may hold the program, which nothing here can look into, so it counts as one.
// An exec.deny entry added needs no such check: a deny refuses before any allow entry is read.
func wordsBlockOf(c rule.Change, rest map[string][]string) (liveblock.Kind, string, string) {
	words, _, err := execmatch.SplitWords(c.Entry)
	if err == nil && len(words) > 0 && strings.Contains(words[0], "/") {
		return "", "", whyCommandFolder
	}
	v, err := liveblock.NormalizeWords(c.Entry)
	if err != nil {
		return "", "", "this command cannot be blocked live: " + strings.TrimPrefix(err.Error(), "liveblock: invalid: ")
	}
	deny, err := execmatch.Parse(v, execmatch.ListDeny, rows.Builtin())
	if err != nil {
		return "", "", "this command cannot be blocked live: " + err.Error()
	}
	if !c.Remove {
		// An exec.deny entry added refuses its commands whatever an allow entry says (deny comes first), so the block is
		// exactly what the new contract refuses.
		return liveblock.KindExec, v, ""
	}
	if rest == nil {
		return "", "", whyCommandRest
	}
	if slices.Contains(rest[implicitKey], deny.Tool) {
		return "", "", whyCommandImplicit
	}
	wordsLeft, imageGrant := false, ""
	for _, e := range rest["exec.allow"] {
		if strings.HasSuffix(strings.TrimSpace(e), "/") {
			imageGrant = e // a folder: every program in it, which may be this one
			continue
		}
		allow, err := execmatch.Parse(e, execmatch.ListAllow, rows.Builtin())
		if err != nil {
			return "", "", "another exec.allow entry (" + e + ") could not be read, so it cannot be shown that it allows nothing this block refuses"
		}
		if allow.Tool != deny.Tool {
			continue
		}
		if allow.Bare {
			if strings.Contains(allow.Command, "/") {
				imageGrant = e // a path entry grants the image and constrains nothing while another entry's words decide
				continue
			}
			return "", "", "another exec.allow entry (" + e + ") allows every command of that program"
		}
		wordsLeft = true
		if res := execmatch.Intersect(rows.Builtin(), deny, allow, execmatch.IntersectionOptions{}); res.Kind != execmatch.IntersectionDisjoint {
			return "", "", "another exec.allow entry (" + e + ") may still allow some of the same commands, so a live block would refuse more than the new rules do"
		}
	}
	if !wordsLeft && imageGrant != "" {
		return "", "", "another exec.allow entry (" + imageGrant + ") grants the program by its file or folder, and no entry with words of " +
			"it is left, so the new rules allow every command of it and a live block would refuse more"
	}
	return liveblock.KindExec, v, ""
}

// restOf is the contract text's view blockOf and wordsBlockOf judge by: its entries (entriesOf) and, under implicitKey,
// the tools its own commands run with any arguments (implicitTools). nil when the text does not parse.
func (s *Service) restOf(text []byte, cwd string) map[string][]string {
	m := entriesOf(text)
	if m == nil {
		return nil
	}
	m[implicitKey] = s.implicitTools(text, cwd)
	return m
}

// withRunCommand is rest with the tool of the command tego run was given for a run (run_start's run_command_grant) added
// to its implicit grants; rest itself when the run had none.
func withRunCommand(rest map[string][]string, grant string) map[string][]string {
	if rest == nil || grant == "" {
		return rest
	}
	out := maps.Clone(rest)
	out[implicitKey] = append(slices.Clone(rest[implicitKey]), toolOf(filepath.Base(grant)))
	return out
}

// toolOf is the tool a program's file name is: its row's tool, or the name itself (as compile names it).
func toolOf(name string) string {
	if r := rows.Builtin().Lookup(name); r != nil {
		return r.Tool
	}
	return name
}

// implicitTools is the tools the contract's own commands run, the program of each command (rule.RunCommands) and the
// interpreter a #! line gives a command that is a script (the interpreter, and env's program argument). A command
// that is found nowhere on this machine has only its own name: compile grants what it can read, and so does this.
func (s *Service) implicitTools(text []byte, cwd string) []string {
	cmds, err := rule.RunCommands(text)
	if err != nil {
		return nil
	}
	var out []string
	add := func(name string) {
		if t := toolOf(filepath.Base(name)); !slices.Contains(out, t) {
			out = append(out, t)
		}
	}
	for _, argv := range cmds {
		add(argv[0])
		file := argv[0]
		if !strings.Contains(file, "/") {
			file = s.onPath(file)
		} else if !filepath.IsAbs(file) {
			file = filepath.Join(cwd, file)
		}
		if file == "" {
			continue
		}
		interp, arg, ok, err := agent.ReadShebang(file)
		if err != nil || !ok {
			continue
		}
		add(interp)
		if filepath.Base(interp) == "env" && arg != "" && !strings.HasPrefix(arg, "-") {
			add(arg)
		}
	}
	return out
}

// onPath is the first regular file called name in the directories of the service's PATH, or "".
func (s *Service) onPath(name string) string {
	for _, d := range filepath.SplitList(s.path()) {
		if d == "" || !filepath.IsAbs(d) {
			continue
		}
		p := filepath.Join(d, name)
		if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() {
			return p
		}
	}
	return ""
}
