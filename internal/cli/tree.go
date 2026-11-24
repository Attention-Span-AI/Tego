// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// verb is one `tego <noun> <verb>`: it runs an existing command (target), or a command of its own (cmd).
type verb struct {
	name, summary string
	target        string
	cmd           func() Command
	// usage is the short synopsis the noun's page shows; -h shows the command's full one.
	usage string
}

// noun groups verbs the way git and gh do (`tego session list`). Each verb runs code that already exists under a
// one-word name, which keeps working; the tree only gives a person one place to look.
type noun struct {
	name  string
	verbs []verb
}

// trees is the command tree, built on each call: its verbs reach dispatch, which reads it.
func trees() []noun {
	return []noun{
		{"rules", []verb{
			{"create", "Create a rules file in a project", "init", nil, "[--name <agent>] [--agent <program>] [--preset <list>] [--write <dir>]... [<dir>]"},
			{"edit", "Edit a rules file, then check it", "", cmdRulesEdit, "<agent | file>"},
			{"check", "Check a rules file and show what it enforces", "compile", nil, "<agent | file> [--json]"},
			{"learn", "Create a rules file from what a session did", "learn", nil, "<session> [--save <name> | --out <file>]"},
			{"history", "Show the changes made to a rules file", "", cmdRulesHistory, "<agent | file> [--json]"},
			{"undo", "Undo the newest change to a rules file", "", cmdRulesUndo, "<agent | file> [<id>] [--yes]"},
		}},
		{"session", []verb{
			{"list", "List sessions", "", cmdSessionList, "[--json]"},
			{"show", "Show what a session did and what Tego blocked", "receipt", nil, "<session> | --last [--json]"},
			{"stop", "Stop a running session", "stop", nil, "<session>"},
			{"pause", "Pause a running session", "pause", nil, "<session>"},
			{"resume", "Resume a paused session", "resume", nil, "<session>"},
		}},
		{"machine", []verb{
			{"check", "Check what this machine can enforce", "doctor", nil, "[--json]"},
			{"test", "Run Tego's self-check", "test", nil, "[--json]"},
		}},
	}
}

func init() {
	register(cmdSession)
	register(cmdMachine) // tego rules is a tego-control noun: handOffCommand runs its verbs
}

func cmdSession() Command {
	return Command{Name: "session", Summary: "manage sessions", Raw: nounRunner("session")}
}

// cmdRulesHistory and cmdRulesUndo are `tego rules history` and `tego rules undo`: the dashboard's change history and its
// Undo for a rules file, run by tego-control (internal/control/cli rules_history.go) through the verified handoff, which
// replaces this process in place, so the terminal, the standard input and the environment pass through as they are.
// tego links none of their code (TestEngineLinksNoControl). The engine parses only the two flags, for its own -h and
// help, and hands on the verb, its flag and the words after "--", so a word that starts with a dash is never read as a flag.
func cmdRulesHistory() Command {
	return rulesHistoryHandoff("history", "show the changes made to a rules file", "<agent | file> [--json]", "json", "print the history as versioned JSON")
}

func cmdRulesUndo() Command {
	return rulesHistoryHandoff("undo", "undo the newest change to a rules file", "<agent | file> [<id>] [--yes]", "yes",
		"confirm an undo that lets the next run do more, instead of typing undo at a terminal (required without one)")
}

func rulesHistoryHandoff(verb, summary, usage, flagName, flagHelp string) Command {
	var on bool
	return Command{
		Name: "rules " + verb, Summary: summary, Usage: usage,
		Flags: func(fs *flag.FlagSet) { fs.BoolVar(&on, flagName, false, flagHelp) },
		Run: func(_ context.Context, fs *flag.FlagSet, _, stderr io.Writer) int {
			args := []string{verb}
			if on {
				args = append(args, "--"+flagName)
			}
			return handOff("rules", append(append(args, "--"), fs.Args()...), stderr)
		},
	}
}

func cmdMachine() Command {
	return Command{Name: "machine", Summary: "check this machine", Raw: nounRunner("machine")}
}

// nounRunner runs the noun named name.
func nounRunner(name string) func(context.Context, []string, io.Writer, io.Writer) int {
	return func(ctx context.Context, args []string, stdout, stderr io.Writer) int {
		n, _ := treeOf(name)
		return runNoun(ctx, n, args, stdout, stderr)
	}
}

// treeOf is the noun named name.
func treeOf(name string) (noun, bool) {
	for _, n := range trees() {
		if n.name == name {
			return n, true
		}
	}
	return noun{}, false
}

// verbOf is the noun's verb named name.
func (n noun) verbOf(name string) (verb, bool) {
	for _, v := range n.verbs {
		if v.name == name {
			return v, true
		}
	}
	return verb{}, false
}

// command is the Command the verb runs.
func (v verb) command() (Command, bool) {
	if v.cmd != nil {
		return v.cmd(), true
	}
	return find(commands(), v.target)
}

// runNoun runs `tego <noun> [verb] args...`: the noun's page with no verb or -h, else the verb.
func runNoun(ctx context.Context, n noun, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		writeNounPage(stdout, n)
		return identity.ExitOK
	}
	v, ok := n.verbOf(args[0])
	if !ok {
		message(stderr, "", 0, 0, fmt.Sprintf("tego %s: unknown command %q; run tego %s for the list", n.name, args[0], n.name), codeUsage)
		return identity.ExitUsage
	}
	cmd, _ := v.command()
	code, _ := runCommand(ctx, n.name+" "+v.name, cmd, args[1:], stdout, stderr)
	return code
}

// isTreeVerb reports whether args start with one of the noun's verbs or ask for its page, for a noun that also takes
// other first words (tego rules <session>).
func isTreeVerb(n noun, args []string) bool {
	if len(args) == 0 {
		return true
	}
	if _, ok := n.verbOf(args[0]); ok {
		return true
	}
	return args[0] == "-h" || args[0] == "--help"
}

// writeNounPage is `tego <noun>`: git's usage lines for each verb, then each verb's summary.
func writeNounPage(w io.Writer, n noun) {
	for i, v := range n.verbs {
		lead := "   or: "
		if i == 0 {
			lead = "usage: "
		}
		fmt.Fprintln(w, strings.TrimRight(lead+"tego "+n.name+" "+v.name+" "+v.usage, " "))
	}
	if n.name == "rules" {
		fmt.Fprintln(w, "   or: tego rules <session> | --last [--json]")
	}
	fmt.Fprintln(w)
	for _, v := range n.verbs {
		helpLine(w, v.name, v.summary)
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "See 'tego help %s <command>' to read about a specific command.\n", n.name)
}
