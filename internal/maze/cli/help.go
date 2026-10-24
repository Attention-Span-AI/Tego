// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/ui"
)

// entry is one line of the help screen: a command of the canonical tree, built or not.
type entry struct {
	name    string // the command as typed, without `maze`
	cmd     string // the command it runs, to mark it built; "" for a group line
	summary string
}

// section is one group of the help screen.
type section struct {
	title   string
	entries []entry
}

// tree is the canonical command tree in the order a new user needs it. A command shows under Commands once
// commands() has it, and under "Coming soon" until then, so help never offers something that doesn't run.
var tree = []section{
	{"Get started", []entry{
		{"init", "init", "Set up rules for this project"},
		{"run", "run", "Run Claude Code under its rules"},
	}},
	{"Every day", []entry{
		{"status", "status", "This project's rules, in one line"},
		{"allow program|website|file <name>", "allow", "Let Claude Code do one more thing"},
		{"block program|website|file <name>", "block", "Stop Claude Code from doing one thing"},
		{"receipt", "receipt", "What Claude Code did last session"},
	}},
	{"Manage", []entry{
		{"workspace show|remove", "workspace", "This project's rules"},
		{"profile show|remove", "profile", "Your rules for every project"},
		{"system doctor|version", "system", "Check this machine and project"},
		{"help [command]", "help", "Show the commands, or one command's help"},
		{"agent", "agent", "The agents Maze can run"},
		{"rule", "rule", "Every rule, at any scope"},
		{"session", "session", "Past and running sessions"},
	}},
}

// planned reports whether name is in the tree, built or not.
func planned(name string) bool {
	for _, s := range tree {
		for _, e := range s.entries {
			if e.cmd == name {
				return true
			}
		}
	}
	return false
}

// help prints the welcome banner and the command list.
func help(t *ui.Term, built map[string]Command) {
	t.Banner()
	helpBody(t, built)
}

// helpBody prints the commands that run today by section, then the names of the ones coming, the way docker
// and kubectl lay out their help.
func helpBody(t *ui.Term, built map[string]Command) {
	w := len("maze <command>")
	var soon []string
	for _, s := range tree {
		for _, e := range s.entries {
			if _, ok := built[e.cmd]; ok {
				w = max(w, len(e.name))
			} else {
				soon = append(soon, e.name)
			}
		}
	}
	t.Println("  " + t.Bold("Usage"))
	t.Println("    " + t.Accent(padRight("maze", w)) + "   open the menu")
	t.Println("    " + t.Accent(padRight("maze <command>", w)) + "   run a command")
	for _, s := range tree {
		var lines []string
		for _, e := range s.entries {
			if _, ok := built[e.cmd]; ok {
				lines = append(lines, "    "+t.Accent(padRight(e.name, w))+"   "+e.summary)
			}
		}
		if len(lines) == 0 {
			continue
		}
		t.Println()
		t.Println("  " + t.Bold(s.title))
		for _, l := range lines {
			t.Println(l)
		}
	}
	t.Println()
	t.Println("  " + t.Bold("Coming soon"))
	t.Println("    " + t.Dim(strings.Join(soon, " · ")))
	t.Println()
	t.Println("  " + t.Dim("maze help <command> for details · --no-color for plain text · maze --version"))
	t.Println()
}

// padRight pads s with spaces to n columns.
func padRight(s string, n int) string {
	if len(s) >= n {
		return s
	}
	return s + strings.Repeat(" ", n-len(s))
}
