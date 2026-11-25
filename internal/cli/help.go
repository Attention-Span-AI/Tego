// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// The help pages follow git's: a usage line, groups named by what the person is doing, one command per line with a
// verb-first summary, and where to read more. Every line puts the command at column 4 and its summary at column 21.

// helpGroup is one group of a help page: its title and its lines, each "name" or "noun verb".
type helpGroup struct {
	title string
	names []string
}

// commonGroups are `tego help`'s groups; `tego help -a` shows them with every verb (all), then advancedGroups.
func commonGroups(all bool) []helpGroup {
	session := []string{"run", "session list", "session show", "session stop"}
	rules := []string{"rules create", "rules edit", "rules check", "rules learn"}
	if all {
		session = append(session, "session pause", "session resume")
		rules = append(rules, "rules list", "rules history", "rules undo")
	}
	return []helpGroup{
		{"get started", []string{"start", "dashboard"}},
		{"supervise an agent", session},
		{"write the rules (see also: tego help rules)", rules},
		{"check this machine", []string{"machine check", "machine test"}},
	}
}

var advancedGroups = []helpGroup{
	{"answer what a session asks", []string{"ask", "approve", "deny", "alternate"}},
	{"change a running session's rules", []string{"block", "unblock", "grant", "lift", "restore", "rule", "rules <session>"}},
	{"read the record", []string{"events", "drift", "measure", "status", "gc"}},
	{"supervise other programs", []string{"watch", "adopt", "agents", "scan"}},
	{"tools for agents", []string{"mcp", "route", "dns"}},
	{"older names", []string{"init", "compile", "learn", "contracts", "receipt", "doctor", "test", "stop", "pause", "resume"}},
	{"about Tego", []string{"setup", "serve", "version", "licenses", "uninstall"}},
}

// commonSummaries are the help pages' summaries of the one-word commands: verb first, in a person's words. A
// command's own Summary keeps its detail for the code and tests that read it. (root) marks a command that needs root.
var commonSummaries = map[string]string{
	"start":           "Set up Tego and connect your first agent",
	"dashboard":       "Print its link (Mac: open in browser)",
	"run":             "Run an agent under its rules",
	"ask":             "List the actions waiting for an answer",
	"approve":         "Allow a waiting action",
	"deny":            "Refuse a waiting action",
	"alternate":       "Answer a waiting file open with another file",
	"block":           "Block a program, host or path in a running session",
	"unblock":         "Remove a block from a running session",
	"grant":           "Give an adjustable session more access, within its limits",
	"lift":            "Allow one of an adjustable session's refusals, within its limits",
	"restore":         "Refuse a granted or lifted entry again",
	"rule":            "Turn what a session did into a rule: block, ask or allow",
	"rules <session>": "Show the rules a session runs under",
	"events":          "List a session's events",
	"drift":           "Compare what a session's rules declared with what it did",
	"measure":         "Show a session's steps, tokens, cost and time",
	"status":          "Show the state of a session",
	"gc":              "Remove orphaned and expired sessions",
	"watch":           "Run a command and record program starts, file opens, creates, removals, renames and connections",
	"adopt":           "(root) Supervise an agent that is already running",
	"agents":          "(root) List the agent processes running here (observes only)",
	"mcp":             "Set the MCP tool rules of a running session",
	"route":           "Set the model routes of a running session",
	"dns":             "Query a session's DNS broker",
	"setup":           "Show where this machine is and what to type next",
	"serve":           "(tego-control) Start the dashboard server",
	"version":         "Print the build's versions",
	"licenses":        "Print the licence texts and third-party notices",
	"uninstall":       "Remove Tego from this machine (keeps your records unless you say so)",
}

// helpLine is one command line of a help page.
func helpLine(w io.Writer, name, summary string) {
	if len(name) >= 17 {
		name += " "
	}
	fmt.Fprintf(w, "   %-17s%s\n", name, summary)
}

// summaryOf is the summary a help page gives the line name.
func summaryOf(name string, cmds []Command) string {
	if s, ok := commonSummaries[name]; ok {
		return s
	}
	if n, v, ok := strings.Cut(name, " "); ok {
		if t, ok := treeOf(n); ok {
			if vb, ok := t.verbOf(v); ok {
				return vb.summary
			}
		}
	}
	for _, t := range trees() {
		for _, v := range t.verbs {
			if v.target == name {
				return "Same as 'tego " + t.name + " " + v.name + "'"
			}
		}
	}
	if c, ok := find(cmds, name); ok {
		return upperFirst(c.Summary)
	}
	return ""
}

// writeHelp is `tego help` (all false) or `tego help -a`.
func writeHelp(w io.Writer, cmds []Command, all bool) {
	fmt.Fprintln(w, "usage: tego [-h | --help] <command> [<args>]")
	fmt.Fprintln(w)
	groups := commonGroups(all)
	if all {
		fmt.Fprintln(w, "All Tego commands:")
		groups = append(groups, advancedGroups...)
	} else {
		fmt.Fprintln(w, "These are common Tego commands used in various situations:")
	}
	for _, g := range groups {
		fmt.Fprintln(w)
		fmt.Fprintln(w, g.title)
		for _, name := range g.names {
			if c, ok := find(cmds, name); ok && c.Hidden || !ok && !strings.Contains(name, " ") && commonSummaries[name] == "" {
				continue // hidden, or not in this table
			}
			helpLine(w, name, summaryOf(name, cmds))
		}
	}
	fmt.Fprintln(w)
	if planned := handoff.Planned(); all && len(planned) > 0 {
		fmt.Fprintf(w, "Planned, not in this build: %s\n", strings.Join(planned, ", "))
	}
	if !all {
		fmt.Fprintln(w, "'tego help -a' lists every command, including approvals and live rule changes.")
	}
	fmt.Fprintln(w, "See 'tego help <command>' to read about a specific command.")
	fmt.Fprintln(w, "Manual: https://github.com/Attention-Span-AI/Tego/blob/main/docs/user/commands.md")
}

// runHelp is `tego help [-a | <command> [<verb>]]`.
func runHelp(ctx context.Context, args []string, stdout, stderr io.Writer, cmds []Command) int {
	switch {
	case len(args) == 0:
		writeHelp(stdout, cmds, false)
		return identity.ExitOK
	case args[0] == "-a" || args[0] == "--all":
		writeHelp(stdout, cmds, true)
		return identity.ExitOK
	}
	if n, ok := treeOf(args[0]); ok {
		if len(args) == 1 {
			writeNounPage(stdout, n)
			return identity.ExitOK
		}
		code, _ := dispatch(ctx, []string{"tego", args[0], args[1], "-h"}, stdout, stderr, cmds)
		return code
	}
	if _, ok := find(cmds, args[0]); !ok {
		message(stderr, "", 0, 0, fmt.Sprintf("tego help: no command %q; run tego help -a for the list", args[0]), codeUsage)
		return identity.ExitUsage
	}
	code, _ := dispatch(ctx, []string{"tego", args[0], "-h"}, stdout, stderr, cmds)
	return code
}

// upperFirst is s with its first letter capitalised.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
