// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// cmdWorkspace is the workspace group: `maze workspace show` prints the project's saved rules, `maze workspace
// remove` deletes its .maze/ folder, its approval record and Maze's .gitignore lines, so the next `maze` sets the
// project up from scratch.
func cmdWorkspace() Command {
	var (
		yes, asJSON bool
		dir         string
	)
	return Command{
		Name:    "workspace",
		Summary: "This project's rules: show, remove",
		Usage:   "show|remove [flags]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&dir, "C", ".", "the project in `<dir>` instead of the current folder")
			fs.BoolVar(&asJSON, "json", false, "show: print the rules as JSON")
			fs.BoolVar(&yes, "yes", false, "remove: don't ask first")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			sub := fs.Arg(0)
			if (sub != "show" && sub != "remove") || fs.NArg() > 1 {
				subProblem(s, "workspace", fs.Args())
				fmt.Fprintln(s.Err, "Usage: maze workspace show [--json] [-C <dir>]")
				fmt.Fprintln(s.Err, "       maze workspace remove [--yes] [-C <dir>]")
				return identity.ExitUsage
			}
			t := newTerm(s, ui.Options{})
			if sub == "remove" {
				// Removing works on a project whose rules file is broken too: it is the way out.
				return removeWorkspace(ctx, t, s, dir, yes)
			}
			p, err := openProject(ctx, dir)
			if err != nil {
				return fail(s, "maze workspace "+sub, err)
			}
			name := p.r.Workspace.Name
			if !p.setUp {
				if asJSON {
					return printJSON(s.Out, s.Err, "maze workspace show", RulesFile{Version: 1, File: scope.WorkspaceFile, Rules: []Rule{}}, identity.ExitFinding)
				}
				t.Println("  " + name + " isn't set up with Maze. To set it up: " + t.Accent("maze init"))
				return identity.ExitFinding
			}
			ws := onlyScope(p.rules, "workspace")
			if sub == "show" {
				f := RulesFile{Version: 1, File: scope.WorkspaceFile, Approved: p.approval.Same, Rules: ws}
				if asJSON {
					return printJSON(s.Out, s.Err, "maze workspace show", f, identity.ExitOK)
				}
				showRules(t, name+"  ·  "+scope.WorkspaceFile, ws, p.approval)
				return identity.ExitOK
			}
			return identity.ExitOK
		},
	}
}

// removeWorkspace is `maze workspace remove`: it takes out everything Maze added to the project (.maze/, the
// pre-push check, its .gitignore lines) and the approval record, after asking.
func removeWorkspace(ctx context.Context, t *ui.Term, s Streams, dir string, yes bool) int {
	env, err := scan.FromOS()
	if err != nil {
		return fail(s, "maze workspace remove", err)
	}
	ws, err := scan.FindWorkspace(dir)
	if err != nil {
		return fail(s, "maze workspace remove", &projectError{upperFirst(err.Error()) + "."})
	}
	if msg := projectProblem(ws.Root, env.Home); msg != "" {
		return fail(s, "maze workspace remove", &projectError{msg})
	}
	if !ws.SetUp {
		// .maze may have been deleted by hand: the pre-push check, the .gitignore line and the record of what
		// was approved can still be there, and they go too.
		if err := scope.RemoveWorkspace(env.Home, ws.Root); err != nil {
			return fail(s, "maze workspace remove", err)
		}
		t.Println("  " + ws.Name + " isn't set up with Maze. Anything Maze had left there is gone.")
		return identity.ExitOK
	}
	if !confirmed(ctx, t, s, yes, "maze workspace remove", "Remove Maze from "+ws.Name+"? This deletes its .maze folder (rules your team may share) and the pre-push check.") {
		return identity.ExitFinding
	}
	if err := scope.RemoveWorkspace(env.Home, ws.Root); err != nil {
		return fail(s, "maze workspace remove", err)
	}
	t.Println("  " + t.Good("✓") + " Removed Maze from " + t.Bold(ws.Name) + ". To set it up again: " + t.Accent("maze"))
	// Say what stays, so nobody thinks Maze is gone from the computer.
	if fileExists(filepath.Join(env.Home, ".maze")) {
		t.Println("  " + t.Dim("Still on this computer: your rules for every project and Claude Code's commit key, in ~/.maze."))
		t.Println("  " + t.Dim("To remove those too: ") + t.Accent("maze profile remove") + t.Dim(", then delete ~/.maze."))
	}
	return identity.ExitOK
}

// cmdProfile is the profile group: `maze profile show` prints the person's rules for every project, `maze
// profile remove` deletes ~/.maze/personal.yaml so the next `maze` starts with the guided first run.
func cmdProfile() Command {
	var yes, asJSON bool
	return Command{
		Name:    "profile",
		Summary: "Your rules for every project: show, remove",
		Usage:   "show|remove [flags]",
		Flags: func(fs *flag.FlagSet) {
			fs.BoolVar(&asJSON, "json", false, "show: print the rules as JSON")
			fs.BoolVar(&yes, "yes", false, "remove: don't ask first")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			sub := fs.Arg(0)
			if (sub != "show" && sub != "remove") || fs.NArg() > 1 {
				subProblem(s, "profile", fs.Args())
				fmt.Fprintln(s.Err, "Usage: maze profile show [--json]")
				fmt.Fprintln(s.Err, "       maze profile remove [--yes]")
				return identity.ExitUsage
			}
			env, err := scan.FromOS()
			if err != nil {
				return fail(s, "maze profile "+sub, err)
			}
			t := newTerm(s, ui.Options{})
			personal, ok, err := scope.LoadPersonal(env.Home)
			if err != nil {
				return fail(s, "maze profile "+sub, err)
			}
			if sub == "show" {
				f := RulesFile{Version: 1, File: "~/" + scope.PersonalFile, Approved: true, Rules: personal.Rules}
				if asJSON {
					return printJSON(s.Out, s.Err, "maze profile show", f, identity.ExitOK)
				}
				if !ok {
					t.Println("  You have no rules for every project yet. They're saved the first time you run " + t.Accent("maze init") + ".")
					return identity.ExitOK
				}
				showRules(t, "Your rules for every project  ·  ~/"+scope.PersonalFile, sortRules(personal.Rules), scope.Approval{Recorded: true, Same: true})
				return identity.ExitOK
			}
			if !ok {
				t.Println("  You have no rules for every project yet, so there's nothing to forget.")
				return identity.ExitOK
			}
			if !confirmed(ctx, t, s, yes, "maze profile remove", "Forget your rules for every project? This deletes ~/.maze/personal.yaml.") {
				return identity.ExitFinding
			}
			if err := scope.RemovePersonal(env.Home); err != nil {
				return fail(s, "maze profile remove", err)
			}
			t.Println("  " + t.Good("✓") + " Forgot your rules for every project. The next " + t.Accent("maze") + " starts fresh.")
			return identity.ExitOK
		},
	}
}

// subProblem says what was wrong with a group's arguments, before its usage lines.
func subProblem(s Streams, group string, args []string) {
	switch {
	case len(args) == 0:
		fmt.Fprintf(s.Err, "maze %s: what should it do?\n", group)
	case len(args) > 1:
		fmt.Fprintf(s.Err, "maze %s %s: takes nothing more (got %q).\n", group, args[0], strings.Join(args[1:], " "))
	default:
		fmt.Fprintf(s.Err, "maze %s: unknown action %q.\n", group, args[0])
	}
}

// RulesFile is `maze workspace show --json` and `maze profile show --json`: one rules file and its rules.
type RulesFile struct {
	Version  int    `json:"version"`
	File     string `json:"file"`
	Approved bool   `json:"approved"`
	Rules    []Rule `json:"rules"`
}

// onlyScope keeps the rules saved at scope.
func onlyScope(rules []Rule, sc string) []Rule {
	var out []Rule
	for _, rl := range rules {
		if rl.Scope == sc {
			out = append(out, rl)
		}
	}
	return out
}

// showRules prints a rules file: a title line, the rules by category, and a warning when they changed since the
// person approved them.
func showRules(t *ui.Term, title string, rules []Rule, a scope.Approval) {
	t.Println("  " + t.Bold(title))
	switch {
	case !a.Same && !a.Recorded:
		t.Println("  " + t.Bad("!") + " Not approved on this computer yet. Review: " + t.Accent("maze"))
	case !a.Same:
		t.Println("  " + t.Bad("!") + " Changed since you approved them. Review: " + t.Accent("maze"))
	}
	t.Println()
	// A rule the file changed that the person hasn't approved must not read as one that holds.
	notes := map[string]string{}
	if a.Recorded {
		for _, c := range a.Changes {
			if c.Kind != "removed" {
				notes[c.Rule.Key()] = "not approved yet"
			}
		}
	}
	printRulesMarked(t, rules, notes)
}

// confirmed asks question with No as the default, or takes --yes. With nobody at the terminal and no --yes it
// says how to go ahead and returns false.
func confirmed(ctx context.Context, t *ui.Term, s Streams, yes bool, cmd, question string) bool {
	if yes {
		return true
	}
	if !t.Interactive() {
		fmt.Fprintf(s.Err, "%s: no terminal to ask in. Add --yes to confirm.\n", cmd)
		return false
	}
	ok, err := t.ConfirmDefault(ctx, "  "+question, false)
	if err != nil || !ok {
		t.Println("  Nothing removed.")
		return false
	}
	return true
}
