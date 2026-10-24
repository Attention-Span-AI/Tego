// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// kinds are what `maze allow` and `maze block` take, with the other words people type for them.
var kinds = map[string]string{
	"program": "program", "cmd": "program", "command": "program",
	"website": "website", "net": "website", "site": "website", "host": "website",
	"file": "file", "read": "file",
	"env": "env", "var": "env", "variable": "env",
	"write": "write",
}

// ruleUsage is the help both commands print: one example per kind.
func ruleUsage(verb string) string {
	ex := map[string][]string{
		"allow": {
			"maze allow program make              Claude Code can run make",
			"maze allow website api.github.com    it can connect to api.github.com",
			"maze allow file config/dev.json      it can read a file Maze blocks",
			"maze allow env OPENAI_API_KEY        it can see that variable",
			"maze allow write                     it can change files in the project",
		},
		"block": {
			"maze block program npm               Claude Code can't run npm",
			"maze block website pypi.org          it can't connect to pypi.org",
			"maze block file config/prod.json     it can't read that file",
			"maze block env OPENAI_API_KEY        it can't see that variable",
			"maze block write                     the project is read-only for it",
		},
	}
	return "Examples:\n  " + strings.Join(ex[verb], "\n  ") + "\n"
}

// cmdAllow is `maze allow <kind> <value>`.
func cmdAllow() Command { return ruleCommand("allow", true) }

// cmdBlock is `maze block <kind> <value>`.
func cmdBlock() Command { return ruleCommand("block", false) }

// ruleCommand builds allow (allow true) or block: change one rule in the project's saved rules, save, and say
// the result as a sentence. Typing the command is the person's approval, so the change is approved as saved; a
// project whose rules changed since they were approved is refused until a person reviews it.
func ruleCommand(verb string, allow bool) Command {
	var dir string
	summary := "Let Claude Code do one more thing"
	if !allow {
		summary = "Stop Claude Code from doing one thing"
	}
	return Command{
		Name:    verb,
		Summary: summary,
		Usage:   "<program|website|file|env|write> [<name>] [flags]\n\n" + ruleUsage(verb),
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&dir, "C", ".", "the project in `<dir>` instead of the current folder")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			kind, ok := kinds[strings.ToLower(fs.Arg(0))]
			switch {
			case fs.NArg() == 0:
				fmt.Fprintf(s.Err, "maze %s: what should Claude Code %s?\n\n%s", verb, map[bool]string{true: "be able to do", false: "stop doing"}[allow], ruleUsage(verb))
				return identity.ExitUsage
			case !ok:
				fmt.Fprintf(s.Err, "maze %s: %q isn't something Maze has rules for. Use program, website, file, env or write.\n", verb, fs.Arg(0))
				if fs.NArg() == 1 {
					fmt.Fprintf(s.Err, "Did you mean: maze %s %s %s\n", verb, guessKind(fs.Arg(0)), shellQuote(fs.Arg(0)))
				}
				return identity.ExitUsage
			case kind == "write" && fs.NArg() > 1:
				fmt.Fprintf(s.Err, "maze %s write: takes no name; it's about the whole project. Use maze %s file <path> for one file.\n", verb, verb)
				return identity.ExitUsage
			case kind != "write" && fs.NArg() == 1:
				fmt.Fprintf(s.Err, "maze %s %s: which one? For example: %s\n", verb, fs.Arg(0), strings.Join(strings.Fields(exampleFor(verb, kind))[:4], " "))
				return identity.ExitUsage
			case kind != "write" && fs.NArg() > 2:
				fmt.Fprintf(s.Err, "maze %s %s: one name at a time. To use spaces, put it in quotes.\n", verb, fs.Arg(0))
				return identity.ExitUsage
			}
			env, err := scan.FromOS()
			if err != nil {
				return fail(s, "maze "+verb, err)
			}
			// Read, change and write under one lock, so a second maze command at the same time waits its turn.
			unlock, err := scope.Lock(ctx, env.Home)
			if err != nil {
				return fail(s, "maze "+verb, err)
			}
			defer unlock()
			p, err := openProject(ctx, dir)
			if err != nil {
				return fail(s, "maze "+verb, err)
			}
			name := p.r.Workspace.Name
			switch {
			case !p.setUp:
				fmt.Fprintf(s.Err, "maze %s: %s isn't set up yet. Run maze init first.\n", verb, name)
				return identity.ExitFinding
			case !p.approval.Same && !p.approval.Recorded:
				fmt.Fprintf(s.Err, "maze %s: the rules for %s aren't approved on this computer yet. Run maze to review them first.\n", verb, name)
				return identity.ExitFinding
			case !p.approval.Same:
				fmt.Fprintf(s.Err, "maze %s: the rules for %s changed since you approved them. Run maze to review them first.\n", verb, name)
				return identity.ExitFinding
			case len(p.r.Agents) == 0:
				fmt.Fprintf(s.Err, "maze %s: Claude Code isn't installed, so there's nothing to set rules for.\n", verb)
				return identity.ExitFinding
			}
			base := p.r.Workspace.Started
			if base == "" {
				base = p.r.Workspace.Root
			}
			rules, out, msg := changeRule(p.r, base, p.rules, kind, fs.Arg(1), allow)
			t := newTerm(s, ui.Options{})
			switch out {
			case same:
				t.Println("  " + msg)
				return identity.ExitOK
			case refused:
				fmt.Fprintln(s.Err, "  ✗ "+msg)
				return identity.ExitFinding
			}
			res, err := saveLocked(ctx, p.r, rules)
			if err != nil {
				return fail(s, "maze "+verb, err)
			}
			t.Println("  " + t.Good("✓") + " " + msg)
			if kind == "website" && allow && pushHosts[strings.ToLower(fs.Arg(1))] {
				t.Println("  " + t.Dim("Git can pull and clone from it now. It still can't push as you: your logins and keys stay blocked."))
			}
			// Only what this change left unenforced; notes about other rules were said when those were made.
			for _, g := range res.gaps {
				if strings.Contains(g, fs.Arg(1)) {
					t.Println("  " + t.Accent("!") + " " + g)
				}
			}
			undo := []string{"maze", map[bool]string{true: "block", false: "allow"}[allow], fs.Arg(0)}
			if kind != "write" {
				undo = append(undo, shellQuote(fs.Arg(1)))
			}
			if dir != "." {
				undo = append(undo, "-C", shellQuote(dir))
			}
			t.Println("  " + t.Dim("Undo: "+strings.Join(undo, " ")))
			return identity.ExitOK
		},
	}
}

// pushHosts are code hosts git pushes to: allowing one lets a saved login push.
var pushHosts = map[string]bool{"github.com": true, "gitlab.com": true, "bitbucket.org": true, "codeberg.org": true, "ssh.github.com": true}

// guessKind is the kind a bare name most likely means: a website when it has a dot and no slash, a file when it
// has a slash, a program otherwise.
func guessKind(name string) string {
	switch {
	case strings.Contains(name, "/"):
		return "file"
	case strings.Contains(name, "."):
		return "website"
	case strings.ToUpper(name) == name && strings.Contains(name, "_"):
		return "env"
	}
	return "program"
}

// exampleFor is the usage line of verb for kind.
func exampleFor(verb, kind string) string {
	for _, l := range strings.Split(ruleUsage(verb), "\n") {
		if f := strings.Fields(l); len(f) > 2 && f[2] == kind {
			return l
		}
	}
	return ""
}

// What changeRule did.
const (
	didChange = iota // the rules changed as asked
	same             // they already said that
	refused          // it can't be done, and msg says why
)

// changeRule applies one allow or block to rules and returns the new rules, what it did, and the sentence to
// print: the result when it changed, the reason when it didn't. base is where a relative file path starts.
func changeRule(r Report, base string, rules []Rule, kind, value string, allow bool) ([]Rule, int, string) {
	rules = slices.Clone(rules)
	switch kind {
	case "write":
		for i, rl := range rules {
			if rl.Category == "files" && rl.Verb == "write" && strings.HasPrefix(rl.Value, "everything in ") {
				if rl.Allow == allow {
					return rules, same, sentence(rl, "already ")
				}
				rules[i].Allow, rules[i].Why = allow, byYou(allow)
				return rules, didChange, sentence(rules[i], "")
			}
		}
		return rules, refused, "This project has no rule about changing its files; run maze to review it."
	case "program":
		if strings.EqualFold(filepath.Base(value), "ssh-keygen") && !allow {
			return rules, refused, "Claude Code uses ssh-keygen only to sign its own commits; it stays allowed while git is. To stop commits: maze block program git"
		}
		rl, note := addProgram(r, value)
		if note != "" {
			return rules, refused, note
		}
		return changeList(rules, rl, allow, func(x Rule) []string { return x.Programs }, func(x *Rule, v []string) { x.Programs = v })
	case "website":
		rl, note := addWebsite(value)
		if note != "" {
			return rules, refused, note
		}
		return changeList(rules, rl, allow, func(x Rule) []string { return x.Hosts }, func(x *Rule, v []string) { x.Hosts = v })
	case "env":
		name, note := envRule(value)
		switch {
		case note != "":
			return rules, refused, note
		case allow && isLoginToken(name):
			return rules, refused, "Not $" + name + ": with it Claude Code could push or publish as you."
		case !allow && (name == "PATH" || name == "HOME" || name == "LANG" || name == "TERM"):
			return rules, refused, "Claude Code needs $" + name + " to run; it holds no secret."
		}
		for i, rl := range rules {
			if rl.Category == "logins" && rl.Verb == "see" && rl.Value == name {
				if rl.Allow == allow {
					return rules, same, sentence(rl, "already ") + " (in every project)"
				}
				rules[i].Allow, rules[i].Why = allow, byYou(allow)
				return rules, didChange, sentence(rules[i], "") + " (in every project)"
			}
		}
		rl := Rule{Scope: "personal", Category: "logins", Verb: "see", Value: name, Allow: allow, Why: byYou(allow), Added: true}
		return sortRules(append(rules, rl)), didChange, sentence(rl, "") + " (in every project)"
	}
	// A file. Allowing lifts a block the person can lift; blocking adds one for a file that exists.
	abs, stored := filePath(r, base, value)
	if why := lockedFile(r, abs); why != "" {
		if allow {
			return rules, refused, "Maze always blocks " + stored + ": " + why[strings.Index(why, ": ")+2:] + "."
		}
		return rules, same, "Claude Code already can't read " + stored + ": " + why + "."
	}
	// A file inside a blocked folder is blocked with it.
	for _, rl := range rules {
		if rl.Category != "files" || rl.Verb != "read" || rl.Allow {
			continue
		}
		for _, p := range rl.Paths {
			if p != "" && strings.HasPrefix(strings.TrimSuffix(stored, "/"), strings.TrimSuffix(p, "/")+"/") {
				if allow {
					return rules, refused, "Maze blocks " + stored + " as part of " + p + "/. To read it, allow the folder: maze allow file " + p
				}
				return rules, same, "Claude Code already can't read " + stored + ": it's inside " + p + "/, which is blocked."
			}
		}
	}
	for i, rl := range rules {
		if rl.Category != "files" || rl.Verb != "read" || !(rl.Value == stored || slices.Contains(rl.Paths, strings.TrimSuffix(stored, "/"))) {
			continue
		}
		switch {
		case rl.Allow == allow:
			return rules, same, sentence(rl, "already ")
		case rl.Always:
			return rules, refused, "Maze always blocks " + stored + "."
		case allow && rl.Added:
			// A block the person added goes away when they allow it again.
			return slices.Delete(rules, i, i+1), didChange, "Claude Code can read " + stored + " again."
		}
		rules[i].Allow, rules[i].Why = allow, byYou(allow)
		return rules, didChange, sentence(rules[i], "")
	}
	if _, err := os.Lstat(abs); err != nil {
		return rules, refused, "There's no file at " + value + "."
	}
	if allow {
		return rules, same, "Claude Code can already read " + stored + ": Maze doesn't block it."
	}
	rl, note := addFile(r, base, value)
	if note != "" {
		return rules, refused, note
	}
	return sortRules(append(rules, rl)), didChange, sentence(rl, "")
}

// byYou is the note on a rule the person switched from the command line.
func byYou(allow bool) string {
	if allow {
		return "set with maze allow"
	}
	return "set with maze block"
}

// changeList allows or blocks one program or website (fresh.Value), which may sit in a shared row (node, npm, or
// basic tools). Blocking one out of a shared row splits it off and remembers the row (From), so allowing it
// again puts it back exactly where it was; a rule the person added is removed rather than switched.
func changeList(rules []Rule, fresh Rule, allow bool, get func(Rule) []string, set func(*Rule, []string)) ([]Rule, int, string) {
	value := fresh.Value
	fresh.Allow, fresh.Added, fresh.Why = allow, true, byYou(allow)
	for i, rl := range rules {
		list := get(rl)
		if rl.Category != fresh.Category || rl.Value == "anything else" || !slices.Contains(list, value) {
			continue
		}
		if rl.Allow == allow {
			return rules, same, sentence(fresh, "already ")
		}
		if len(list) == 1 {
			// Its own row: put a split-off one back into its row, take away one the person added, or switch it.
			if allow && len(rl.From) > 0 {
				if j := rowWith(rules, rl.Category, rl.From, value, get); j >= 0 {
					set(&rules[j], ordered(rl.From, append(get(rules[j]), value)))
					fixValue(&rules[j], get(rules[j]))
					return slices.Delete(rules, i, i+1), didChange, sentence(fresh, "")
				}
			}
			if rl.Added && !allow && len(rl.From) == 0 {
				return slices.Delete(rules, i, i+1), didChange, sentence(fresh, "")
			}
			rules[i].Allow, rules[i].Why = allow, byYou(allow)
			return rules, didChange, sentence(fresh, "")
		}
		// Split value out of the shared row; the others keep their effect.
		fresh.From = slices.Clone(list)
		set(&rules[i], slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == value }))
		fixValue(&rules[i], get(rules[i]))
		return sortRules(append(rules, fresh)), didChange, sentence(fresh, "")
	}
	if !allow {
		return rules, same, sentence(fresh, "already ")
	}
	return sortRules(append(rules, fresh)), didChange, sentence(fresh, "")
}

// rowWith finds the allowed row that still holds another member of from, the row value was split out of.
func rowWith(rules []Rule, cat string, from []string, value string, get func(Rule) []string) int {
	for j, rl := range rules {
		if rl.Category != cat || !rl.Allow {
			continue
		}
		for _, m := range from {
			if m != value && slices.Contains(get(rl), m) {
				return j
			}
		}
	}
	return -1
}

// ordered puts list in the order of from, members from doesn't name last.
func ordered(from, list []string) []string {
	var out []string
	for _, m := range from {
		if slices.Contains(list, m) {
			out = append(out, m)
		}
	}
	for _, m := range list {
		if !slices.Contains(out, m) {
			out = append(out, m)
		}
	}
	return out
}

// fixValue keeps a row's label in step with its list: "node, npm" for programs and hosts rows, the short list
// for basic tools.
func fixValue(rl *Rule, list []string) {
	switch {
	case rl.Value == "basic tools":
		rl.Why = shortList(list, 3)
	case rl.Category == "websites" && strings.HasSuffix(rl.Why, " packages"):
		rl.Value = strings.Join(list, ", ")
	default:
		rl.Value = strings.Join(list, ", ")
	}
}

// sentence says what rl means as a sentence about Claude Code: "Claude Code can run make." With "already ",
// it says nothing had to change.
func sentence(rl Rule, already string) string {
	label, _ := phrase(rl)
	if rl.Allow && already != "" {
		return "Claude Code can already " + label + "."
	}
	if rl.Allow {
		return "Claude Code can " + label + "."
	}
	if already != "" {
		return "Claude Code already can't " + label + "."
	}
	return "Claude Code can't " + label + "."
}
