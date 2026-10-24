// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
)

// Rule is one line of the review: in a category, an action on something, allowed or blocked. It is the same
// rule the saved files hold and the contract is compiled from (scope.Rule).
type Rule = scope.Rule

// The categories, in the order the review shows them, with their headings and a note beside the heading.
var categories = []struct{ key, title, note string }{
	{"files", "Files", ""},
	{"programs", "Programs", ""},
	{"websites", "Websites", ""},
	{"logins", "Your logins & keys", "you keep using them"},
}

// neverAllowed are programs no rule may let the agent run: Maze's own CLI and the engine, which could change or
// stop the rules the agent runs under.
var neverAllowed = scope.NeverAllowed

// toolGroups puts programs that come together on one line: the runtime and its package manager.
var toolGroups = map[string]string{
	"node": "node", "npm": "node", "bun": "node", "pnpm": "node", "yarn": "node",
	"python3": "python", "pip": "python", "uv": "python", "poetry": "python",
}

// logins are what a toolchain does with the person's login that the agent must not do as them: the rule reads
// "can't push to GitHub as you".
var logins = []struct{ tool, verb, service string }{
	{"git", "push", "GitHub"},
	{"npm", "publish", "npm"},
	{"pip", "publish", "PyPI"},
}

// rule builds a suggested rule.
func rule(cat, verb, value string, allow, always bool, why string) Rule {
	return Rule{Category: cat, Verb: verb, Value: value, Allow: allow, Always: always, Why: why, Suggested: allow}
}

// buildRules turns what Maze found into rules, by category, each an action that is allowed or blocked. The
// "anything else" lines make the default visible: what isn't allowed is blocked. Without the look (looked
// false) only what the engine always enforces is listed.
func buildRules(r Report, looked bool) []Rule {
	name := r.Workspace.Name
	if !looked {
		// Without the look Maze knows no project files or tools, but every locked promise still holds and is shown.
		basics := []Rule{
			rule("files", "read", "everything in "+name, true, true, ""),
			rule("files", "write", "everything in "+name, true, false, ""),
			rule("files", "read", "any .env file", false, true, ""),
			rule("files", "read", "~/.ssh, ~/.aws and other keys", false, true, ""),
			rule("files", "write", ".git/hooks, .git/config, .claude/", false, true, ""),
			rule("files", "write", "anything outside "+name, false, true, ""),
		}
		basics = append(basics, shellRule())
		if rl, ok := basicToolsRule(r); ok {
			basics = append(basics, rl)
		}
		basics = append(basics,
			// Nothing else is allowed to run or connect: say so, rather than leave the reader guessing.
			rule("programs", "run", "anything else", false, true, ""),
			rule("websites", "reach", "anything else", false, true, ""),
		)
		for _, l := range logins {
			basics = append(basics, rule("logins", l.verb, l.service, false, true, ""))
		}
		setScopes(basics)
		return sortRules(basics)
	}
	var rules []Rule
	add := func(rl Rule) { rules = append(rules, rl) }

	// Files.
	add(rule("files", "read", "everything in "+name, true, true, ""))
	add(rule("files", "write", "everything in "+name, true, false, ""))
	var envFiles []string // .env files the engine always blocks, on one line
	for _, f := range r.Repo.Secrets {
		path := strings.TrimSuffix(f.Path, "/")
		// Every .env file stays blocked, even one with only public settings: letting the agent read one inside
		// the blocked set needs the engine's per-path exception, and showing "can read" before then would
		// promise what the engine doesn't do. --explain still says which ones could be readable.
		switch why := scope.LockedPath(r.Home, path); {
		case f.BuiltIn || strings.HasPrefix(why, ".env"):
			envFiles = append(envFiles, path) // .ENV.local too: it gets a block of its own
			continue
		case why != "":
			rl := rule("files", "read", f.Path, false, true, "may hold a publish token")
			rl.Paths = []string{path}
			add(rl)
			continue
		}
		rl := rule("files", "read", f.Path, false, false, "has keys")
		rl.Paths = []string{path}
		add(rl)
	}
	// One row for every .env file, found now or made later: the engine finds them again at every run.
	env := rule("files", "read", "any .env file", false, true, "")
	if len(envFiles) > 0 {
		env.Why, env.Paths = "found: "+shortList(envFiles, 3), envFiles
	}
	add(env)
	p := r.Personal
	var keyPaths []string
	for _, f := range p.Files {
		if !f.BuiltIn {
			rl := rule("files", "read", f.Path, false, false, "has keys")
			rl.Paths = []string{f.Path}
			add(rl)
			continue
		}
		keyPaths = append(keyPaths, f.Path)
	}
	if len(keyPaths) > 0 {
		rl := rule("files", "read", shortList(keyPaths, 3), false, true, "")
		rl.Paths = keyPaths
		add(rl)
	}
	for _, f := range p.Startup {
		if len(f.Secrets) > 0 {
			rl := rule("files", "read", f.Path, false, false, "sets "+names(f.Secrets))
			rl.Paths = []string{f.Path}
			add(rl)
		}
	}
	add(rule("files", "write", ".git/hooks, .git/config, .claude/", false, true, ""))
	add(rule("files", "write", "anything outside "+name, false, true, ""))

	// Programs, one line per toolchain, and websites, one line per package manager.
	type group struct {
		programs []string
	}
	groups := map[string]*group{}
	var groupOrder []string
	hostsFor := map[string][]string{}
	for _, h := range r.Repo.Hosts {
		hostsFor[h.For] = append(hostsFor[h.For], h.Name)
	}
	tools := map[string]bool{}
	for _, tool := range r.Repo.Tools {
		if tool.Path == "" || neverAllowed[tool.Name] {
			continue
		}
		tools[tool.Name] = true
		key := tool.Name
		if g, ok := toolGroups[tool.Name]; ok {
			key = g
		}
		if groups[key] == nil {
			groups[key] = &group{}
			groupOrder = append(groupOrder, key)
		}
		groups[key].programs = append(groups[key].programs, tool.Name)
	}
	add(shellRule())
	if rl, ok := basicToolsRule(r); ok {
		add(rl)
	}
	for _, key := range groupOrder {
		g := groups[key]
		rl := rule("programs", "run", strings.Join(g.programs, ", "), true, false, "")
		rl.Programs = g.programs
		add(rl)
	}
	// Maze and the engine are never allowed (neverAllowed): "anything else" covers them.
	add(rule("programs", "run", "anything else", false, true, ""))
	for _, key := range groupOrder {
		for _, prog := range groups[key].programs {
			hosts := hostsFor[prog]
			if len(hosts) == 0 {
				continue
			}
			rl := rule("websites", "reach", strings.Join(hosts, ", "), true, false, prog+" packages")
			rl.Hosts = hosts
			add(rl)
		}
	}
	add(rule("websites", "reach", "anything else", false, true, ""))

	// Logins and secrets.
	if tools["git"] {
		add(commitRule())
	}
	for _, l := range logins {
		if tools[l.tool] {
			add(rule("logins", l.verb, l.service, false, true, ""))
		}
	}
	for _, e := range p.Env {
		if isLoginToken(e.Name) {
			add(rule("logins", "see", e.Name, false, true, "it could push or publish as you"))
			continue
		}
		if e.NeededBy != "" {
			add(rule("logins", "see", e.Name, true, false, displayName(e.NeededBy)+" signs in with it"))
			continue
		}
		add(rule("logins", "see", e.Name, false, false, ""))
	}
	// Claude Code's own permission rules: what they add (an allowed program or website, a blocked file) joins the
	// suggestions; the review says how each one is covered.
	tr := translateClaude(r, rules)
	rules = applyDenies(append(rules, tr.add...), tr)
	rules = sortRules(rules)
	setScopes(rules)
	return rules
}

// commitRule says how the agent's commits look; the pre-push check is said where it is installed.
func commitRule() Rule {
	return rule("logins", "commit", scope.AgentName, true, true, "signed with its own key")
}

// applyDenies switches off suggested programs and websites that Claude Code's own settings deny as a whole:
// Maze never suggests looser rules than the ones the person already wrote. A shared row loses just that member.
func applyDenies(rules []Rule, tr translation) []Rule {
	deny := func(get func(Rule) []string, set func(*Rule, []string), cat, value, src string) {
		for i, rl := range rules {
			list := get(rl)
			if rl.Category != cat || !rl.Allow || !slices.Contains(list, value) {
				continue
			}
			off := rule(cat, rl.Verb, value, false, false, "denied in "+src)
			set(&off, []string{value})
			if len(list) == 1 {
				rules[i] = off
			} else {
				set(&rules[i], slices.DeleteFunc(slices.Clone(list), func(s string) bool { return s == value }))
				fixValue(&rules[i], get(rules[i]))
				rules = append(rules, off)
			}
			return
		}
	}
	for p, src := range tr.blockProgram {
		deny(func(x Rule) []string { return x.Programs }, func(x *Rule, v []string) { x.Programs = v }, "programs", p, src)
	}
	for h, src := range tr.blockHost {
		deny(func(x Rule) []string { return x.Hosts }, func(x *Rule, v []string) { x.Hosts = v }, "websites", h, src)
	}
	return rules
}

// shellRule is the fixed "can run bash" row: Claude Code runs every command through it, so it is always allowed.
func shellRule() Rule {
	rl := rule("programs", "run", scope.Shell, true, true, "Claude Code's shell")
	rl.Programs = []string{scope.Shell}
	return rl
}

// ensureLocked adds the fixed rows a saved file is missing (a hand edit deleted one, or the person's own file was
// removed), so every screen always shows what Maze always enforces.
func ensureLocked(r Report, rules []Rule) []Rule {
	name := r.Workspace.Name
	has := func(match func(Rule) bool) bool { return slices.ContainsFunc(rules, match) }
	want := []struct {
		match func(Rule) bool
		rule  Rule
	}{
		{func(x Rule) bool {
			return x.Category == "files" && x.Verb == "read" && strings.HasPrefix(x.Value, "everything in ")
		},
			rule("files", "read", "everything in "+name, true, true, "")},
		{func(x Rule) bool { return x.Category == "files" && x.Verb == "read" && x.Value == "any .env file" },
			rule("files", "read", "any .env file", false, true, "")},
		{func(x Rule) bool {
			return x.Category == "files" && x.Verb == "read" && x.Always && strings.HasPrefix(x.Value, "~/")
		},
			rule("files", "read", "~/.ssh, ~/.aws and other keys", false, true, "")},
		{func(x Rule) bool {
			return x.Category == "files" && x.Verb == "write" && strings.HasPrefix(x.Value, ".git/hooks")
		},
			rule("files", "write", ".git/hooks, .git/config, .claude/", false, true, "")},
		{func(x Rule) bool {
			return x.Category == "files" && x.Verb == "write" && strings.HasPrefix(x.Value, "anything outside ")
		},
			rule("files", "write", "anything outside "+name, false, true, "")},
		{func(x Rule) bool { return x.Category == "programs" && x.Value == scope.Shell }, shellRule()},
		{func(x Rule) bool { return x.Category == "programs" && x.Value == "anything else" },
			rule("programs", "run", "anything else", false, true, "")},
		{func(x Rule) bool { return x.Category == "websites" && x.Value == "anything else" },
			rule("websites", "reach", "anything else", false, true, "")},
		{func(x Rule) bool { return x.Category == "logins" && x.Verb == "push" },
			rule("logins", "push", "GitHub", false, true, "")},
		{func(x Rule) bool { return x.Category == "logins" && x.Verb == "commit" }, commitRule()},
	}
	for _, w := range want {
		if !has(w.match) {
			rules = append(rules, w.rule)
		}
	}
	setScopes(rules)
	syncCommit(rules)
	return sortRules(rules)
}

// syncCommit makes the commit row say what is true: Claude Code commits (as itself) only when it may run git.
func syncCommit(rules []Rule) {
	git := false
	for _, rl := range rules {
		git = git || (rl.Category == "programs" && rl.Allow && slices.Contains(rl.Programs, "git"))
	}
	for i, rl := range rules {
		if rl.Category == "logins" && rl.Verb == "commit" {
			rules[i].Allow, rules[i].Why = git, "signed with its own key"
			if !git {
				rules[i].Why = "needs: run git"
			}
		}
	}
}

// basicToolsRule is the suggested "can run basic tools" rule, listing the ones installed here.
func basicToolsRule(r Report) (Rule, bool) {
	var found []string
	for _, p := range scope.BasicTools {
		if r.env.LookPath(p) != "" {
			found = append(found, p)
		}
	}
	if len(found) == 0 {
		return Rule{}, false
	}
	rl := rule("programs", "run", "basic tools", true, false, shortList(found, 3))
	rl.Programs = found
	return rl, true
}

// setScopes marks each rule personal (outside any project: paths under ~ and environment variables) or
// workspace (this project), which decides the file it is saved in.
func setScopes(rules []Rule) {
	for i := range rules {
		if rules[i].Scope == "" {
			rules[i].Scope = scopeOf(rules[i])
		}
	}
}

// scopeOf is a rule's scope; see setScopes.
func scopeOf(r Rule) string {
	if strings.HasPrefix(r.Value, "~") || strings.HasPrefix(r.Value, "/") || (r.Category == "logins" && r.Verb == "see") {
		return "personal"
	}
	return "workspace"
}

// sortRules keeps each category together, in the review's order, and the found order within one, with the
// "anything else" and "anything outside" lines last, so a rule added later doesn't land below them.
func sortRules(rules []Rule) []Rule {
	var out []Rule
	for _, c := range categories {
		for rank := 0; rank <= 9; rank++ {
			for _, rl := range rules {
				if rl.Category == c.key && rankOf(rl) == rank {
					out = append(out, rl)
				}
			}
		}
	}
	return out
}

// rankOf is a rule's place within its category, so the review reads the same on every run: what Claude Code can
// do first, then what is blocked, the catch-all "anything" lines last.
func rankOf(rl Rule) int {
	v := rl.Value
	switch {
	case strings.HasPrefix(v, "anything "):
		return 9
	case rl.Category == "files" && strings.HasPrefix(v, "everything in "):
		if rl.Verb == "read" {
			return 0
		}
		return 1
	case rl.Category == "files" && rl.Verb == "read" && v == "any .env file":
		return 2
	case rl.Category == "files" && rl.Verb == "read" && (strings.HasPrefix(v, "~") || strings.HasPrefix(v, "/")):
		if rl.Always {
			return 4
		}
		return 5
	case rl.Category == "files" && rl.Verb == "read":
		return 3
	case rl.Category == "files":
		return 6
	case rl.Category == "programs" && v == scope.Shell:
		return 0
	case rl.Category == "programs" && v == "basic tools":
		return 0
	case rl.Category == "logins":
		return map[string]int{"commit": 0, "push": 1, "publish": 2, "see": 3}[rl.Verb]
	}
	return 1
}

// title is a category's heading, and the note printed beside it.
func title(cat string) (string, string) {
	for _, c := range categories {
		if c.key == cat {
			return c.title, c.note
		}
	}
	return cat, ""
}

// phrase is how a rule reads after "can" or "can't" ("read files in shop", "download npm packages", "push to
// GitHub as you"), and the quiet words after it. The saved files keep the plain verb and value.
func phrase(rl Rule) (label, hint string) {
	v, hint := rl.Value, rl.Why
	switch rl.Category + "/" + rl.Verb {
	case "files/read", "files/write":
		if v == "any .env file" {
			return "read .env files", hint
		}
		if rl.Verb == "read" && strings.HasSuffix(v, "/") && !strings.Contains(v, ", ") {
			v = "the folder " + v
		}
		verb := "read"
		if rl.Verb == "write" {
			verb = "change"
		}
		switch {
		case strings.HasPrefix(v, "everything in "):
			return verb + " files in " + strings.TrimPrefix(v, "everything in "), hint
		case strings.HasPrefix(v, "anything outside "):
			return verb + " files outside " + strings.TrimPrefix(v, "anything outside "), hint
		}
		return verb + " " + v, hint
	case "programs/run":
		if v == "anything else" {
			return "run any other program", hint
		}
		return "run " + v, hint
	case "websites/reach":
		switch {
		case v == "anything else":
			return "connect to any other website", hint
		case strings.HasSuffix(hint, " packages"):
			return "download " + hint, v
		}
		return "connect to " + v, hint
	case "logins/push", "logins/publish":
		return rl.Verb + " to " + v + " as you", hint
	case "logins/see":
		return "see $" + v, hint
	case "logins/commit":
		return "commit as " + v, hint
	}
	return rl.Verb + " " + v, hint
}

// toRows turns rules into rule-list rows.
func toRows(rules []Rule) []ui.Row {
	allowed := map[string]bool{} // categories with something allowed: "any other" needs something to be other than
	for _, rl := range rules {
		allowed[rl.Category] = allowed[rl.Category] || rl.Allow
	}
	rows := make([]ui.Row, len(rules))
	for i, rl := range rules {
		group, note := title(rl.Category)
		label, hint := phrase(rl)
		if rl.Value == "anything else" && !allowed[rl.Category] {
			label, hint = strings.Replace(strings.Replace(label, "any other program", "programs", 1), "any other website", "websites", 1), "add one with + Add a rule"
		}
		was := rl.Suggested
		if rl.Added {
			was = rl.Allow // an added rule says "added", not "changed"
		}
		rows[i] = ui.Row{Group: group, Note: note, Label: label, Hint: hint, Allow: rl.Allow, Was: was, Locked: rl.Always}
	}
	return rows
}

// alwaysLines returns the review's ALWAYS summary: the fixed rules, merged into a few lines so they read as what
// Maze guarantees rather than as rows to switch. What it can always do comes first, on one line; then what it never
// can, a line per kind: files it can't read, files it can't change, logins it can't use, and everything not
// listed. Rows give each rule's current state (the commit rule follows git).
func alwaysLines(rules []Rule) func(rows []ui.Row) []ui.Fixed {
	return func(rows []ui.Row) []ui.Fixed {
		var can, read, change, logins, others []string
		var publish []string
		for i, rl := range rules {
			if !rl.Always || i >= len(rows) {
				continue
			}
			label := rows[i].Label
			if rl.Category == "logins" && rl.Verb == "commit" {
				label = "commit under its own name, not yours"
			}
			switch {
			case rows[i].Allow:
				can = append(can, label)
			case rl.Category == "files" && strings.HasPrefix(label, "read "):
				read = append(read, strings.TrimPrefix(label, "read "))
			case rl.Category == "files" && strings.HasPrefix(label, "change "):
				change = append(change, strings.TrimPrefix(label, "change "))
			case rl.Category == "logins" && (rl.Verb == "push" || rl.Verb == "publish"):
				publish = append(publish, rl.Value)
			case rl.Category == "logins":
				logins = append(logins, label)
			default:
				others = append(others, label)
			}
		}
		if len(publish) > 0 {
			logins = append([]string{"push or publish as you (" + strings.Join(publish, ", ") + ")"}, logins...)
		}
		// The approval gate: a change to the rules (by hand, a commit, an agent) waits for the person.
		others = append(others, "change its own rules: changes wait for your OK")
		if len(others) == 3 {
			others = []string{"run programs or reach websites not listed above", others[2]}
		}
		var out []ui.Fixed
		if len(can) > 0 {
			out = append(out, ui.Fixed{Allow: true, Text: strings.Join(can, " · ")})
		}
		for _, l := range []struct {
			prefix string
			items  []string
		}{
			{"read ", read}, {"change ", change},
		} {
			if len(l.items) > 0 {
				out = append(out, ui.Fixed{Text: l.prefix + strings.Join(l.items, ", ")})
			}
		}
		// One line each: "see $GITHUB_TOKEN" joined to another line read like "see also".
		for _, item := range append(logins, others...) {
			out = append(out, ui.Fixed{Text: item})
		}
		return out
	}
}

// liveHints returns the review's Update: before each draw it makes rows that depend on other rows say so. The
// commit row follows git; a switched row that breaks something says what.
func liveHints(rules []Rule) func(rows []ui.Row) {
	return func(rows []ui.Row) {
		git := false
		for i, rl := range rules {
			if rl.Category == "programs" && rows[i].Allow && slices.Contains(rl.Programs, "git") {
				git = true
			}
		}
		for i, rl := range rules {
			switch {
			case rl.Category == "logins" && rl.Verb == "commit":
				rows[i].Allow, rows[i].Was, rows[i].Hint = git, git, "signed with its own key"
				if !git {
					rows[i].Hint = "needs: run git"
				}
			case rl.Category == "logins" && rl.Verb == "see" && strings.Contains(rl.Why, "signs in"):
				rows[i].Changed = "can't sign in"
			case rl.Category == "programs" && slices.Contains(rl.Programs, "git"):
				rows[i].Changed = "can't commit or pull"
			case rl.Category == "files" && rl.Verb == "write" && strings.HasPrefix(rl.Value, "everything in "):
				rows[i].Changed = "read-only"
			case rl.Category == "files" && rl.Verb == "read" && strings.HasPrefix(rl.Why, "sets "):
				rows[i].Changed = "its secrets readable"
			}
		}
	}
}

// can is a rule's effect in words: "✓ can" or "✗ can't".
func can(t *ui.Term, allow bool) string {
	if allow {
		return t.Good("✓ can  ")
	}
	return t.Bad("✗ can't")
}

// errAddCancelled is returned when the person backs out of adding a rule.
var errAddCancelled = errors.New("add cancelled")

// addRule is its own page, under the same header as the review: what kind of rule, then its name. A name that
// can't work (a URL's extra parts are dropped first, so a pasted link works) says why and asks again; an empty
// answer or Back returns errAddCancelled. have are the rules already on the review, so nothing is added twice.
func addRule(ctx context.Context, t *ui.Term, r Report, header func(), have []Rule) (Rule, error) {
	name := r.Workspace.Name
	kinds := []ui.Choice{
		{Label: "Let it run a program", Hint: "make, docker, cargo"},
		{Label: "Let it reach a website", Hint: "api.github.com"},
		{Label: "Keep it out of a file", Hint: "config/prod.json"},
		{Label: "Back"},
	}
	// Each kind's own page: the question, what to type, and an example, like gh's and npm's prompts.
	asks := []struct{ question, help, prompt string }{
		{"Which program should Claude Code be able to run?", "Its name, as you'd type it in a terminal: make, docker, cargo.", "Program"},
		{"Which website should Claude Code be able to reach?", "A name like api.github.com, or paste a link. It connects over HTTPS.", "Website"},
		{"Which file or folder should Claude Code stay out of?", "A path in " + name + ", like config/prod.json or secrets/. It won't read or change it.", "Path"},
	}
	page := func(title string) {
		t.Clear()
		header()
		t.Println("  " + t.Accent(t.Bold("ADD A RULE")) + title)
		t.Println()
	}
	for {
		page("")
		kind, err := t.Select(ctx, kinds)
		if err != nil {
			return Rule{}, err
		}
		if kind >= len(asks) {
			return Rule{}, errAddCancelled
		}
		a, note := asks[kind], ""
		for {
			page(t.Dim("  ·  " + kinds[kind].Label))
			t.Println("  " + t.Bold(a.question))
			t.Println("  " + t.Dim(a.help))
			t.Println()
			if note != "" {
				t.Println("  " + t.Bad("✗") + " " + note)
				t.Println()
			}
			t.Println("  " + t.Dim("Enter to add · Esc to go back"))
			t.Println()
			value, err := t.Ask(ctx, "  "+a.prompt+":")
			if err != nil {
				return Rule{}, err
			}
			if value = strings.TrimSpace(value); value == "" {
				break // back to the kinds
			}
			var rl Rule
			switch kind {
			case 0:
				rl, note = addProgram(r, value)
			case 1:
				rl, note = addWebsite(value)
			default:
				rl, note = addFile(r, r.Workspace.Root, value)
			}
			if note == "" {
				for _, h := range have {
					if h.Category == rl.Category && h.Allow == rl.Allow && covers(h, rl) {
						label, _ := phrase(h)
						note = "Already on the list: " + sentenceCan(h.Allow) + " " + label + "."
					}
				}
			}
			if note == "" {
				return rl, nil
			}
		}
	}
}

// printRules prints rules by category, for screens without the list (piped output, show commands), in the same
// columns as the review.
func printRules(t *ui.Term, rules []Rule) { printRulesMarked(t, rules, nil) }

// printRulesMarked is printRules with a note in place of the hint for some rules (by Key), such as "not approved
// yet" for a rule the shared file added that the person hasn't approved.
func printRulesMarked(t *ui.Term, rules []Rule, notes map[string]string) {
	w, anyFixed := 0, false
	for _, rl := range rules {
		label, _ := phrase(rl)
		w = max(w, len([]rune(label)))
		anyFixed = anyFixed || rl.Always
	}
	w = min(w, 40) // a pasted path mustn't push every hint off the line
	cat := ""
	for _, rl := range rules {
		if rl.Category != cat {
			if cat != "" {
				t.Println()
			}
			cat = rl.Category
			heading, note := title(cat)
			if note != "" {
				note = "  " + t.Dim(note)
			}
			t.Println("  " + t.Bold(strings.ToUpper(heading)) + note)
		}
		label, hint := phrase(rl)
		if n, ok := notes[rl.Key()]; ok {
			hint = t.Accent(n)
		} else {
			hint = t.Dim(hint)
		}
		shown := label
		// "fixed" has a column of its own, so it never runs into the hint.
		col := ""
		if anyFixed {
			col = "       "
			if rl.Always {
				col = t.Dim("fixed") + "  "
				shown = t.Dim(label)
			}
		}
		line := "    " + can(t, rl.Allow) + "  " + shown + strings.Repeat(" ", max(w-len([]rune(label)), 0)) + "  " + col + hint
		t.Println(strings.TrimRight(line, " "))
	}
}

// sentenceCan is "can" or "can't" without color, for a sentence.
func sentenceCan(allow bool) string {
	if allow {
		return "can"
	}
	return "can't"
}
