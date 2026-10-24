// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
)

// agentNames are the names people know the agents by.
var agentNames = map[string]string{"claude": "Claude Code"}

// displayName is an agent's product name, or its id when Maze has none for it.
func displayName(id string) string {
	if n, ok := agentNames[id]; ok {
		return n
	}
	return id
}

// tildePath shows path as ~/… when it is under home.
func tildePath(home, path string) string {
	if home == "" {
		return path
	}
	rel, err := filepath.Rel(home, path)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return path
	}
	return "~/" + filepath.ToSlash(rel)
}

// expandHome turns a leading ~ into the home folder, the way a shell would.
func expandHome(home, path string) string {
	if home == "" {
		return path
	}
	if path == "~" {
		return home
	}
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, path[2:])
	}
	return path
}

// errWrongFolder is returned when the person cancels the setup.
var errWrongFolder = errors.New("setup cancelled")

// errKeep is returned when the person leaves the review of saved rules without saving.
var errKeep = errors.New("review left without saving")

// errBack is returned when the person picks Back on the first page: the start menu shows again.
var errBack = errors.New("back to the start menu")

// rescanFunc builds the report for another folder: the first page's "a different project".
type rescanFunc func(ctx context.Context, dir string) (Report, error)

// projectScanner looks around once the person allows it, telling show how each part goes.
type projectScanner func(ctx context.Context, r Report, show progress) (Report, error)

// The three pages of the guided setup.
const (
	pageProject = iota + 1
	pagePermission
	pageReview
	pages = pageReview
)

// guided is the first run on a machine: three pages, each replacing the last on a full screen. Project (the
// agent found, which project), Permission (read once, or keep the basics), Review (everything found, then
// start, go back or cancel). fromMenu is set when the start menu launched it, which adds Back to the first page.
// It returns the report of the project actually chosen.
func guided(ctx context.Context, t *ui.Term, r Report, fromMenu bool, rescan rescanFunc, look projectScanner) (Report, bool, error) {
	page, looked := pageProject, false
	var rules, suggested []Rule
	for {
		switch page {
		case pageProject:
			next, err := showProject(ctx, t, r, fromMenu, rescan)
			if err != nil {
				return r, false, err
			}
			r, page, rules = next, pagePermission, nil
		case pagePermission:
			choice, err := showPermission(ctx, t, r)
			if err != nil {
				return r, false, err
			}
			switch choice {
			case permBack:
				page = pageProject
				continue
			case permCancel:
				return r, false, errWrongFolder
			case permLook:
				if !looked || rules == nil {
					if r, err = showReading(ctx, t, r, look); err != nil {
						return r, false, err
					}
					rules = buildRules(r, true)
					suggested = slices.Clone(rules)
				}
				looked = true
			case permSkip:
				if looked || rules == nil {
					rules = buildRules(r, false)
					suggested = slices.Clone(rules)
				}
				looked = false
			}
			page = pageReview
		case pageReview:
			choice, edited, err := showReview(ctx, t, r, rules, suggested)
			rules = edited
			r.Rules = rules
			if err != nil {
				return r, false, err
			}
			switch choice {
			case reviewStart:
				r.edits = countEdits(suggested, rules)
				return r, true, nil
			case reviewBack:
				page = pagePermission
			default:
				return r, false, errWrongFolder
			}
		}
	}
}

// showProject is page 1: the agent Maze found, and which project the agent will work in. Picking "a different
// project" asks for its path on the same page; an empty answer goes back to the choice, a bad one is reported
// and asked again.
func showProject(ctx context.Context, t *ui.Term, r Report, fromMenu bool, rescan rescanFunc) (Report, error) {
	var note string
	for {
		t.Clear()
		t.Banner()
		t.Step(pageProject, pages, "Project")
		t.Println()
		t.Println("  Hello :) Let's set up Maze in 3 steps.")
		t.Println()
		for _, a := range r.Agents {
			t.Println("  " + t.Good("✓") + " " + t.Bold(displayName(a.Name)) + " found")
		}
		if len(r.Agents) == 0 {
			t.Println("  " + t.Bad("✗") + " No coding agent found. Maze runs Claude Code, which isn't installed here.")
		}
		t.Println()
		t.Println("  " + t.Bold("Which project will Claude Code work in?"))
		if note != "" {
			t.Println("  " + note)
		}
		t.Println()
		inHome := r.Home != "" && r.Workspace.Root == r.Home
		where := "  (current directory)"
		if r.Workspace.Started != "" && r.Workspace.Started != r.Workspace.Root {
			where = "  (the project you're in)"
		}
		if !r.Workspace.Git {
			where = strings.TrimSuffix(where, ")") + ", not a git repo)"
		}
		// The menu puts hints after its widest label ("A different project") and a 4-column margin.
		room := t.Width() - 4 - max(len([]rune(r.Workspace.Name)), len("A different project")) - 2 - len([]rune(where)) - 2
		here := ui.Choice{Label: r.Workspace.Name, Hint: fitPath(tildePath(r.Home, r.Workspace.Root), room) + where}
		if inHome {
			here = ui.Choice{Label: "Your home folder", Hint: "not a project"}
		}
		choices := []ui.Choice{here, {Label: "A different project", Hint: "type its path"}}
		if fromMenu {
			choices = append(choices, ui.Choice{Label: "Back"})
		}
		choices = append(choices, ui.Choice{Label: "Cancel"})
		at := 0
		if inHome || note != "" {
			at = 1 // after a bad path, stay on "A different project"
		}
		i, err := t.SelectAt(ctx, choices, at)
		if err != nil {
			if errors.Is(err, ui.ErrQuit) {
				return r, errWrongFolder
			}
			return r, err
		}
		switch choices[i].Label {
		case "A different project":
		case "Back":
			return r, errBack
		case "Cancel":
			return r, errWrongFolder
		default:
			if msg := projectProblem(r.Workspace.Root, r.Home); msg != "" {
				note = t.Bad("✗") + " " + msg
				continue
			}
			return r, nil
		}
		line, err := t.Ask(ctx, "  Project path (Enter to go back):")
		if err != nil {
			return r, err
		}
		if line == "" {
			note = ""
			continue
		}
		line = typedPath(line)
		next, err := rescan(ctx, expandHome(r.Home, line))
		if err != nil {
			note = t.Bad("✗") + " " + pathProblem(line, expandHome(r.Home, line))
			continue
		}
		if msg := projectProblem(next.Workspace.Root, next.Home); msg != "" {
			note = t.Bad("✗") + " " + msg
			continue
		}
		return next, nil
	}
}

// showReading is the page shown while Maze reads, once: each part appears as it starts and gets a ✓ and a short
// summary when it's done (the project's files count up as they're walked), so a large project never looks stuck.
// The finished summary stays a moment before the review replaces it.
func showReading(ctx context.Context, t *ui.Term, r Report, look projectScanner) (Report, error) {
	labels := []string{"Your home folder", r.Workspace.Name + "'s files", "Tools it uses", "Claude Code settings"}
	state := make([]string, len(labels)) // "" not started, "…" running, "✓" done
	detail := make([]string, len(labels))
	w := 0
	for _, l := range labels {
		w = max(w, len([]rune(l)))
	}
	draw := func() {
		t.Repaint()
		t.Step(pagePermission, pages, "Reading")
		t.Println()
		t.Println("  Reading once. " + t.Bold("Nothing leaves this computer."))
		t.Println()
		for i, l := range labels {
			switch state[i] {
			case "":
				t.Println("  " + t.Dim("· "+l))
			case "…":
				t.Println("  " + t.Accent("·") + " " + pad(l, w) + "   " + t.Dim(orNone(detail[i], "reading…")))
			default:
				t.Println("  " + t.Good("✓") + " " + pad(l, w) + "   " + t.Dim(detail[i]))
			}
		}
		t.ClearBelow()
	}
	t.Clear()
	draw()
	r, err := look(ctx, r, func(part int, done bool, d string) {
		state[part], detail[part] = "…", d
		if done {
			state[part] = "✓"
		}
		draw()
	})
	if err == nil {
		t.Pause(ctx, 900*time.Millisecond) // long enough to read what was found
	}
	return r, err
}

// Choices on the permission page.
const (
	permLook = iota
	permSkip
	permBack
	permCancel
)

// showPermission is page 2: Maze asks once to look around, in a few plain words.
func showPermission(ctx context.Context, t *ui.Term, r Report) (int, error) {
	t.Clear()
	t.Step(pagePermission, pages, "Permission")
	t.Println()
	t.Para("  " + t.Bold("Can Maze read these once to suggest rules?"))
	t.Para("  " + t.Dim("File names, plus a few files that show your tools. Secret values are never read. Nothing leaves this computer."))
	t.Println()
	// Like an app's permission screen: each place, then what is read there and why. The project comes with its
	// full path, the git projects inside it (found by folder name) and where the read stops, so nobody has to
	// guess whether a folder of repos means all of them.
	bullet := func(s string) { t.Para("    • " + s) }
	t.Para("  In " + t.Bold(fitPath(tildePath(r.Home, r.Workspace.Root), max(t.Width()-8, 20))))
	if nested := scan.NestedProjects(r.Workspace.Root); len(nested) > 0 {
		bullet(t.Accent("includes " + count(len(nested), "git project") + ": " + shortList(nested, 3)))
	}
	bullet("file names, " + strconv.Itoa(scan.ReadDepth) + " folders deep " + t.Dim("(skips "+strings.Join(scan.SkippedFolders()[:4], ", ")+")"))
	bullet("package.json and Python files: which tools it uses, whether it loads .env")
	bullet(".env files: setting names only")
	bullet(".claude/settings.json: your Claude Code rules")
	t.Println()
	t.Para("  In your home folder")
	bullet("whether ~/.ssh, ~/.aws and ~/.config/gh exist")
	bullet("setting names in ~/.zshrc, ~/.bashrc and your environment")
	bullet("~/.claude/settings.json: your Claude Code rules")
	t.Println()
	return t.Select(ctx, []ui.Choice{
		{Label: "Yes, read these once"},
		{Label: "Skip", Hint: "start with basic tools only"},
		{Label: "Back"},
		{Label: "Cancel"},
	})
}

// Choices on the review page.
const (
	reviewStart = iota
	reviewBack
	reviewCancel
)

// showReview is page 3: what Claude Code can and can't do, by category (files, programs, websites, logins and
// keys), one "✓ can …" or "✗ can't …" per line. Space or Enter on a rule switches it; rules Maze always
// enforces carry a lock and can't be switched. Start, Add a rule, Back and Cancel are rows below the rules.
// Without an agent there is nothing to start.
func showReview(ctx context.Context, t *ui.Term, r Report, rules, suggested []Rule) (int, []Rule, error) {
	return reviewPage(ctx, t, r, rules, func() { t.Step(pageReview, pages, "Review") }, false, suggested)
}

// reviewPage is the review with top drawn at the top: the step bar during setup, the project's name after.
// backLoses is set when Back leaves the page for good (back to the menu), so it asks first like Cancel does.
// baseline is what the person's changes are counted against (Maze's suggestion on a first run, kept across Back
// and forward); nil counts from the rules as the page opens.
func reviewPage(ctx context.Context, t *ui.Term, r Report, rules []Rule, top func(), backLoses bool, baseline []Rule) (int, []Rule, error) {
	header := func() {
		top()
		t.Println()
		// The header is kept short: on an 80x24 terminal every line here is a rule the person can't see. The Claude
		// Code line joins the title when both fit.
		title := t.Bold("What Claude Code can do in " + r.Workspace.Name)
		lines := claudeLines(t, r, rules)
		if len(lines) > 0 && ui.VisibleLen(title)+3+ui.VisibleLen(lines[0]) < t.Width() {
			title += "   " + lines[0]
			lines = lines[1:]
		}
		t.Println("  " + title)
		for _, line := range lines {
			t.Println("  " + line)
		}
		// Nothing enforces these yet: say so where the rules are chosen, not only after saving.
		t.Para("  " + t.Accent("!") + t.Dim(" Not active yet: Maze saves these now; they apply once maze run ships."))
		t.Println()
	}
	// Pages opened from the review (add a rule, leave without saving) ask one thing: the step bar only.
	subHeader := func() {
		top()
		t.Println()
	}
	focus, status := "", "" // the rule just added: the cursor starts on it, so the person sees where it went
	before := baseline
	if before == nil {
		before = slices.Clone(rules)
	}
	unsaved := func() int { return countEdits(before, rules) }
	for {
		t.Clear()
		if len(r.Agents) == 0 {
			top()
			t.Println()
			t.Println("  " + t.Bad("✗") + " Install Claude Code to start: https://code.claude.com/docs")
			t.Println()
			i, err := t.Select(ctx, []ui.Choice{{Label: "Back"}, {Label: "Cancel"}})
			return i + 1, rules, err
		}
		rows := toRows(rules)
		for j := range rules {
			rows[j].Focus = rules[j].Key() == focus
		}
		focus = ""
		i, err := t.RuleList(ctx, ui.List{Header: header, Rows: rows, Actions: []string{"Save rules", "+ Add a rule", "Back", "Cancel"},
			ActionHelp: []string{
				"Saves the rules, a pre-push check and a key for Claude Code's own commits. Nothing runs yet.",
				"Let Claude Code run a program or reach a website, or keep it out of a file.",
				"Back to the previous step.",
				"Leave without saving.",
			},
			Status: status, Footer: "↑/↓ move · Space switch · Enter choose · Esc back · q quit", Update: liveHints(rules), EscAction: 3,
			Always: alwaysLines(rules), AlwaysShort: "can't read .env files or your keys, push or publish as you, or run anything not listed · all: maze workspace show"})
		status = ""
		for j := range rows {
			if !rules[j].Always {
				rules[j].Allow = rows[j].Allow
			}
		}
		if err != nil {
			return reviewCancel, rules, err
		}
		if (i < 0 || i == 3 || (i == 2 && backLoses)) && unsaved() > 0 {
			// Leaving would throw away what the person switched or added: ask first.
			if keep, err := confirmLeave(ctx, t, subHeader, unsaved()); err != nil || keep {
				if err != nil {
					return reviewCancel, rules, err
				}
				continue
			}
		}
		switch i {
		case 0:
			return reviewStart, rules, nil
		case 1:
			rl, err := addRule(ctx, t, r, subHeader, rules)
			switch {
			case errors.Is(err, errAddCancelled), errors.Is(err, ui.ErrQuit):
			case err != nil:
				return reviewCancel, rules, err
			default:
				rules = sortRules(append(rules, rl))
				focus = rl.Key()
				label, _ := phrase(rl)
				status = "Added: " + sentenceCan(rl.Allow) + " " + label + ". Save rules to keep it."
			}
		case 2:
			return reviewBack, rules, nil
		default:
			return reviewCancel, rules, nil
		}
	}
}

// errNotApproved is returned when the person doesn't approve rules that changed since they last approved them.
var errNotApproved = errors.New("changed rules not approved")

// reviewSaved is a project set up before: if its rules changed since the person approved them (by hand, a
// teammate's commit, or an agent), it shows what changed and asks first; approving saves at once, so the rules
// the engine is given always match what was approved. Then the review, filled in with the saved rules.
func reviewSaved(ctx context.Context, t *ui.Term, r Report, fromMenu bool) (Report, bool, error) {
	a, err := scope.CheckApproval(r.Home, r.Workspace.Root)
	if err != nil {
		return r, false, err
	}
	notice, approved := "", false
	if !a.Same {
		choice, err := showApproval(ctx, t, r, a)
		if err != nil {
			return r, false, err
		}
		switch choice {
		case approveYes:
			if !a.Recorded && !r.Personal.SetUp {
				// A teammate's first approval: the rules came with the project, but the protections for this
				// person's own home (keys, startup files, secret settings) need the one-time look, as at setup.
				looked, err := lookAround(ctx, r)
				if err != nil {
					return r, false, err
				}
				var mine []Rule
				for _, rl := range buildRules(looked, true) {
					if rl.Scope == "personal" {
						mine = append(mine, rl)
					}
				}
				r.Rules = ensureLocked(r, append(onlyScope(r.Rules, "workspace"), mine...))
				r.personalLoaded = false
			}
			approving := r
			approving.keepFile = true
			if _, err := save(ctx, approving, r.Rules); err != nil {
				return r, false, err
			}
			notice, approved = "Approved and saved.", true
		case approveRestore:
			if err := scope.Restore(r.Home, r.Workspace.Root); err != nil {
				return r, false, err
			}
			rules, _, err := loadSaved(r)
			if err != nil {
				return r, false, err
			}
			r.Rules = rules
			r.loaded, _ = scope.CurrentWorkspace(r.Workspace.Root)
			notice = "Undone: these are the rules you approved."
		default:
			if fromMenu {
				return r, false, errBack
			}
			return r, false, errNotApproved
		}
	}
	before := slices.Clone(r.Rules)
	choice, rules, err := reviewPage(ctx, t, r, r.Rules, func() {
		t.Brand(r.Workspace.Name)
		if notice != "" {
			t.Println()
			t.Println("  " + t.Good("✓") + " " + notice)
		}
	}, fromMenu, nil)
	r.Rules = rules
	if err != nil {
		return r, false, err
	}
	switch choice {
	case reviewStart:
		r.edits = countEdits(before, rules)
		return r, true, nil
	case reviewBack:
		if fromMenu {
			return r, false, errBack
		}
	}
	if approved {
		return r, false, errKeepApproved
	}
	return r, false, errKeep
}

// errKeepApproved is errKeep after an approval was saved: leaving the review keeps that.
var errKeepApproved = errors.New("review left after approving")

// Choices on the approval page.
const (
	approveYes = iota
	approveRestore
	approveNo
)

// changeSource says when the rules file last changed and whether a git command (a pull, a checkout, a commit)
// happened at the same moment, so the person can tell a teammate's change from an edit on this computer (by hand
// or by an agent). It reads .git/logs/HEAD directly: Maze can't start git everywhere it runs.
func changeSource(root string, now time.Time) string {
	fi, err := os.Stat(filepath.Join(root, ".maze", "workspace.yaml"))
	if err != nil {
		return "Made by hand, a commit or an agent."
	}
	when := fi.ModTime()
	stamp := when.Format("Jan 2 15:04")
	if y, m, d := when.Date(); y == now.Year() && m == now.Month() && d == now.Day() {
		stamp = "today at " + when.Format("15:04")
	}
	if action, ok := gitActionNear(root, when); ok {
		return "Changed " + stamp + ", by git: " + action + "."
	}
	return "Changed " + stamp + ", not by a git command: edited on this computer, by hand or by an agent."
}

// gitActionNear is the last git action (its reflog message, "pull: Fast-forward") when it is one that rewrites
// files (a pull, checkout, merge, reset or rebase; a commit writes none) and git logged it within seconds after
// when, the moment the file was written. A hand edit after a git command is not it.
func gitActionNear(root string, when time.Time) (string, bool) {
	data, err := os.ReadFile(filepath.Join(root, ".git", "logs", "HEAD"))
	if err != nil {
		return "", false
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	head, msg, ok := strings.Cut(lines[len(lines)-1], "\t")
	if !ok {
		return "", false
	}
	f := strings.Fields(head)
	if len(f) < 2 {
		return "", false
	}
	sec, err := strconv.ParseInt(f[len(f)-2], 10, 64)
	if err != nil {
		return "", false
	}
	if strings.HasPrefix(msg, "commit") {
		return "", false
	}
	if d := time.Unix(sec, 0).Sub(when); d < -2*time.Second || d > 10*time.Second {
		return "", false
	}
	return scope.Clean(msg), true
}

// approvalRows are what the approval page lists, to read: any rule the file tried that Maze ignores, with why;
// then, for a file never approved here, its rules; otherwise each change in what is enforced, riskiest first, as
// a diff (+ added, - removed, ~ switched) saying what it would let Claude Code do.
func approvalRows(a scope.Approval) []ui.Row {
	var rows []ui.Row
	for _, ig := range a.Ignored {
		label, _ := phrase(ig.Rule)
		rows = append(rows, ui.Row{Group: "Ignored", Note: "the file asks, Maze keeps the rule as it is", Label: label,
			Hint: strings.TrimSuffix(ig.Reason, "."), Allow: ig.Rule.Allow, Was: ig.Rule.Allow})
	}
	if !a.Recorded {
		for _, r := range toRows(a.Rules) {
			r.Was = r.Allow
			rows = append(rows, r)
		}
		return rows
	}
	for _, c := range a.Changes {
		label, _ := phrase(c.Rule)
		diff := "+"
		switch c.Kind {
		case "removed":
			diff = "-"
		case "flipped":
			diff = "~"
		}
		rows = append(rows, ui.Row{Group: "Changes", Note: "not approved yet", Label: label, Hint: risk(c), Allow: c.Rule.Allow,
			Was: c.Rule.Allow, Diff: diff})
	}
	return rows
}

// risk says in a few words what a change lets Claude Code do, or what it takes away.
func risk(c scope.Change) string {
	gives := c.Rule.Allow != (c.Kind == "removed")
	if !gives {
		return "Claude Code could do less"
	}
	switch c.Rule.Category {
	case "websites":
		return "it could send your code there"
	case "programs":
		return "it could run this"
	case "files":
		if c.Rule.Verb == "write" {
			return "it could change these files"
		}
		return "it could read these files"
	case "logins":
		return "it could use this login"
	}
	return "Claude Code could do more"
}

// showApproval says what changed in the project's rules since the person approved them, or that a teammate's
// rules were never approved here, and asks what to do. The list scrolls like the review, so nothing is approved
// unseen; the cursor starts on Decide later, the choice that changes nothing.
func showApproval(ctx context.Context, t *ui.Term, r Report, a scope.Approval) (int, error) {
	name := r.Workspace.Name
	header := func() {
		t.Brand(name)
		t.Println()
		if a.Recorded {
			t.Println("  " + t.Bold("The rules for "+name+" changed since you approved them."))
			t.Para("  " + t.Dim(changeSource(r.Workspace.Root, time.Now())+" The rules you approved stay saved until you decide."))
		} else {
			t.Println("  " + t.Bold(name+" has rules you haven't approved on this computer."))
			t.Println("  " + t.Dim("From a teammate's commit, or the folder moved. Read them, then decide."))
			if !r.Personal.SetUp {
				t.Println("  " + t.Dim("Approving also checks your home folder once (names only) to protect your keys."))
			}
		}
		t.Println()
	}
	actions := []string{"Approve and save"}
	if a.Recorded {
		actions = append(actions, "Put back the rules I approved")
	}
	actions = append(actions, "Decide later")
	t.Clear()
	i, err := t.RuleList(ctx, ui.List{Header: header, Rows: approvalRows(a), Actions: actions, ReadOnly: true,
		FocusAction: len(actions), Footer: "↑/↓ to move · Enter to choose · q to decide later"})
	switch {
	case err != nil:
		return approveNo, err
	case i < 0 || i == len(actions)-1:
		return approveNo, nil
	case i == 0:
		return approveYes, nil
	}
	return approveRestore, nil
}

// shortList names up to n items and counts the rest: "a, b and 2 more".
func shortList(items []string, n int) string {
	if len(items) <= n {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:n], ", ") + fmt.Sprintf(" and %d more", len(items)-n)
}

// typedPath cleans up a path as people type or paste it: surrounding quotes, and the backslashes a terminal adds
// before spaces when a folder is dragged in from Finder.
func typedPath(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		s = s[1 : len(s)-1]
	}
	return strings.NewReplacer(`\ `, " ", `\(`, "(", `\)`, ")", `\'`, "'", `\&`, "&").Replace(s)
}

// pathProblem says in plain words why path can't be the project: missing, a file, or unreadable.
func pathProblem(typed, path string) string {
	fi, err := os.Stat(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "There's no folder at " + typed + "."
	case errors.Is(err, fs.ErrPermission):
		return "Maze isn't allowed to open " + typed + "."
	case err == nil && !fi.IsDir():
		return typed + " is a file. Type the project's folder."
	}
	return "Can't open " + typed + "."
}

// confirmLeave asks before throwing away n changes; keep is true when the person wants to go on editing.
func confirmLeave(ctx context.Context, t *ui.Term, header func(), n int) (keep bool, err error) {
	t.Clear()
	header()
	what := "1 change"
	if n != 1 {
		what = fmt.Sprintf("%d changes", n)
	}
	t.Println("  " + t.Bold("Leave without saving? Your "+what+" will be lost."))
	t.Println()
	i, err := t.Select(ctx, []ui.Choice{{Label: "Keep editing"}, {Label: "Leave without saving"}})
	if errors.Is(err, ui.ErrQuit) {
		// q or Esc here keeps editing: leaving takes a deliberate choice. Only the end of input leaves.
		return !t.InputEnded(), nil
	}
	return i == 0, err
}

// claudeLines say how Maze covers the rules in Claude Code's own settings, and any settings file it couldn't read.
func claudeLines(t *ui.Term, r Report, rules []Rule) []string {
	var out []string
	if line := claudeLine(t, r, rules); line != "" {
		out = append(out, line)
	}
	if r.ClaudeProblem != "" {
		out = append(out, t.Accent("!")+t.Dim(" Skipped: "+r.ClaudeProblem))
	}
	return out
}

// claudeLine is one line on how Maze covers the rules in Claude Code's own settings, or "" when there are none.
func claudeLine(t *ui.Term, r Report, rules []Rule) string {
	// The project's rules and the person's own denies count; an allow in ~/.claude/settings.json is meant for
	// every project, and leaving it out only makes this one stricter (--explain still lists each).
	var tr []Translation
	for _, x := range translateClaude(r, rules).lines {
		if !(x.Source == "~/.claude/settings.json" && x.List == "allow") {
			tr = append(tr, x)
		}
	}
	if len(tr) == 0 {
		return ""
	}
	open, wider := 0, 0
	for _, x := range tr {
		if !x.Covered {
			open++
		}
		if x.Wider {
			wider++
		}
	}
	if open == 0 && wider == 0 {
		return t.Good("✓") + t.Dim(fmt.Sprintf(" Includes your %d Claude Code rules", len(tr)))
	}
	if open == 0 {
		return t.Good("✓") + t.Dim(fmt.Sprintf(" Includes your %d Claude Code rules · %d wider here · ", len(tr), wider)) + t.Accent("maze init --explain")
	}
	return t.Accent("!") + t.Dim(fmt.Sprintf(" %d of your %d Claude Code rules work differently here · ", open, len(tr))) + t.Accent("maze init --explain")
}

// fitPath shortens path to n columns by dropping folders from the front: …/attention-span-ai/shop.
func fitPath(path string, n int) string {
	if len([]rune(path)) <= n || n < 8 {
		return path
	}
	parts := strings.Split(path, "/")
	out := parts[len(parts)-1]
	for i := len(parts) - 2; i >= 0; i-- {
		next := parts[i] + "/" + out
		if len([]rune(next))+2 > n {
			break
		}
		out = next
	}
	return "…/" + out
}

// names names the first of ns and counts the rest, short enough for a hint: "OPENAI_API_KEY and 1 more".
func names(ns []string) string {
	return shortList(ns, 1)
}

// compact is every later run, and any run without a person at the terminal: the review on one screen, then the
// question when someone can answer it.
func compact(ctx context.Context, t *ui.Term, r Report, yes bool) (bool, error) {
	t.Brand("setting up " + tildePath(r.Home, r.Workspace.Root))
	t.Println()
	for _, a := range r.Agents {
		t.Println("  " + t.Good("✓") + " " + t.Bold(displayName(a.Name)) + " found")
	}
	if len(r.Agents) == 0 {
		t.Println("  " + t.Bad("✗") + " No coding agent found. Maze runs Claude Code, which isn't installed here.")
		return false, nil
	}
	t.Println()
	if r.Rules == nil {
		r.Rules = buildRules(r, r.Scanned)
	}
	printRules(t, r.Rules)
	if lines := claudeLines(t, r, r.Rules); len(lines) > 0 {
		t.Println()
		for _, line := range lines {
			t.Println("  " + line)
		}
	}
	if yes {
		return true, nil
	}
	if !t.Interactive() {
		return false, nil
	}
	t.Println()
	return t.Confirm(ctx, "  Save these rules?")
}

// renderExplain prints every step's findings with the reason for each. It is plain text, for reading or for
// pasting into an issue.
func renderExplain(w io.Writer, r Report) {
	ws := r.Workspace
	fmt.Fprintln(w, "Step 1 · Find the project")
	fmt.Fprintf(w, "  folder   %s\n", tildePath(r.Home, ws.Root))
	fmt.Fprintf(w, "  name     %s  (from the folder name)\n", ws.Name)
	if ws.Git {
		fmt.Fprintln(w, "  git      yes  (found .git here; this is the repo's root)")
	} else {
		fmt.Fprintln(w, "  git      no  (no .git above; the folder itself is the project)")
	}
	if ws.SetUp {
		fmt.Fprintf(w, "  status   already set up  (%s exists)\n", scan.WorkspaceFile)
	} else {
		fmt.Fprintf(w, "  status   new  (no %s)\n", scan.WorkspaceFile)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Step 2 · Find the agent")
	if len(r.Agents) == 0 {
		fmt.Fprintln(w, "  none     no known agent on PATH  (looked for: claude)")
	}
	for _, a := range r.Agents {
		fmt.Fprintf(w, "  %-8s found at %s\n", displayName(a.Name), tildePath(r.Home, a.Path))
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Step 3 · Outside the project (saved in ~/.maze/personal.yaml)")
	if r.Personal.SetUp {
		fmt.Fprintf(w, "  status   already set up  (~/%s exists; shown for reference)\n", scan.PersonalFile)
	} else {
		fmt.Fprintf(w, "  status   new  (no ~/%s)\n", scan.PersonalFile)
	}
	if len(r.Personal.Files) == 0 {
		fmt.Fprintln(w, "  files    none of the engine's credential locations exist here")
	}
	for i, f := range r.Personal.Files {
		fmt.Fprintf(w, "  %-8s %-24s %s  → blocked by default\n", label(i, "files"), f.Path, f.Why)
	}
	if len(r.Personal.Env) == 0 {
		fmt.Fprintln(w, "  env      no variable name looks like a secret")
	}
	for i, f := range r.Personal.Startup {
		outcome := "→ no secrets set here"
		if len(f.Secrets) > 0 {
			outcome = "→ sets " + strings.Join(f.Secrets, ", ") + ": suggest blocking it"
		}
		fmt.Fprintf(w, "  %-8s %-24s %s\n", label(i, "startup"), f.Path, outcome)
	}
	for i, e := range r.Personal.Env {
		outcome := "→ Claude Code won't see it"
		if e.NeededBy != "" {
			outcome = "→ keep: " + displayName(e.NeededBy) + " signs in with it"
		}
		fmt.Fprintf(w, "  %-8s %-24s %s  %s\n", label(i, "env"), e.Name, e.Why, outcome)
	}
	fmt.Fprintln(w, "           (names only: no value was read)")

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Step 4 · In the project (saved in .maze/workspace.yaml)")
	if len(r.Repo.Secrets) == 0 {
		fmt.Fprintln(w, "  secrets  no file name looks like a secret")
	}
	advice := map[string]scan.EnvAdvice{}
	for _, a := range r.EnvFiles {
		advice[a.Path] = a
	}
	for i, f := range r.Repo.Secrets {
		outcome := "→ suggest blocking it"
		if f.BuiltIn {
			outcome = "→ always blocked"
		}
		if a, ok := advice[f.Path]; ok {
			names := "no settings"
			if len(a.Keys) > 0 {
				names = "settings: " + strings.Join(a.Keys, ", ")
			}
			switch {
			case a.Readable:
				outcome += " (" + names + "; all public, since " + a.LoadedBy + " puts " + a.Prefix + " settings in the browser: readable once the engine supports exceptions)"
			case a.LoadedBy != "":
				outcome += " (" + names + "; " + a.LoadedBy + " loads it, but " + strings.Join(a.NotPublic, ", ") + " isn't public)"
			default:
				outcome += " (" + names + ")"
			}
		}
		fmt.Fprintf(w, "  %-8s %-24s %s  %s\n", label(i, "secrets"), f.Path, f.Why, outcome)
	}
	if len(r.Repo.Tools) == 0 {
		fmt.Fprintln(w, "  tools    no toolchain file found")
	}
	for i, t := range r.Repo.Tools {
		outcome := "→ not installed, not proposed"
		if t.Path != "" {
			outcome = "→ found at " + tildePath(r.Home, t.Path) + ", propose: run " + t.Name
		}
		fmt.Fprintf(w, "  %-8s %-24s from %s  %s\n", label(i, "tools"), t.Name, strings.Join(t.From, ", "), outcome)
	}
	for i, h := range r.Repo.Hosts {
		fmt.Fprintf(w, "  %-8s %-24s needed by %s  → propose: reach\n", label(i, "hosts"), fmt.Sprintf("%s:%d", h.Name, h.Port), h.For)
	}
	if r.Repo.Cut {
		fmt.Fprintln(w, "  note     the scan stopped after 50000 entries, like the engine's own .env scan;")
		fmt.Fprintln(w, "           a secret file beyond that point is not listed here")
	}

	for i, l := range r.Repo.EnvLoaders {
		fmt.Fprintf(w, "  %-8s %-24s loads a .env file when the backend starts  → under Maze, Claude Code runs the backend without those settings\n", label(i, "backend"), l)
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Step 5 · Claude Code's own rules (its settings files)")
	switch {
	case r.ClaudeProblem != "":
		fmt.Fprintf(w, "  problem  %s\n", r.ClaudeProblem)
	case len(r.Claude) == 0:
		fmt.Fprintln(w, "  rules    none in .claude/settings.json, .claude/settings.local.json or ~/.claude/settings.json")
	}
	for i, x := range translateClaude(r, buildRules(r, true)).lines {
		how := "→ " + x.How
		if x.Covered {
			how = "→ Maze: " + x.How
		}
		fmt.Fprintf(w, "  %-8s %-5s %s  (%s)\n           %s\n", label(i, "rules"), x.List, x.Rule, x.Source, how)
	}

	renderReads(w, r)

	fmt.Fprintln(w)
	fmt.Fprintln(w, "Nothing was written. To review and save: maze init")
}

// renderReads says which files the look around opened and why, then which it meant to open and skipped, and
// why: the answer to "what did Maze read?". Files are grouped by why they were opened, with the first few named,
// so 300 Python files read as one line; --json lists every one. Names alone (the walk) aren't listed: every
// name was looked at.
func renderReads(w io.Writer, r Report) {
	shown := func(path string) string {
		if rel, err := filepath.Rel(r.Workspace.Root, path); err == nil && !strings.HasPrefix(rel, "..") {
			return scope.Clean(rel)
		}
		return scope.Clean(tildePath(r.Home, path))
	}
	type group struct {
		what, why string
		paths     []string
	}
	var opened, skipped []*group
	add := func(gs *[]*group, what, why, path string) {
		for _, g := range *gs {
			if g.what == what {
				g.paths = append(g.paths, shown(path))
				return
			}
		}
		*gs = append(*gs, &group{what, why, []string{shown(path)}})
	}
	n := 0
	for _, note := range r.Reads {
		if !note.Opened {
			add(&skipped, "file", note.Skipped, note.Path)
			continue
		}
		n++
		base := filepath.Base(note.Path)
		switch {
		case base == "package.json":
			add(&opened, "package.json file", "which tool builds the project", note.Path)
		case scan.IsEnvFile(base) || strings.HasSuffix(base, ".env"):
			add(&opened, ".env file", "setting names only; values are cut off unread", note.Path)
		case strings.HasSuffix(base, ".py"):
			add(&opened, "Python file", "does it load a .env file?", note.Path)
		case base == "settings.json" || base == "settings.local.json":
			add(&opened, "Claude Code settings file", "its permission rules", note.Path)
		default:
			add(&opened, "shell startup file", "names of exported settings", note.Path)
		}
	}
	list := func(gs []*group) {
		w0 := 0
		for _, g := range gs {
			w0 = max(w0, len(count(len(g.paths), g.what)))
		}
		for _, g := range gs {
			fmt.Fprintf(w, "  %-*s   %s\n", w0, count(len(g.paths), g.what), g.why)
			if len(g.paths) > 1 || filepath.Base(g.paths[0]) != strings.TrimSuffix(g.what, " file") {
				fmt.Fprintf(w, "  %-*s   %s\n", w0, "", firstFew(g.paths, 64))
			}
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Files Maze opened: %s. Every other file was only seen by its name.\n", thousands(n))
	list(opened)
	if len(skipped) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintln(w, "Files Maze skipped (not opened):")
		list(skipped)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Every path: maze init --json")
}

// label returns name for a group's first row and blank after it, so a group reads as one block.
func label(i int, name string) string {
	if i == 0 {
		return name
	}
	return ""
}

// firstFew names paths, as many as fit in about width characters (always at least one), then "… N more".
func firstFew(paths []string, width int) string {
	out := paths[0]
	k := 1
	for ; k < len(paths) && len(out)+2+len(paths[k]) <= width; k++ {
		out += ", " + paths[k]
	}
	if k < len(paths) {
		out += fmt.Sprintf(", … %s more", thousands(len(paths)-k))
	}
	return out
}

// countEdits counts the rows changed between before and after: switched, added or removed. A row counts once,
// however many programs or websites it lists.
func countEdits(before, after []Rule) int {
	was := map[string]bool{}
	for _, rl := range before {
		was[rl.Key()] = rl.Allow
	}
	n, seen := 0, map[string]bool{}
	for _, rl := range after {
		seen[rl.Key()] = true
		if allow, ok := was[rl.Key()]; !ok || allow != rl.Allow {
			n++
		}
	}
	for k := range was {
		if !seen[k] {
			n++
		}
	}
	return n
}
