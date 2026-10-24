// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ReportVersion is the version of `maze init --json`'s output. Bump it when a field changes meaning or
// goes away; adding a field does not bump it.
const ReportVersion = 1

// Report is everything `maze init` found, in the order its steps ran.
type Report struct {
	Version   int            `json:"version"`
	Workspace scan.Workspace `json:"workspace"`
	Agents    []scan.Agent   `json:"agents"`
	Personal  scan.Personal  `json:"personal"`
	Repo      scan.Repo      `json:"repo"`
	// EnvFiles are the suggestions for the project's .env files: keep blocked, or keep readable.
	EnvFiles []scan.EnvAdvice `json:"env_files"`
	// Rules are what the review shows: suggested, then changed by the person.
	Rules []Rule `json:"rules,omitempty"`
	// Claude are the permission rules in Claude Code's own settings, read with the person's permission.
	Claude []scan.ClaudeRule `json:"claude_rules,omitempty"`
	// Reads lists every file the look around opened, or meant to and skipped (only in iCloud, a link, the time
	// limit), so --explain can show exactly what Maze read.
	Reads []scan.ReadNote `json:"files_read,omitempty"`
	// ClaudeProblem says why Claude Code's settings couldn't be read (a link, not JSON); the setup goes on.
	ClaudeProblem string `json:"claude_rules_problem,omitempty"`
	// Scanned reports whether Maze looked around (outside the project and in it); the guided setup asks first.
	Scanned bool `json:"scanned"`
	// Home is the home directory, to show paths as ~/…; not part of the JSON output.
	Home string `json:"-"`
	// env is what the scans read from the machine, kept so the project can be scanned later.
	env scan.Env
	// edits is how many effects the person changed on the review, for the line after saving.
	edits int
	// personalLoaded is set when Rules came from the saved files, so they hold every personal rule and replace
	// the personal file on save (a rule removed stays removed).
	personalLoaded bool
	// keepFile approves the project's rules file as it is on disk instead of writing it again (approving a
	// change someone committed).
	keepFile bool
	// loaded is the project's rules file as it was read for this review; a save refuses to overwrite a file that
	// changed since (a maze allow in another terminal), rather than lose that change.
	loaded []byte
}

// initOptions are `maze init`'s flags.
type initOptions struct {
	explain bool
	asJSON  bool
	yes     bool
	noColor bool
	dir     string
	// fromMenu is set when the start menu launched init: the banner is already on screen.
	fromMenu bool
}

// cmdInit is `maze init`: find the workspace and the agent, scan what an agent could reach everywhere and in
// this project, and propose rules. The first time it walks the person through three pages; a project set up
// before opens its saved rules. Saving writes the rules files and the engine contract.
func cmdInit() Command {
	var o initOptions
	return Command{
		Name:    "init",
		Summary: "Set up rules for this project",
		Usage:   "[flags]",
		Flags: func(fs *flag.FlagSet) {
			fs.StringVar(&o.dir, "C", ".", "set up the project in `<dir>` instead of the current folder")
			fs.BoolVar(&o.explain, "explain", false, "print what Maze found and why it suggests each rule")
			fs.BoolVar(&o.asJSON, "json", false, "print what Maze found as JSON")
			fs.BoolVar(&o.yes, "yes", false, "read once and save the suggested rules without asking (writes the rules, a pre-push check and a commit key)")
			fs.BoolVar(&o.noColor, "no-color", false, "plain text (same as NO_COLOR=1)")
		},
		Run: func(ctx context.Context, fs *flag.FlagSet, s Streams) int {
			if fs.NArg() > 0 {
				fmt.Fprintln(s.Err, "maze init takes no arguments; use -C <dir> to set up another folder")
				return identity.ExitUsage
			}
			return runInit(ctx, o, s)
		},
	}
}

// runInit scans, then shows the findings the way the flags and the terminal ask for.
func runInit(ctx context.Context, o initOptions, s Streams) int {
	code, _ := initFlow(ctx, o, s, nil)
	return code
}

// initFlow is runInit for a caller that may already hold the Term (the start menu); t is nil otherwise. back
// reports that the person picked Back, so the menu should show again. A project set up before goes to its
// saved rules (after an approval check when they changed); a new one gets the guided setup. Start saves.
func initFlow(ctx context.Context, o initOptions, s Streams, t *ui.Term) (code int, back bool) {
	if o.yes && (o.asJSON || o.explain) {
		fmt.Fprintln(s.Err, "maze init: --yes saves, --json and --explain only print. Run them one at a time.")
		return identity.ExitUsage, false
	}
	env, err := scan.FromOS()
	if err != nil {
		return fail(s, "maze init", err), false
	}
	rep, err := buildReport(ctx, o.dir, env, false)
	if err != nil {
		return fail(s, "maze init", err), false
	}
	if t == nil {
		t = newTerm(s, ui.Options{NoColor: o.noColor})
	}
	savedRules, hasSaved, err := loadSaved(rep)
	if err != nil {
		return fail(s, "maze init", err), false
	}
	rep.personalLoaded = hasSaved
	if hasSaved {
		rep.loaded, _ = scope.CurrentWorkspace(rep.Workspace.Root)
	}
	interactive := t.Interactive() && !o.yes && !o.asJSON && !o.explain
	if msg := projectProblem(rep.Workspace.Root, rep.Home); msg != "" && !interactive {
		return fail(s, "maze init", &projectError{msg}), false
	}
	if !interactive {
		// Flags and piped runs are the person's go-ahead to look through the project.
		if rep, err = lookAround(ctx, rep); err != nil {
			return fail(s, "maze init", err), false
		}
		rep.Rules = buildRules(rep, true)
		if hasSaved {
			rep.Rules = savedRules
		}
	}
	switch {
	case o.asJSON:
		enc := json.NewEncoder(s.Out)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			return fail(s, "maze init", err), false
		}
		return identity.ExitOK, false
	case o.explain:
		renderExplain(s.Out, rep)
		return identity.ExitOK, false
	}
	var accepted bool
	switch {
	case interactive && hasSaved:
		t.Enter()
		rep.Rules = savedRules
		rep, accepted, err = reviewSaved(ctx, t, rep, o.fromMenu)
	case interactive:
		t.Enter()
		rescan := func(ctx context.Context, dir string) (Report, error) { return buildReport(ctx, dir, env, false) }
		rep, accepted, err = guided(ctx, t, rep, o.fromMenu, rescan, lookAroundShowing)
	default:
		if hasSaved {
			// --yes never approves rules that changed since a person approved them: that takes a person.
			a, aerr := scope.CheckApproval(rep.Home, rep.Workspace.Root)
			if aerr == nil && !a.Same {
				why := "changed since you approved them"
				if !a.Recorded {
					why = "aren't approved on this computer yet"
				}
				fmt.Fprintf(s.Err, "maze init: the rules for %s %s. Run maze in a terminal to review them.\n", rep.Workspace.Name, why)
				return identity.ExitFinding, false
			}
			if !o.yes {
				// Set up and approved: nothing to do without a person, and nothing wrong.
				fmt.Fprintf(s.Out, "%s is set up and its rules are approved. To change them, run maze in a terminal.\n", rep.Workspace.Name)
				return identity.ExitOK, false
			}
		}
		accepted, err = compact(ctx, t, rep, o.yes)
	}
	if errors.Is(err, errBack) {
		return identity.ExitOK, true
	}
	t.Leave()
	switch {
	case errors.Is(err, context.Canceled):
		t.Println("  Stopped. Nothing changed.")
		return exitInterrupted, false
	case errors.Is(err, errNotApproved):
		t.Println("  Not approved yet. The rules you approved stay saved. Run " + t.Accent("maze") + " here to decide.")
		return identity.ExitFinding, false
	case errors.Is(err, errKeep):
		t.Println("  Nothing changed.")
		return identity.ExitOK, false
	case errors.Is(err, errKeepApproved):
		t.Println("  " + t.Good("✓") + " Approved and saved. Nothing else changed.")
		return identity.ExitOK, false
	case errors.Is(err, errWrongFolder), errors.Is(err, ui.ErrQuit):
		t.Println("  Nothing saved. To set up later, run " + t.Accent("maze") + " in your project.")
		return identity.ExitOK, false
	case err != nil:
		return fail(s, "maze init", err), false
	}
	if !accepted || len(rep.Agents) == 0 {
		return finish(t, rep, accepted), false
	}
	res, err := save(ctx, rep, rep.Rules)
	if err != nil {
		fmt.Fprintf(s.Err, "maze init: saving the rules: %v\n", err)
		return identity.ExitError, false
	}
	return finishSaved(t, rep, res), false
}

// finishSaved is what stays on the terminal after saving: where the rules went, what isn't enforced yet, and
// what the engine's check found where it ran.
func finishSaved(t *ui.Term, rep Report, res saved) int {
	name := t.Bold(rep.Workspace.Name)
	if rep.Workspace.SetUp && rep.edits == 0 {
		t.Println("  " + t.Good("✓") + " No changes: the rules for " + name + " are saved as they were.")
	} else {
		note := ""
		switch {
		case rep.edits == 1:
			note = " (1 change by you)"
		case rep.edits > 1:
			note = fmt.Sprintf(" (%d changes by you)", rep.edits)
		}
		t.Println("  " + t.Good("✓") + " Saved rules for " + name + note)
		t.Println()
		t.Println("    .maze/workspace.yaml    " + t.Dim("this project's rules · commit it to share them"))
		t.Println("    ~/.maze/personal.yaml   " + t.Dim("your rules for every project"))
		t.Println("    .gitignore              " + t.Dim("ignores .maze/state/ (Claude Code's run files)"))
		if res.hook.Installed {
			t.Println("    .git/hooks/pre-push     " + t.Dim("asks before you push Claude Code's commits"))
		}
		t.Println("    ~/.maze/agent/          " + t.Dim("a key for Claude Code's own commits, not yours"))
	}
	if res.hook.Chained {
		t.Println("  " + t.Dim("  Your own pre-push hook still runs, right after Maze's check."))
	}
	if res.hook.Skipped != "" && res.hook.Skipped != "not a git repo" {
		t.Println("  " + t.Accent("!") + " No pre-push check: " + res.hook.Skipped + ".")
		if res.hook.Helper != "" {
			t.Println("    " + t.Dim("To add it, put this line last in your pre-push hook:"))
			t.Println("    " + res.hook.Helper)
		}
	}
	t.Println()
	// maze run doesn't exist yet: say plainly that nothing protects the person today, rather than let a saved
	// file look like protection.
	t.Println("  " + t.Accent("!") + " " + t.Bold("Not active yet.") + " Keep using Claude Code as usual: these rules apply once " + t.Accent("maze run") + " ships.")
	for _, g := range res.gaps {
		t.Println("    " + t.Dim("· "+g))
	}
	t.Println()
	t.Println("  " + t.Dim("Change them any time: ") + t.Accent("maze") + t.Dim("   Undo all of this: ") + t.Accent("maze workspace remove"))
	switch {
	case res.checked && res.note == "":
		t.Println()
		t.Println("  " + t.Good("✓") + fmt.Sprintf(" Engine check: %d of %d passed", res.passed, res.checks))
	case res.checked:
		t.Println()
		t.Println("  " + t.Bad("✗") + " " + res.note)
		return identity.ExitFinding
	case res.note != "":
		t.Println()
		t.Println("  " + t.Dim(res.note))
	}
	return identity.ExitOK
}

// finish ends the setup with a line that stays on the terminal: without an agent there is nothing to run;
// otherwise the answer.
func finish(t *ui.Term, rep Report, accepted bool) int {
	if len(rep.Agents) == 0 {
		t.Println("  " + t.Bad("✗") + " Maze needs Claude Code to run. Install it (https://code.claude.com/docs),")
		t.Println("    then run " + t.Accent("maze") + " again.")
		return identity.ExitFinding
	}
	if t.Interactive() {
		t.Println("  Nothing changed. Run " + t.Accent("maze") + " again any time.")
		return identity.ExitFinding
	}
	t.Println()
	t.Println("  " + t.Dim("Not saved. Run maze init in a terminal, or add --yes."))
	return identity.ExitFinding
}

// buildReport runs the steps that need no permission: find the project, find the agent, check whether this
// computer was set up before. With withScan it also looks around (lookAround); the guided setup asks first.
func buildReport(ctx context.Context, dir string, env scan.Env, withScan bool) (Report, error) {
	ws, err := scan.FindWorkspace(dir)
	if err != nil {
		return Report{}, &projectError{upperFirst(err.Error()) + "."}
	}
	setUp, err := scan.PersonalSetUp(env)
	if err != nil {
		return Report{}, err
	}
	r := Report{Version: ReportVersion, Workspace: ws, Agents: scan.FindAgents(env), Home: env.Home, env: env}
	r.Personal.SetUp = setUp
	if withScan {
		return lookAround(ctx, r)
	}
	return r, nil
}

// The parts of the one-time look, in the order they run and are shown.
const (
	lookHome = iota
	lookFiles
	lookTools
	lookClaude
)

// progress hears how the one-time look is going: part (lookHome, …) is running or done, with a short detail
// ("1,284 files · 2 .env files"). The reading page shows it; anything else passes nil.
type progress func(part int, done bool, detail string)

// lookAround is the one-time look the person allows: what the agent could reach outside the project
// (credentials, secret variables, shell startup files) and what the project holds and needs.
func lookAround(ctx context.Context, r Report) (Report, error) { return lookAroundShowing(ctx, r, nil) }

// lookAroundShowing is lookAround telling show how each part goes.
func lookAroundShowing(ctx context.Context, r Report, show progress) (out Report, err error) {
	if show == nil {
		show = func(int, bool, string) {}
	}
	var reads []scan.ReadNote
	seen := map[string]bool{} // a file read by two checks is listed once
	stop := scan.Record(func(n scan.ReadNote) {
		if !seen[n.Path] {
			seen[n.Path] = true
			reads = append(reads, n)
		}
	})
	defer stop()
	defer func() { out.Reads = reads }()
	show(lookHome, false, "")
	personal, err := scan.ScanPersonal(r.env, r.Agents)
	if err != nil {
		return r, fmt.Errorf("look outside the project: %w", err)
	}
	secrets := len(personal.Env)
	for _, f := range personal.Startup {
		secrets += len(f.Secrets)
	}
	show(lookHome, true, joinNonEmpty(count(len(personal.Files), "key folder"), count(secrets, "secret setting")))

	show(lookFiles, false, "")
	repo, err := scan.ScanRepoProgress(ctx, r.Workspace, r.env, func(n int) { show(lookFiles, false, thousands(n)+" so far") })
	if err != nil {
		return r, fmt.Errorf("look through the project: %w", err)
	}
	advice, err := scan.AdviseEnvFiles(r.Workspace.Root, repo.Secrets)
	if err != nil {
		return r, fmt.Errorf("look through the project: %w", err)
	}
	env, keys := 0, 0
	for _, f := range repo.Secrets {
		if f.BuiltIn {
			env++
		} else {
			keys++
		}
	}
	opened := 0
	for _, n := range reads {
		if n.Opened && strings.HasPrefix(n.Path, r.Workspace.Root+string(filepath.Separator)) {
			opened++
		}
	}
	inCloud := ""
	if repo.InCloud > 0 {
		inCloud = thousands(repo.InCloud) + " only in iCloud"
	}
	show(lookFiles, true, joinNonEmpty(thousands(repo.Files)+" names", checkedFor(opened), count(env, ".env file"), inCloud))

	var tools []string
	for _, tool := range repo.Tools {
		if tool.Path != "" {
			tools = append(tools, tool.Name)
		}
	}
	show(lookTools, true, orNone(shortList(tools, 5), "none found"))

	r.Personal, r.Repo, r.EnvFiles, r.Scanned = personal, repo, advice, true
	// A settings file Maze can't read is said on the review, not fatal: the rest of the setup still holds.
	var problems []string
	r.Claude, problems = scan.ClaudeRules(r.env, r.Workspace.Root)
	r.ClaudeProblem = scope.Clean(strings.Join(problems, "; "))
	// Masked where it is read, so no output (--explain, --json) ever holds a token from a rule, and
	// cleaned of control characters, so a rule can't rewrite the screen.
	for i := range r.Claude {
		r.Claude[i].Rule = scope.Clean(maskSecrets(r.Claude[i].Rule))
	}
	detail := orNone(count(len(r.Claude), "rule"), "none")
	if len(problems) > 0 {
		detail = joinNonEmpty(detail, count(len(problems), "file skipped"))
	}
	show(lookClaude, true, detail)
	return r, nil
}

// checkedFor is "179 checked for tools", or "" when no file was opened.
func checkedFor(opened int) string {
	if opened == 0 {
		return ""
	}
	return thousands(opened) + " checked for tools"
}

// count is "1 key folder" or "3 key folders", or "" for none.
func count(n int, what string) string {
	switch n {
	case 0:
		return ""
	case 1:
		return "1 " + what
	}
	if strings.HasSuffix(what, " skipped") {
		return thousands(n) + " " + strings.Replace(what, "file", "files", 1)
	}
	return thousands(n) + " " + what + "s"
}

// thousands writes n with commas: 1,284.
func thousands(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// joinNonEmpty joins the parts that say something with " · ".
func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return orNone(strings.Join(out, " · "), "nothing secret found")
}

// orNone is s, or none when s is empty.
func orNone(s, none string) string {
	if s == "" {
		return none
	}
	return s
}

// upperFirst capitalizes s's first letter, for an error that starts a sentence.
func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
