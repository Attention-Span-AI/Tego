// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/maze/scan"
	"github.com/attention-span-ai/tego/internal/maze/scope"
	"github.com/attention-span-ai/tego/internal/maze/ui"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func streams(in string) (Streams, *bytes.Buffer, *bytes.Buffer) {
	var out, errOut bytes.Buffer
	return Streams{In: strings.NewReader(in), Out: &out, Err: &errOut}, &out, &errOut
}

func TestMainExitCodes(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want int
	}{
		{"no command prints help", nil, identity.ExitOK},
		{"help", []string{"help"}, identity.ExitOK},
		{"help for a command", []string{"help", "init"}, identity.ExitOK},
		{"version", []string{"--version"}, identity.ExitOK},
		{"unknown command", []string{"nope"}, identity.ExitUsage},
		{"planned but not built", []string{"run"}, identity.ExitUsage},
		{"unknown flag", []string{"init", "--nope"}, identity.ExitUsage},
		{"init takes no arguments", []string{"init", "extra"}, identity.ExitUsage},
		{"init -h", []string{"init", "-h"}, identity.ExitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, _, errOut := streams("")
			if got := Main(context.Background(), tt.args, s); got != tt.want {
				t.Errorf("Main(%v) = %d, want %d (stderr: %s)", tt.args, got, tt.want, errOut.String())
			}
		})
	}
}

func TestHelpMarksUnbuilt(t *testing.T) {
	s, out, _ := streams("")
	Main(context.Background(), []string{"help"}, s)
	got := out.String()
	for _, want := range []string{"Usage", "Get started", "Every day", "Manage", "init", "workspace show|remove", "Coming soon", "run · receipt", "maze help <command>"} {
		if !strings.Contains(got, want) {
			t.Errorf("help is missing %q\n%s", want, got)
		}
	}
	for _, line := range strings.Split(got, "\n") {
		if strings.Contains(line, "Set up rules") && strings.Contains(line, "soon") {
			t.Errorf("init is built but marked soon: %q", line)
		}
	}
	if strings.Contains(got, "\x1b[") {
		t.Errorf("help into a buffer printed color codes:\n%q", got)
	}
}

// fixture builds a project and a home folder and returns the report init would show for them.
func fixture(t *testing.T, withAgent bool) Report {
	t.Helper()
	root := filepath.Join(t.TempDir(), "demo")
	home := t.TempDir()
	bin := t.TempDir()
	files := map[string]os.FileMode{
		filepath.Join(root, ".git", "HEAD"):       0o644,
		filepath.Join(root, ".env"):               0o644,
		filepath.Join(root, "package.json"):       0o644,
		filepath.Join(root, "keys", "deploy.pem"): 0o644,
		filepath.Join(home, ".ssh", "id_ed25519"): 0o600,
		filepath.Join(bin, "node"):                0o755,
		filepath.Join(bin, "npm"):                 0o755,
		filepath.Join(bin, "git"):                 0o755,
	}
	if withAgent {
		files[filepath.Join(bin, "claude")] = 0o755
	}
	for p, mode := range files {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("never-printed-value\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	env := scan.Env{
		Home:    home,
		Path:    bin,
		Environ: []string{"GITHUB_TOKEN=ghp_never_printed", "ANTHROPIC_API_KEY=sk-never-printed"},
	}
	rep, err := buildReport(context.Background(), root, env, true)
	if err != nil {
		t.Fatal(err)
	}
	return rep
}

func TestRenderExplain(t *testing.T) {
	var out bytes.Buffer
	renderExplain(&out, fixture(t, true))
	s := out.String()
	for _, want := range []string{
		"Step 1 · Find the project", "git      yes", "Step 2 · Find the agent", "Claude Code",
		"Step 3 · Outside the project", "GITHUB_TOKEN", "→ Claude Code won't see it",
		"→ keep: Claude Code signs in with it", "(names only: no value was read)",
		"Step 4 · In the project", "keys/deploy.pem", "→ suggest blocking it", "registry.npmjs.org:443",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("explain is missing %q\n%s", want, s)
		}
	}
	if strings.Contains(s, "never-printed") {
		t.Errorf("explain printed a value:\n%s", s)
	}
}

func TestTildePath(t *testing.T) {
	tests := []struct{ home, path, want string }{
		{"/Users/sam", "/Users/sam/code/app", "~/code/app"},
		{"/Users/sam", "/opt/homebrew/bin/claude", "/opt/homebrew/bin/claude"},
		{"/Users/sam", "/Users/samuel/x", "/Users/samuel/x"},
		{"", "/a/b", "/a/b"},
	}
	for _, tt := range tests {
		if got := tildePath(tt.home, tt.path); got != tt.want {
			t.Errorf("tildePath(%q, %q) = %q, want %q", tt.home, tt.path, got, tt.want)
		}
	}
}

func TestStartMenu(t *testing.T) {
	tests := []struct {
		name, keys, says string
		want             int
	}{
		{"down to all commands", "\x1b[B\r", "Coming soon", identity.ExitOK},
		{"wraps up to quit", "\x1b[A\r", "", identity.ExitOK},
		{"q quits", "q", "", identity.ExitOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, out, _ := streams(tt.keys)
			saved := newTerm
			newTerm = func(s Streams, o ui.Options) *ui.Term { return ui.NewScripted(s.In, s.Out) }
			defer func() { newTerm = saved }()
			if got := Main(context.Background(), nil, s); got != tt.want {
				t.Errorf("exit = %d, want %d", got, tt.want)
			}
			if !strings.Contains(out.String(), "What would you like to do?") {
				t.Errorf("no menu:\n%s", out.String())
			}
			if tt.says != "" && !strings.Contains(out.String(), tt.says) {
				t.Errorf("missing %q:\n%s", tt.says, out.String())
			}
		})
	}
}

// noRescan fails every rescan: tests that never pick another folder.
func noRescan(ctx context.Context, dir string) (Report, error) {
	return Report{}, errors.New("no rescan in this test")
}

func TestExpandHome(t *testing.T) {
	for in, want := range map[string]string{"~": "/h", "~/code/x": "/h/code/x", "/abs": "/abs", "rel/x": "rel/x"} {
		if got := expandHome("/h", in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

// keepScan stands in for scanProject: the fixture's report was already scanned.
func keepScan(ctx context.Context, r Report, show progress) (Report, error) {
	r.Scanned = true
	return r, nil
}

func TestHelpBackToMenu(t *testing.T) {
	// Down to "Show all commands", Enter, then Enter on Back, then q at the menu.
	s, out, _ := streams("\x1b[B\r\rq")
	saved := newTerm
	newTerm = func(s Streams, o ui.Options) *ui.Term { return ui.NewScripted(s.In, s.Out) }
	defer func() { newTerm = saved }()
	if got := Main(context.Background(), nil, s); got != identity.ExitOK {
		t.Errorf("exit = %d", got)
	}
	if n := strings.Count(out.String(), "What would you like to do?"); n != 2 {
		t.Errorf("the menu showed %d times, want 2 (Back returns to it):\n%s", n, out.String())
	}
}

// On the review the cursor starts on the first rule that can change. These move it to an action: down to the
// last one (Cancel; the cursor stops there), then up.
var (
	toSave = strings.Repeat("\x1b[B", 60) + "\x1b[A\x1b[A\x1b[A"
	toAdd  = strings.Repeat("\x1b[B", 60) + "\x1b[A\x1b[A"
	toBack = strings.Repeat("\x1b[B", 60) + "\x1b[A"
)

func TestGuidedPages(t *testing.T) {
	tests := []struct {
		name    string
		keys    string
		agent   bool
		want    bool
		wantErr error
		says    []string
	}{
		{"enter through: this project, read once, start", "\r\r" + toSave + "\r", true, true, nil, []string{
			"Step 1 of 3", "Hello :)", "Claude Code found", "Which project will Claude Code work in?", "(current directory)",
			"Step 2 of 3", "Can Maze read these once", "Nothing leaves this computer", "folders deep", ".env files: setting names only",
			"In your home folder", "~/.ssh", "and your environment", "your Claude Code rules",
			"Step 3 of 3", "What Claude Code can do in demo", "FILES", "✓ can    read files in demo", "change files in demo",
			"✗ can't  read .env", "read keys/deploy.pem", "PROGRAMS", "run node, npm", "run git", "run programs or reach websites not listed above",
			"WEBSITES", "download npm packages", "registry.npmjs.org", "ALWAYS", "you can't switch these", "Not active yet: Maze saves these now",
			"YOUR LOGINS & KEYS", "you keep using them", "push or publish as you (GitHub, npm",
			"Save rules", "+ Add a rule", "~/.ssh", "[✓]  run node, npm", "see $GITHUB_TOKEN", "see $ANTHROPIC_API_KEY",
		}},
		{"cancel on the review", "\r\rq", true, false, errWrongFolder, nil},
		{"review back to permission, then skip and start", "\r\r" + toBack + "\r\x1b[B\r" + toSave + "\r", true, true, nil, []string{"read .env files", "ALWAYS"}},
		{"permission back to project, then through", "\r\x1b[B\x1b[B\r\r\r" + toSave + "\r", true, true, nil, nil},
		{"q on the permission page", "\rq", true, false, ui.ErrQuit, nil},
		{"cancel on the project page", "\x1b[B\x1b[B\r", true, false, errWrongFolder, nil},
		{"no agent: cancel on the review", "\r\r\x1b[B\r", false, false, errWrongFolder, []string{"No coding agent found", "Install Claude Code"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			_, got, err := guided(context.Background(), ui.NewScripted(strings.NewReader(tt.keys), &out), fixture(t, tt.agent), false, noRescan, keepScan)
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("err = %v, want %v\n%s", err, tt.wantErr, out.String())
			}
			if got != tt.want {
				t.Errorf("accepted = %v, want %v", got, tt.want)
			}
			for _, want := range tt.says {
				if !strings.Contains(out.String(), want) {
					t.Errorf("missing %q\n%s", want, out.String())
				}
			}
			if s := out.String(); strings.Contains(s, "never-printed") || strings.Contains(s, "ghp_") || strings.Contains(s, "sk-never") {
				t.Errorf("a value was printed:\n%s", s)
			}
		})
	}
}

func TestHomeFolderStartsOnDifferentProject(t *testing.T) {
	rep := fixture(t, true)
	rep.Home = rep.Workspace.Root
	var out bytes.Buffer
	// Enter picks "A different project" in the home folder; an empty path goes back; then the input ends.
	_, _, err := guided(context.Background(), ui.NewScripted(strings.NewReader("\r\n"), &out), rep, false, noRescan, keepScan)
	if !errors.Is(err, errWrongFolder) {
		t.Fatalf("err = %v, want errWrongFolder", err)
	}
	if !strings.Contains(out.String(), "Your home folder") || !strings.Contains(out.String(), "Project path (Enter to go back):") {
		t.Errorf("Enter in the home folder did not start on a different project:\n%s", out.String())
	}
}

func TestDifferentProject(t *testing.T) {
	first, second := fixture(t, true), fixture(t, true)
	asked := ""
	rescan := func(ctx context.Context, dir string) (Report, error) {
		asked = dir
		if dir == "/nope" {
			return Report{}, errors.New("no such folder")
		}
		return second, nil
	}
	keys := "\x1b[B\r/nope\n\r" + second.Workspace.Root + "\n\r" + toSave + "\r" // after the error the cursor stays on "A different project"
	var out bytes.Buffer
	got, ok, err := guided(context.Background(), ui.NewScripted(strings.NewReader(keys), &out), first, true, rescan, keepScan)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v\n%s", ok, err, out.String())
	}
	if asked != second.Workspace.Root || got.Workspace.Root != second.Workspace.Root {
		t.Errorf("set up %s (asked %s), want %s", got.Workspace.Root, asked, second.Workspace.Root)
	}
	if !strings.Contains(out.String(), "There's no folder at /nope.") {
		t.Errorf("a bad path was not reported:\n%s", out.String())
	}
}

func TestProjectPageBack(t *testing.T) {
	var out bytes.Buffer
	_, _, err := guided(context.Background(), ui.NewScripted(strings.NewReader("\x1b[B\x1b[B\r"), &out), fixture(t, true), true, noRescan, keepScan)
	if !errors.Is(err, errBack) {
		t.Fatalf("Back from the menu: err = %v, want errBack", err)
	}
	out.Reset()
	_, ok, err := guided(context.Background(), ui.NewScripted(strings.NewReader("\x1b[B\r\n\r\r"+toSave+"\r"), &out), fixture(t, true), false, noRescan, keepScan)
	if err != nil || !ok {
		t.Fatalf("empty path then through: ok=%v err=%v\n%s", ok, err, out.String())
	}
}

func TestSkipNeverReads(t *testing.T) {
	read := false
	look := func(ctx context.Context, r Report, show progress) (Report, error) {
		read = true
		return r, nil
	}
	var out bytes.Buffer
	if _, _, err := guided(context.Background(), ui.NewScripted(strings.NewReader("\r\x1b[B\r"+toSave+"\r"), &out), fixture(t, true), false, noRescan, look); err != nil {
		t.Fatal(err)
	}
	if read {
		t.Error("Skip still read the project")
	}
}

func TestCompactWithoutTerminal(t *testing.T) {
	var out bytes.Buffer
	term := ui.NewPlain(strings.NewReader(""), &out, 80)
	accepted, err := compact(context.Background(), term, fixture(t, true), false)
	if err != nil || accepted {
		t.Fatalf("compact with nobody at the terminal = %v, %v", accepted, err)
	}
	for _, want := range []string{"setting up", "Claude Code found", "FILES", "PROGRAMS", "node, npm", "WEBSITES", "YOUR LOGINS & KEYS"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q\n%s", want, out.String())
		}
	}
	if accepted, _ := compact(context.Background(), term, fixture(t, true), true); !accepted {
		t.Error("--yes did not accept")
	}
}

func TestReviewFlipAndAdd(t *testing.T) {
	// Project, read once. On the review: to Save, up to the last rule that can change (see $ANTHROPIC_API_KEY;
	// $GITHUB_TOKEN is fixed, so the cursor skips it) and switch it; down twice to "+ Add a rule"; add the
	// program make. The cursor comes back on make; then Save.
	keys := "\r\r" + toSave + "\x1b[A" + " " + "\x1b[B\x1b[B\r" + "\r" + "make\n" + toSave + "\r"
	var out bytes.Buffer
	r, ok, err := guided(context.Background(), ui.NewScripted(strings.NewReader(keys), &out), fixture(t, true), false, noRescan, keepScan)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v\n%s", ok, err, out.String())
	}
	var key, mk, token *Rule
	for i := range r.Rules {
		switch r.Rules[i].Value {
		case "ANTHROPIC_API_KEY":
			key = &r.Rules[i]
		case "GITHUB_TOKEN":
			token = &r.Rules[i]
		case "make":
			mk = &r.Rules[i]
		}
		if r.Rules[i].Always && r.Rules[i].Allow != scope.LockedAllow(r.Rules[i]) {
			t.Errorf("a locked rule was switched: %+v", r.Rules[i])
		}
	}
	if key == nil || key.Allow {
		t.Errorf("see ANTHROPIC_API_KEY = %+v, want switched to blocked", key)
	}
	if token == nil || token.Allow || !token.Always {
		t.Errorf("see GITHUB_TOKEN = %+v, want locked blocked", token)
	}
	if mk == nil || !mk.Added || !mk.Allow || mk.Category != "programs" {
		t.Errorf("run make = %+v, want added and allowed", mk)
	}
	for _, want := range []string{"▸ [✓]  run make", "can't sign in"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the review lacks %q:\n%s", want, out.String())
		}
	}
	if n := r.edits; n != 2 {
		t.Errorf("edits = %d, want 2", n)
	}
}

func TestRulesStructure(t *testing.T) {
	rules := buildRules(fixture(t, true), true)
	last := -1
	for _, rl := range rules {
		pos := -1
		for i, c := range categories {
			if c.key == rl.Category {
				pos = i
			}
		}
		if pos < last {
			t.Errorf("categories out of order at %+v", rl)
		}
		last = pos
		for _, p := range rl.Programs {
			if neverAllowed[p] {
				t.Errorf("a rule allows %s: %+v", p, rl)
			}
		}
	}
	find := func(cat, verb, value string) *Rule {
		for i := range rules {
			if rules[i].Category == cat && rules[i].Verb == verb && rules[i].Value == value {
				return &rules[i]
			}
		}
		return nil
	}
	if rl := find("programs", "run", "node, npm"); rl == nil || !rl.Allow || !reflect.DeepEqual(rl.Programs, []string{"node", "npm"}) {
		t.Errorf("run node, npm = %+v", rl)
	}
	if rl := find("websites", "reach", "registry.npmjs.org"); rl == nil || !reflect.DeepEqual(rl.Hosts, []string{"registry.npmjs.org"}) {
		t.Errorf("reach registry.npmjs.org = %+v", rl)
	}
	for _, c := range []struct{ verb, service string }{{"push", "GitHub"}, {"publish", "npm"}} {
		if rl := find("logins", c.verb, c.service); rl == nil || rl.Allow || !rl.Always {
			t.Errorf("%s to %s = %+v, want always blocked", c.verb, c.service, rl)
		}
	}
	for _, c := range []struct{ cat, verb string }{{"programs", "run"}, {"websites", "reach"}} {
		if rl := find(c.cat, c.verb, "anything else"); rl == nil || rl.Allow || !rl.Always {
			t.Errorf("%s %s anything else = %+v, want always blocked", c.cat, c.verb, rl)
		}
	}
	for _, rl := range buildRules(fixture(t, true), false) {
		if !rl.Always && !(rl.Verb == "write" && strings.HasPrefix(rl.Value, "everything in ")) {
			t.Errorf("a basics rule other than project writes can be flipped: %+v", rl)
		}
	}
}

func TestCannotAddMaze(t *testing.T) {
	// Add a rule, a program, maze (refused), then nothing (back to the kinds), Back, and Save.
	keys := "\r\r" + toAdd + "\r" + "\r" + "maze\n" + "\n" + "\x1b[B\x1b[B\x1b[B\r" + toSave + "\r"
	var out bytes.Buffer
	r, ok, err := guided(context.Background(), ui.NewScripted(strings.NewReader(keys), &out), fixture(t, true), false, noRescan, keepScan)
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	for _, rl := range r.Rules {
		if rl.Value == "maze" && rl.Allow {
			t.Errorf("maze was allowed: %+v", rl)
		}
	}
	if !strings.Contains(out.String(), "Not maze: it could change the rules") {
		t.Errorf("no refusal shown:\n%s", out.String())
	}
}

func TestSaveAndReload(t *testing.T) {
	rep := fixture(t, true)
	rules := buildRules(rep, true)
	res, err := save(context.Background(), rep, rules)
	if err != nil {
		t.Fatal(err)
	}
	compiled := scope.CompiledFolder(rep.Home, rep.Workspace.Root)
	for _, f := range []string{filepath.Join(compiled, "claude.yaml"), filepath.Join(compiled, "claude.verdicts.yaml")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(rep.Workspace.Root, ".maze/compiled")); err == nil {
		t.Error("a contract was written inside the project, where the agent could rewrite it")
	}
	for _, f := range []string{".maze/workspace.yaml", ".maze/state", ".gitignore"} {
		if _, err := os.Stat(filepath.Join(rep.Workspace.Root, f)); err != nil {
			t.Errorf("%s not written: %v", f, err)
		}
	}
	if _, err := os.Stat(filepath.Join(rep.Home, ".maze/personal.yaml")); err != nil {
		t.Errorf("personal.yaml not written: %v", err)
	}
	if res.checks == 0 || (runtime.GOOS != "linux" && res.checked) {
		t.Errorf("saved = %+v", res)
	}
	back, ok, err := loadSaved(rep)
	if err != nil || !ok {
		t.Fatalf("loadSaved: ok=%v err=%v", ok, err)
	}
	if len(back) != len(rules) {
		t.Errorf("reloaded %d rules, saved %d", len(back), len(rules))
	}
	a, err := scope.CheckApproval(rep.Home, rep.Workspace.Root)
	if err != nil || !a.Same {
		t.Errorf("just-saved rules aren't approved: %+v %v", a, err)
	}
}

func TestYesNeverApprovesChangedRules(t *testing.T) {
	rep := fixture(t, true)
	if _, err := save(context.Background(), rep, buildRules(rep, true)); err != nil {
		t.Fatal(err)
	}
	ws := filepath.Join(rep.Workspace.Root, ".maze/workspace.yaml")
	data, err := os.ReadFile(ws)
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, []byte("  - category: websites\n    verb: reach\n    value: evil.example\n    allow: true\n")...)
	if err := os.WriteFile(ws, data, 0o644); err != nil {
		t.Fatal(err)
	}
	a, err := scope.CheckApproval(rep.Home, rep.Workspace.Root)
	if err != nil || a.Same || len(a.Changes) != 1 || a.Changes[0].Rule.Value != "evil.example" {
		t.Fatalf("approval after an edit = %+v, %v", a, err)
	}
	var out bytes.Buffer
	_, _, err = reviewSaved(context.Background(), ui.NewScripted(strings.NewReader("\r"), &out), withSaved(t, rep), false)
	if !errors.Is(err, errNotApproved) {
		t.Errorf("Enter on the approval page (cursor on Cancel) = %v, want errNotApproved", err)
	}
	if !strings.Contains(out.String(), "changed since you approved") || !strings.Contains(out.String(), "evil.example") {
		t.Errorf("approval page doesn't show the change:\n%s", out.String())
	}
}

// withSaved returns rep with its saved rules loaded, as initFlow does for a set-up project.
func withSaved(t *testing.T, rep Report) Report {
	t.Helper()
	rules, _, err := loadSaved(rep)
	if err != nil {
		t.Fatal(err)
	}
	rep.Rules = rules
	return rep
}

func TestAddRuleInputs(t *testing.T) {
	r := fixture(t, true)
	for _, tt := range []struct{ in, want string }{
		{"https://API.github.com/repos/x?y=1", "api.github.com"},
		{"api.github.com:443", "api.github.com"},
		{"registry.npmjs.org", "registry.npmjs.org"},
	} {
		if rl, note := addWebsite(tt.in); note != "" || rl.Value != tt.want || rl.Hosts[0] != tt.want {
			t.Errorf("addWebsite(%q) = %q, %q; want %q", tt.in, rl.Value, note, tt.want)
		}
	}
	if rl, note := addWebsite("git@github.com:org/repo.git"); note != "" || rl.Value != "github.com" {
		t.Errorf("a git remote = %q, %q", rl.Value, note)
	}
	for _, bad := range []string{"localhost", "not a site", ".com", "a..b", "127.0.0.1", "🎉.com", "api.anthropic.com", "x.123"} {
		if _, note := addWebsite(bad); note == "" {
			t.Errorf("addWebsite(%q) was accepted", bad)
		}
	}
	if rl, note := addProgram(r, "/usr/bin/make"); note != "" || rl.Value != "make" {
		t.Errorf("addProgram(/usr/bin/make) = %q, %q", rl.Value, note)
	}
	for _, bad := range []string{"/opt/bin/tego", "MAZE", "Tego", "sudo", "make test", "rm -rf /", "a;b", "-x"} {
		if _, note := addProgram(r, bad); note == "" {
			t.Errorf("addProgram(%q) was accepted", bad)
		}
	}
	if _, note := addFile(r, r.Workspace.Root, "config/missing.json"); !strings.Contains(note, "no file") {
		t.Errorf("a missing file was accepted: %q", note)
	}
	if rl, note := addFile(r, r.Workspace.Root, "./keys/deploy.pem"); note != "" || rl.Value != "keys/deploy.pem" {
		t.Errorf("addFile(./keys/deploy.pem) = %q, %q", rl.Value, note)
	}
	rules := buildRules(r, true)
	for _, dup := range []Rule{{Category: "websites", Value: "registry.npmjs.org", Allow: true}, {Category: "programs", Value: "npm", Allow: true}} {
		found := false
		for _, h := range rules {
			if h.Category == dup.Category && h.Allow == dup.Allow && covers(h, dup) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s %s isn't seen as already on the list", dup.Category, dup.Value)
		}
	}
}

func TestReadingPageShowsProgress(t *testing.T) {
	// The real look, on the fixture: the reading page names each part with what it found.
	var out bytes.Buffer
	r := fixture(t, true)
	_, _, err := guided(context.Background(), ui.NewScripted(strings.NewReader("\r\r"), &out), r, false, noRescan, lookAroundShowing)
	if err != nil && !errors.Is(err, errWrongFolder) {
		t.Fatal(err)
	}
	for _, want := range []string{"Reading once. Nothing leaves this computer.", "✓ Your home folder", "✓ demo's files", "files", ".env file", "✓ Tools it uses", "git", "✓ Claude Code settings"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the reading page lacks %q:\n%s", want, out.String())
		}
	}
}
