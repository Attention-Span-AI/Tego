// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/handoff"
	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fakeProgram puts an executable named name on PATH for this test.
func fakeProgram(t *testing.T, name string) {
	t.Helper()
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, name), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
}

// noLogins clears the sign-in variables for this test, and restores them after (the guide sets the one it is given).
func noLogins(t *testing.T) {
	for _, v := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "CODEX_API_KEY", "TEGO_ON_MAC", "TEGO_HOST_KIND", "WSL_DISTRO_NAME"} {
		t.Setenv(v, "")
		if err := os.Unsetenv(v); err != nil {
			t.Fatal(err)
		}
	}
}

// runGuide runs tego start's guide on answers, one per line, through Huh's plain prompts.
func runGuide(t *testing.T, answers string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := runSetupGuide(context.Background(), strings.NewReader(answers), &out, &errs, false)
	return code, out.String(), errs.String()
}

func wantAll(t *testing.T, label, out string, wants ...string) {
	t.Helper()
	for _, w := range wants {
		if !strings.Contains(out, w) {
			t.Errorf("%s: output lacks %q\n%s", label, w, out)
		}
	}
}

// savedRules reads the rules file of the agent named name.
func savedRules(t *testing.T, name string) string {
	t.Helper()
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	path, err := agentFile(m, name)
	if err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestGuideLookPath exercises the real lookup, rather than an installation stub.
func TestGuideLookPath(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("PATH", dir)
	executable := filepath.Join(dir, "bot")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	notExecutable := filepath.Join(dir, "data")
	if err := os.WriteFile(notExecutable, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	// A slash must never cause a search inside a PATH directory, even if it has a match.
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "bot"), nil, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, program, want string
		wantErr             bool
	}{
		{"absolute executable", executable, executable, false},
		{"absolute nonexecutable", notExecutable, "", true},
		{"absolute directory", dir, "", true},
		{"absolute missing", filepath.Join(dir, "missing"), "", true},
		{"bare on PATH", "bot", executable, false},
		{"bare missing", "missing", "", true},
		{"relative with slash", "sub/bot", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := guideLookPath(tt.program)
			if got != tt.want || (err != nil) != tt.wantErr {
				t.Errorf("guideLookPath(%q) = %q, %v; want %q, error %v", tt.program, got, err, tt.want, tt.wantErr)
			}
		})
	}
}

func TestStartProgramWithAbsolutePath(t *testing.T) {
	for _, relativeFirst := range []bool{false, true} {
		t.Run(fmt.Sprint("relative first=", relativeFirst), func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			t.Chdir(f.Home)
			project := filepath.Join(f.Home, "my app")
			if err := os.Mkdir(project, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.Home, "bot.sh"), nil, 0o755); err != nil {
				t.Fatal(err)
			}
			prev := guideVersion
			t.Cleanup(func() { guideVersion = prev })
			var versionPrograms []string
			guideVersion = func(_ context.Context, program string) string {
				versionPrograms = append(versionPrograms, program)
				return "1.2.3"
			}
			answers := "3\n"
			if relativeFirst {
				answers += "./bot.sh\n"
			}
			answers += "/bin/sh -i\n2\n" + project + "\n1\n"
			code, out, errs := runGuide(t, answers)
			if code != identity.ExitOK {
				t.Fatalf("exit %d\n%s\n%s", code, out, errs)
			}
			if !slices.Equal(versionPrograms, []string{"/bin/sh"}) {
				t.Errorf("version programs = %q, want only /bin/sh", versionPrograms)
			}
			wantAll(t, "absolute program", out, "1/4  Agent", "✓ /bin/sh 1.2.3 is installed",
				"2/4  Login", "Nothing to log in to: /bin/sh brings its own", "3/4  Project", "4/4  Rules",
				"Which rules should /bin/sh follow?", "Run /bin/sh under Tego",
				"cd "+shellword.Quote(project)+" && tego run "+agentNameFor(project))
			wantAll(t, "rules file", savedRules(t, agentNameFor(project)), `command: ["/bin/sh", "-i"]`)
			// Compile from the chosen project as tego run does, without starting a run.
			t.Chdir(project)
			m, _, err := loadMachine(config.TrustWarn)
			if err != nil {
				t.Fatal(err)
			}
			var diagnostics bytes.Buffer
			rt, _, _, compileCode := compileForRun(t.Context(), runOptions{contract: agentNameFor(project), offline: true}, m, &diagnostics)
			if compileCode != identity.ExitOK {
				t.Fatalf("compile exit %d: %s", compileCode, &diagnostics)
			}
			if got := commandFor(runOptions{}, rt); !slices.Equal(got, []string{"/bin/sh", "-i"}) {
				t.Errorf("saved run command = %q", got)
			}
			if !slices.ContainsFunc(rt.Exec, func(r agent.ExecRule) bool {
				return r.Raw == "/bin/sh" && r.Path == "/bin/sh" && r.Basename == "sh" && !r.ByName && r.Source == agent.ExecSourceCommand
			}) {
				t.Errorf("compiled exec rules do not grant /bin/sh by path: %+v", rt.Exec)
			}
			if relativeFirst {
				wantAll(t, "relative retry", out, "use the program's name or its full path; relative paths would run from the project folder chosen later")
				if strings.Contains(out, "isn't installed") {
					t.Errorf("relative path was called missing:\n%s", out)
				}
			}
		})
	}
}

func TestGuideMissingProgramMessages(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	data := filepath.Join(dir, "data")
	if err := os.WriteFile(data, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	missing := dir + "/./missing"
	for _, tt := range []struct{ program, message string }{
		{"missing", "missing isn't installed. Install it, then run tego start again."},
		{missing, missing + " was not found."},
		{data, data + " is not a program that can be run."},
		{dir, dir + " is not a program that can be run."},
	} {
		t.Run(tt.program, func(t *testing.T) {
			var out bytes.Buffer
			g := newWalk(strings.NewReader(""), &out, false)
			code, err := g.installed(t.Context(), guideAgents[2], tt.program, tt.program, dir)
			if code != identity.ExitFinding || err != nil {
				t.Fatalf("installed = %d, %v", code, err)
			}
			wantAll(t, "missing program", out.String(), "✗ "+tt.message)
		})
	}
}

// TestStartTestProjectWithClaude: Claude Code, logged in with an API key that is saved, on the test project with the
// Base development rules. The guide says what to start, never starts it, saves the token where only the person can
// read it, and keeps Claude's own approval prompts.
func TestStartTestProjectWithClaude(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)

	code, out, errs := runGuide(t, "1\n2\nsk-test-123\n1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "first run", out,
		"Welcome to Tego", "1/4  Agent", "Which agent do you want to supervise?", "✓ Claude Code is installed",
		"2/4  Login", "How do you want to log in to Claude Code?", "✓ Logged in to Claude Code", "Save the login for later sessions?",
		"3/4  Project", "Which project should Claude Code work in?", "✓ Created ~/tego-sample", "Files: "+sampleURL,
		"4/4  Rules", "Which rules should Claude Code follow?", "✓ Created agent tego-sample", "Presets: "+presetsDocURL,
		"Ready", "Agent       tego-sample · Claude Code", "Rules       Base development", "Dashboard   tego dashboard opens it",
		"Next steps", "cd "+filepath.Join(f.Home, guideSample)+" && tego run tego-sample", "tego session list", "tego session show --last",
		"tego rules edit tego-sample")
	if strings.Contains(out, "sk-test-123") {
		t.Errorf("the token was printed:\n%s", out)
	}
	env := filepath.Join(f.Home, agentEnvRel)
	if fi, err := os.Stat(env); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved login: %v %v", fi, err)
	}
	if got := savedLogin(f.Home, "ANTHROPIC_API_KEY"); got != "sk-test-123" {
		t.Errorf("saved token %q", got)
	}
	for _, p := range []string{".env", "README.md", "tests/test_notes.py", "libs/telemetry_helper/__init__.py"} {
		if _, err := os.Stat(filepath.Join(f.Home, guideSample, p)); err != nil {
			t.Errorf("test project lacks %s", p)
		}
	}
	if b, _ := os.ReadFile(filepath.Join(f.Home, lastProjectRel)); strings.TrimSpace(string(b)) != filepath.Join(f.Home, guideSample) {
		t.Errorf("last project %q", b)
	}
	rules := savedRules(t, guideSample)
	wantAll(t, "rules file", rules, `command: ["claude"]`, `- "./"`, "tego/no-secrets", "tego/no-prod")
	if strings.Contains(rules, "dangerously") {
		t.Errorf("the test project switched Claude's own approval prompts off:\n%s", rules)
	}

	// Again: the saved login is used, and the existing agent is kept unless the person replaces it.
	code, out, errs = runGuide(t, "1\n1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("second run: exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "second run", out, "✓ Logged in to Claude Code", "✓ Using ~/tego-sample",
		"Agent tego-sample already exists. Replace its rules?", "✓ Kept agent tego-sample")
	b, _ := os.ReadFile(filepath.Join(f.Home, ".bashrc"))
	if strings.Count(string(b), bashrcLine) != 1 {
		t.Errorf(".bashrc holds the loading line %d times", strings.Count(string(b), bashrcLine))
	}
}

// TestStartSubscriptionNotSaved: the subscription login starts Claude's own browser login, the token is used but not
// saved, and Read-only review leaves the project unwritable.
func TestStartSubscriptionNotSaved(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	prev := guideSetupToken
	t.Cleanup(func() { guideSetupToken = prev })
	ran := ""
	guideSetupToken = func(_ context.Context, program, _ string) (string, error) {
		ran = program
		return "sk-ant-oat01-read-from-the-sign-in-0123456789", nil
	}

	code, out, errs := runGuide(t, "1\n1\n2\n1\n2\n")
	if code != identity.ExitOK || ran != "claude" {
		t.Fatalf("exit %d, setup-token ran %q\n%s\n%s", code, ran, out, errs)
	}
	wantAll(t, "subscription", out, "Open the link Claude Code shows", "export CLAUDE_CODE_OAUTH_TOKEN=<your token>",
		"Project content stays read-only", "Rules       Read-only review")
	if strings.Contains(out, "Paste the token") {
		t.Errorf("asked to paste a token the login already gave:\n%s", out)
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "sk-ant-oat01-read-from-the-sign-in-0123456789" {
		t.Errorf("the login's token was not used")
	}
	if rules := savedRules(t, guideSample); strings.Contains(rules, `- "./"`) || !strings.Contains(rules, ".tego/") {
		t.Errorf("Read-only review: the agent may change the project, or has no folder of its own:\n%s", rules)
	}

	// A login whose token can't be read: the guide asks for it.
	guideSetupToken = func(context.Context, string, string) (string, error) { return "", nil }
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	code, out, errs = runGuide(t, "1\n1\ntok-pasted\n2\n1\n2\n1\n")
	if code != identity.ExitOK || !strings.Contains(out, "Paste the token Claude Code printed") {
		t.Fatalf("fallback: exit %d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(f.Home, agentEnvRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a login the person did not save was saved: %v", err)
	}
}

// TestStartOwnProjectOnMac: another program, on one of the person's projects given by path. A path that is not in the
// VM gets the one-line reason and the question again; the person's own rules name an extra host.
func TestStartOwnProjectOnMac(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	t.Setenv("TEGO_ON_MAC", "1")
	fakeProgram(t, "python3")
	t.Chdir(f.Home)
	app := filepath.Join(f.Home, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}

	code, out, errs := runGuide(t, "3\npython3 bot.py\n2\n~/nope\n~/app\n3\n0\napi.github.com\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "own project", out, "python3 bot.py is only an example. To try Tego on its test project, type: python3 -m unittest -v",
		"What command starts it?", "✓ python3 is installed", "Nothing to log in to",
		"Path to the project", "~/nope isn't in Tego's VM", "✓ Using ~/app",
		"Which rules?", "✓ Created agent app", "cd "+app+" && tego run app",
		"Shell       Tego's Linux VM · type exit to return to your Mac")
	if strings.Contains(out, "How do you want to log in") {
		t.Errorf("another program was asked to log in:\n%s", out)
	}
	wantAll(t, "rules file", savedRules(t, "app"), "python3", "bot.py", "api.github.com")
}

// TestStartOwnRulesFile: a rules file of the person's own: one that does not check gets its error and the question
// again; one that does is saved as the agent its name: names.
func TestStartOwnRulesFile(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	app := filepath.Join(f.Home, "app")
	if err := os.MkdirAll(app, 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(name, text string) {
		if err := os.WriteFile(filepath.Join(f.Home, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("bad.yaml", "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\nnet:\n  allow: [\"not a host\"]\n")
	write("good.yaml", "version: 0\nname: helper\ncommand: [\"/bin/sh\"]\n")

	code, out, errs := runGuide(t, "1\n2\n~/app\n4\n~/nope.yaml\n~/bad.yaml\n~/good.yaml\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "own rules file", out, "Path to the rules file", "~/nope.yaml doesn't exist", "~/bad.yaml line 5: ",
		"✓ Created agent helper from ~/good.yaml", "Rules       Your own file", "tego run helper")
	wantAll(t, "rules file", savedRules(t, "helper"), "name: helper", "/bin/sh")
}

// TestStartInsideAProject: started inside a project, with the login already in the shell, the guide offers this folder
// and keeps Claude's own approval prompts.
func TestStartInsideAProject(t *testing.T) {
	f := onFixture(t, "fresh") // the fixture's working folder is its project
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-the-shell")
	fakeProgram(t, "claude")
	code, out, errs := runGuide(t, "1\n2\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "inside a project", out, "This folder", "✓ Using "+tildeHome(f.Project, f.Home))
	name := agentNameFor(f.Project)
	if strings.Contains(out, "tego-sample") || strings.Contains(savedRules(t, name), "dangerously") {
		t.Errorf("a real project got the test project or approvals off:\n%s", out)
	}
}

// TestStartInstallsTheAgent: an agent that is not installed is offered for install; "No" shows the line and stops,
// "Yes" installs it and the guide goes on.
func TestStartInstallsTheAgent(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "x")
	t.Chdir(f.Home)
	bin := filepath.Join(f.Home, ".local", "bin")
	prevLook, prevInstall := guideLookPath, guideInstall
	t.Cleanup(func() { guideLookPath, guideInstall = prevLook, prevInstall })
	installed := false
	guideLookPath = func(p string) (string, error) {
		if installed {
			return filepath.Join(bin, p), nil
		}
		return "", errors.New("not found")
	}
	guideInstall = func(_ context.Context, _ string, _ io.Writer) error {
		installed = true
		if err := os.MkdirAll(bin, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\n"), 0o755)
	}

	code, out, _ := runGuide(t, "1\n2\n")
	if code != identity.ExitFinding || installed {
		t.Fatalf("no: exit %d installed %v\n%s", code, installed, out)
	}
	wantAll(t, "no", out, "Install Claude Code now?", "curl -fsSL https://claude.ai/install.sh | bash")

	code, out, errs := runGuide(t, "1\n1\n1\n1\n")
	if code != identity.ExitOK || !installed {
		t.Fatalf("yes: exit %d installed %v\n%s\n%s", code, installed, out, errs)
	}
	wantAll(t, "yes", out, "Installing Claude Code…", "✓ Installed Claude Code", "✓ Created agent tego-sample")
}

// TestStartNeedsATerminal: tego start asks questions, so outside a terminal it says what to use instead.
func TestStartNeedsATerminal(t *testing.T) {
	code, _, errs := run(t, "start")
	if code != identity.ExitUsage || !strings.Contains(errs, "runs in a terminal") {
		t.Fatalf("exit %d\n%s", code, errs)
	}
}

// TestLastToken: the token is read from what Claude's sign-in showed, colour codes and all; the last one wins.
func TestLastToken(t *testing.T) {
	for in, want := range map[string]string{
		"no token here": "",
		"Your OAuth token:\n\x1b[1msk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123\x1b[0m\nStore it": "sk-ant-oat01-abcdefghijklmnopqrstuvwxyz0123",
		"sk-ant-oat01-first-aaaaaaaaaaaaaaaaaaaaa sk-ant-oat01-second-bbbbbbbbbbbbbbbbbbbb":      "sk-ant-oat01-second-bbbbbbbbbbbbbbbbbbbb",
	} {
		if got := lastToken(in); got != want {
			t.Errorf("lastToken(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestLongListSaysWhatIsOutOfView follows a 9-item list as the cursor moves down and back up: the hint counts the
// items above and below the 6 rows in view, scrolling only as far as keeps the cursor in view, as Huh does.
func TestLongListSaysWhatIsOutOfView(t *testing.T) {
	cursor := 0
	h := &hinted{items: 9, hovered: func() (int, bool) { return cursor, true }}
	for _, step := range []struct {
		cursor int
		want   string
	}{
		{0, "↓ 3 more · "}, {5, "↓ 3 more · "}, {6, "↑ 1 more · ↓ 2 more · "}, {8, "↑ 3 more · "},
		{4, "↑ 3 more · "}, {2, "↑ 2 more · ↓ 1 more · "}, {0, "↓ 3 more · "},
	} {
		cursor = step.cursor
		if got := h.more(); got != step.want {
			t.Errorf("cursor %d: %q, want %q", step.cursor, got, step.want)
		}
	}
	if got := (&hinted{items: 4, hovered: func() (int, bool) { return 3, true }}).more(); got != "" {
		t.Errorf("a list that fits: %q", got)
	}
}

// TestRulesLineNamesTheChoice: the line tego start writes keeps init's marker first, and tego run reads the name back.
func TestRulesLineNamesTheChoice(t *testing.T) {
	for _, c := range []struct {
		rc   rulesChoice
		want string
	}{
		{rulesChoice{label: "Base development"}, "Base development rules"},
		{rulesChoice{label: "Your own choice", presets: []string{"no-secrets", "no-prod"}}, "rules no-secrets, no-prod"},
	} {
		text := withRulesLine([]byte(initMarker+" --preset x.\nname: a\n"), c.rc)
		if !strings.HasPrefix(string(text), initMarker) {
			t.Errorf("the marker is no longer first:\n%s", text)
		}
		if l := chosenRulesLine.FindSubmatch(text); l == nil || string(l[1]) != c.want {
			t.Errorf("read back %q, want %q", l, c.want)
		}
	}
}

// TestStartSavedLogin: a saved login is offered, not used silently. Keeping it asks nothing more; logging in again
// replaces it, so the old key and the new token are never saved side by side, and other agents' logins stay.
func TestStartSavedLogin(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	if code, out, errs := runGuide(t, "1\n2\nsk-test-123\n1\n1\n1\n"); code != identity.ExitOK {
		t.Fatalf("first run: exit %d\n%s\n%s", code, out, errs)
	}
	if err := saveLogin(f.Home, "CODEX_API_KEY", "sk-codex"); err != nil {
		t.Fatal(err)
	}

	noLogins(t) // a new shell: the saved login is what it has
	code, out, errs := runGuide(t, "1\n1\n1\n1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("keep: exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "keep", out, "Use your saved Claude Code login?", "✓ Logged in to Claude Code")
	if strings.Contains(out, "How do you want to log in") {
		t.Errorf("keeping the saved login asked how to log in:\n%s", out)
	}

	noLogins(t)
	prev := guideSetupToken
	t.Cleanup(func() { guideSetupToken = prev })
	guideSetupToken = func(context.Context, string, string) (string, error) { return "sk-ant-oat01-new-0123456789", nil }
	code, out, errs = runGuide(t, "1\n2\n1\n1\n1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("again: exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "again", out, "Use your saved Claude Code login?", "How do you want to log in to Claude Code?")
	if got := savedLogin(f.Home, "CLAUDE_CODE_OAUTH_TOKEN"); got != "sk-ant-oat01-new-0123456789" {
		t.Errorf("the new login was not saved: %q", got)
	}
	if got := savedLogin(f.Home, "ANTHROPIC_API_KEY"); got != "" {
		t.Errorf("the replaced key is still saved: %q", got)
	}
	if got := savedLogin(f.Home, "CODEX_API_KEY"); got != "sk-codex" {
		t.Errorf("another agent's login was removed: %q", got)
	}
}

// TestRunningDashboardIsReused: a dashboard whose address answers is reused, link and all, so the tabs open on it
// stay signed in; one that stopped is not.
func TestRunningDashboardIsReused(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0700); err != nil {
		t.Fatal(err)
	}
	if runningDashboard(home) != "" {
		t.Fatal("no log, yet a dashboard")
	}
	l := dashboardStandIn(t)
	link := l.URL + "/?t=0123abcd"
	if err := os.MkdirAll(filepath.Dir(dashboardLog(home)), 0o700); err != nil {
		t.Fatal(err)
	}
	this := thisProgramFile(t)
	startedBy(t, home, this, "tego serve: dashboard at "+link+"\n") // it runs this tego
	if got := runningDashboard(home); got != link {
		t.Errorf("running: %q, want %q", got, link)
	}
	if got := guideDashboard(context.Background(), home); got != link {
		t.Errorf("tego start restarted a running dashboard: %q", got)
	}
	startedBy(t, home, olderProgramFile(this), "tego serve: dashboard at "+link+"\n") // tego was updated since
	if got := runningDashboard(home); got != "" {
		t.Errorf("tego was updated after the dashboard started, yet it was reused: %q", got)
	}
	startedBy(t, home, this, "tego serve: dashboard at "+link+"\n")
	l.Close()
	if got := runningDashboard(home); got != "" {
		t.Errorf("stopped, yet reused: %q", got)
	}
}

// TestDashboardIsOneDashboard: tego dashboard says one is running and reuses it, restarts one started before tego was
// updated, and starts one only when none runs: never a second dashboard beside the first.
func TestDashboardIsOneDashboard(t *testing.T) {
	f := onFixture(t, "fresh")
	starts := 0
	prev := guideDashboard
	t.Cleanup(func() { guideDashboard = prev })
	guideDashboard = func(_ context.Context, home string) string {
		if u := runningDashboard(home); u != "" {
			return u
		}
		starts++
		return "http://127.0.0.1:1/?t=started"
	}
	l := dashboardStandIn(t)
	link := l.URL + "/?t=0123abcd"
	if err := os.MkdirAll(filepath.Dir(dashboardLog(f.Home)), 0o700); err != nil {
		t.Fatal(err)
	}
	this := thisProgramFile(t)
	startedBy(t, f.Home, this, link+"\n")

	code, out, errs := run(t, "dashboard")
	if code != identity.ExitOK || !strings.Contains(out, "The dashboard is already running: "+link) || starts != 0 {
		t.Fatalf("running: exit %d, %d starts\n%s%s", code, starts, out, errs)
	}

	startedBy(t, f.Home, olderProgramFile(this), link+"\n")
	code, out, errs = run(t, "dashboard")
	if code != identity.ExitOK || !strings.Contains(out, "Started the dashboard again, on the updated tego") || starts != 1 {
		t.Fatalf("updated: exit %d, %d starts\n%s%s", code, starts, out, errs)
	}

	l.Close()
	code, out, errs = run(t, "dashboard")
	if code != identity.ExitOK || !strings.Contains(out, "Started the dashboard: http://127.0.0.1:1/?t=started") || starts != 2 {
		t.Fatalf("none: exit %d, %d starts\n%s%s", code, starts, out, errs)
	}
}

// testProgram is the SHA-256 a test's dashboard is taken to run: this test binary has no pinned tego-control, so
// thisProgram answers with it (init below), as a pinned build answers with its pin.
const testProgram = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

func init() { thisProgram = func() (string, bool) { return testProgram, true } }

// thisProgramFile is the program a dashboard started now would run, as dashboardAt compares it.
func thisProgramFile(t *testing.T) string {
	t.Helper()
	p, ok := thisProgram()
	if !ok {
		t.Fatal("no program to compare the dashboard with")
	}
	return p
}

// olderProgramFile is a program with other bytes than p: the dashboard tego was updated from.
func olderProgramFile(p string) string {
	return strings.Repeat("f", len(p))
}

// startedBy writes the dashboard log at home as the dashboard leaves it: the program line (the
// SHA-256 p of the bytes it runs), then body, what tego serve printed.
func startedBy(t *testing.T, home string, p string, body string) {
	t.Helper()
	if err := os.WriteFile(dashboardLog(home), []byte(handoff.ProgramLine(p)+body), 0o600); err != nil {
		t.Fatal(err)
	}
}

// savedLogin is the value the guide's data-only reader can use.
func savedLogin(home, envVar string) string { return readSavedLogins(home, nil)[envVar] }

// Relative grants are checked from the selected project, just as the printed
// cd PROJECT && tego run command will compile them.
func TestStartOwnRulesUseSelectedProject(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-shell")
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	project := filepath.Join(f.Home, "app")
	if err := os.MkdirAll(filepath.Join(project, "out", "cache"), 0700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(f.Home, "own.yaml")
	if err := os.WriteFile(file, []byte("version: 0\nname: helper\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\"./out/cache/\"]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	// Limit the failing reproduction to one validation, rather than repeatedly
	// submitting EOF through the plain guide's retry loop.
	var output bytes.Buffer
	g := newWalk(strings.NewReader("4\n~/own.yaml\n"), &output, false)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	g.ctx = ctx
	rc, err := g.rules(ctx, m, "Claude Code", guideAgents[0], project)
	if err != nil || rc.file != file {
		t.Fatalf("selected-project rules: %+v, %v\n%s", rc, err, &output)
	}
}

// TestDashboardReadyHasFallback: the Ready panel says how to open the dashboard when the guide's opening did not work.
func TestDashboardReadyHasFallback(t *testing.T) {
	win := strings.Join(dashboardReady(hostWindows, "http://127.0.0.1:8484/", true, "", ""), "\n")
	if !strings.Contains(win, "opening in your browser") || !strings.Contains(win, "tego dashboard in PowerShell or cmd") {
		t.Errorf("Windows Ready lacks the fallback:\n%s", win)
	}
	mac := strings.Join(dashboardReady(hostMac, "http://127.0.0.1:8484/", false, "", ""), "\n")
	if !strings.Contains(mac, "Type tego dashboard.") {
		t.Errorf("Mac Ready lacks the fallback:\n%s", mac)
	}
	if got := dashboardReady(hostLinux, "http://x/", false, "", ""); len(got) != 1 {
		t.Errorf("Linux Ready: %v", got)
	}
}
