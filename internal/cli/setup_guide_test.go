// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

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
	for _, v := range []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY", "CODEX_API_KEY", "TEGO_ON_MAC"} {
		t.Setenv(v, "")
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

// savedRules reads the rules file the guide named in its "Agent … added:" line.
func savedRules(t *testing.T, out, home string) string {
	t.Helper()
	i := strings.Index(out, "added: ")
	if i < 0 {
		t.Fatalf("no rules file named:\n%s", out)
	}
	path := strings.Replace(strings.SplitN(out[i+len("added: "):], "\n", 2)[0], "~", home, 1)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestStartTestProjectWithClaude: Claude Code, signed in with an API key that is saved, on the test project with the
// Base development rules. The guide says what to start, never starts it, saves the token where only the person can
// read it, and keeps Claude's own approval prompts.
func TestStartTestProjectWithClaude(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "claude")
	t.Chdir(f.Home)

	code, out, errs := runGuide(t, "1\n2\nsk-test-123\ny\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "first run", out,
		"Welcome to Tego.", "Which agent do you want to supervise?", "✓ Claude Code is installed",
		"How do you sign in to Claude Code?", "✓ Signed in to Claude Code",
		"Which project should Claude Code work in?", "✓ Project: ~/tego-sample", "See its files: "+sampleURL,
		"Which rules should Claude Code follow?", "Read more about rules and presets: "+presetsDocURL,
		"✓ Rules: Base development", "✓ Agent tego-sample added: ~/",
		"cd ~/tego-sample && tego run tego-sample", `ask Claude Code to "run the tests"`, "Tego blocks both.",
		"tego get sessions", "tego describe session --last", "tego dashboard")
	if strings.Contains(out, "sk-test-123") {
		t.Errorf("the token was printed:\n%s", out)
	}
	env := filepath.Join(f.Home, agentEnvRel)
	if fi, err := os.Stat(env); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("saved sign-in: %v %v", fi, err)
	}
	if got := savedLogin(f.Home, "ANTHROPIC_API_KEY"); got != "sk-test-123" {
		t.Errorf("saved token %q", got)
	}
	for _, p := range []string{".env", "README.md", "tests/test_notes.py", "libs/telemetry_helper/__init__.py"} {
		if _, err := os.Stat(filepath.Join(f.Home, guideSample, p)); err != nil {
			t.Errorf("test project lacks %s", p)
		}
	}
	wantAll(t, "first run", out, "For one of your own projects", "tego add agent --project <folder> --program claude-code")
	if b, _ := os.ReadFile(filepath.Join(f.Home, lastProjectRel)); strings.TrimSpace(string(b)) != filepath.Join(f.Home, guideSample) {
		t.Errorf("last project %q", b)
	}
	rules := savedRules(t, out, f.Home)
	wantAll(t, "rules file", rules, `command: ["claude"]`, `- "./"`, "tego/no-secrets", "tego/no-prod")
	if strings.Contains(rules, "dangerously") {
		t.Errorf("the test project switched Claude's own approval prompts off:\n%s", rules)
	}

	// Again: the saved sign-in is used, and the existing agent is kept unless the person replaces it.
	code, out, errs = runGuide(t, "1\n1\n1\n\n")
	if code != identity.ExitOK {
		t.Fatalf("second run: exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "second run", out, "✓ Signed in to Claude Code", "Agent tego-sample already exists. Replace its rules?", "✓ Agent tego-sample kept:")
	b, _ := os.ReadFile(filepath.Join(f.Home, ".bashrc"))
	if strings.Count(string(b), bashrcLine) != 1 {
		t.Errorf(".bashrc holds the loading line %d times", strings.Count(string(b), bashrcLine))
	}
}

// TestStartSubscriptionNotSaved: the subscription sign-in starts Claude's own browser sign-in, the token is used but not
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

	code, out, errs := runGuide(t, "1\n1\nn\n1\n2\n")
	first := out
	if code != identity.ExitOK || ran != "claude" {
		t.Fatalf("exit %d, setup-token ran %q\n%s\n%s", code, ran, out, errs)
	}
	wantAll(t, "subscription", out, "shows a link", "export CLAUDE_CODE_OAUTH_TOKEN=<your token>", "✓ Rules: Read-only review")
	if strings.Contains(out, "Paste the token") {
		t.Errorf("asked to paste a token the sign-in already gave:\n%s", out)
	}
	if os.Getenv("CLAUDE_CODE_OAUTH_TOKEN") != "sk-ant-oat01-read-from-the-sign-in-0123456789" {
		t.Errorf("the sign-in's token was not used")
	}

	// A sign-in whose token can't be read: the guide asks for it.
	guideSetupToken = func(context.Context, string, string) (string, error) { return "", nil }
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "")
	code, out, errs = runGuide(t, "1\n1\ntok-pasted\nn\n1\n2\n\n")
	if code != identity.ExitOK || !strings.Contains(out, "Paste the token Claude Code printed") {
		t.Fatalf("fallback: exit %d\n%s\n%s", code, out, errs)
	}
	if _, err := os.Stat(filepath.Join(f.Home, agentEnvRel)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a sign-in the person did not save was saved: %v", err)
	}
	if rules := savedRules(t, first, f.Home); strings.Contains(rules, `- "./"`) || !strings.Contains(rules, ".tego/") {
		t.Errorf("Read-only review: the agent may change the project, or has no folder of its own:\n%s", rules)
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
	wantAll(t, "own project", out, "What command starts it?", "✓ python3 is installed",
		"Path to the project, inside Tego's VM", "~/nope isn't in Tego's VM", "✓ Project: ~/app",
		"Pick each rule", "✓ Rules: your own", "✓ Agent app added:", "cd ~/app && tego run app",
		"tego shell", "back into Tego's VM, in ~/app")
	if strings.Contains(out, "How do you sign in") {
		t.Errorf("another program was asked to sign in:\n%s", out)
	}
	wantAll(t, "rules file", savedRules(t, out, f.Home), "python3", "bot.py", "api.github.com")
}

// TestStartInsideAProject: started inside a project, with the sign-in already in the shell, the guide offers this folder
// first and keeps Claude's own approval prompts.
func TestStartInsideAProject(t *testing.T) {
	f := onFixture(t, "fresh") // the fixture's working folder is its project
	noLogins(t)
	t.Setenv("CLAUDE_CODE_OAUTH_TOKEN", "from-the-shell")
	fakeProgram(t, "claude")
	code, out, errs := runGuide(t, "1\n1\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	wantAll(t, "inside a project", out, "This folder: "+tildeHome(f.Project, f.Home), "✓ Project: "+tildeHome(f.Project, f.Home), "opens as usual")
	if strings.Contains(out, "tego-sample") || strings.Contains(savedRules(t, out, f.Home), "dangerously") {
		t.Errorf("a real project got the test project or approvals off:\n%s", out)
	}
}

// TestStartInstallsTheAgent: an agent that is not installed is offered for install; "no" shows the line and stops,
// "yes" installs it and the guide goes on.
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

	code, out, _ := runGuide(t, "1\nn\n")
	if code != identity.ExitFinding || installed {
		t.Fatalf("no: exit %d installed %v\n%s", code, installed, out)
	}
	wantAll(t, "no", out, "✗ Claude Code isn't installed", "Install Claude Code now?", "curl -fsSL https://claude.ai/install.sh | bash")

	code, out, errs := runGuide(t, "1\ny\n1\n1\n")
	if code != identity.ExitOK || !installed {
		t.Fatalf("yes: exit %d installed %v\n%s\n%s", code, installed, out, errs)
	}
	wantAll(t, "yes", out, "Installing Claude Code...", "✓ Claude Code installed", "✓ Agent tego-sample added:")
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
