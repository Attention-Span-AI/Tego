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

func runGuide(t *testing.T, answers string) (int, string, string) {
	t.Helper()
	var out, errs bytes.Buffer
	code := runSetupGuide(context.Background(), strings.NewReader(answers), &out, &errs, false)
	return code, out.String(), errs.String()
}

// TestSetupGuideClaudeCode: started from home, the guide makes a sample project without asking, writes Claude Code's
// rules file outside it, says what it allows in plain words, and how to run it.
func TestSetupGuideClaudeCode(t *testing.T) {
	f := onFixture(t, "fresh")
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	sample := filepath.Join(f.Home, "tego-sample")

	code, out, errs := runGuide(t, "1\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	for _, want := range []string{
		"✓ This computer can protect your agents (Basic level, no admin needed)",
		"Welcome to Tego.", "Step 1 of 4 · Connect your agent", "Step 2 of 4 · Your first project", "Step 3 of 4 · Its rules", "Step 4 of 4 · Run it", "1. Claude Code", "2. Codex", "3. Another program",
		"✓ Claude Code is installed",
		"✓ Sample project ready to try Tego on: ~/tego-sample",
		"✓ Rules written to ~/",
		"may change    ~/tego-sample",
		"never reads   ~/.ssh, ~/.aws, .env files and other secrets",
		"may connect   api.anthropic.com",
		"cd ~/tego-sample && tego run tego-sample",
		"For one of your own projects, run tego start from inside it.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q\n%s", want, out)
		}
	}
	if strings.Contains(out, "[Y/n]") || strings.Contains(out, "Which folder") {
		t.Errorf("the project step asked a question:\n%s", out)
	}
	for name := range sampleFiles {
		if _, err := os.Stat(filepath.Join(sample, name)); err != nil {
			t.Errorf("sample project lacks %s: %v", name, err)
		}
	}
	line := out[strings.Index(out, "Rules written to ")+len("Rules written to "):]
	saved := strings.Replace(strings.SplitN(line, "\n", 2)[0], "~", f.Home, 1)
	if strings.HasPrefix(saved, sample+"/") {
		t.Errorf("rules file %s is inside the project the agent may change", saved)
	}
	text, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("rules file: %v", err)
	}
	if !strings.Contains(string(text), `- "./"`) || !strings.Contains(string(text), "harness: claude-code") {
		t.Errorf("rules file does not let Claude Code change the project it runs in:\n%s", text)
	}

	// A second run reuses the sample and its rules file, and keeps a file the person changed.
	if err := os.WriteFile(filepath.Join(sample, "hello.py"), []byte("print(1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, out, errs = runGuide(t, "1\n")
	if code != identity.ExitOK || !strings.Contains(out, "✓ Rules written to") {
		t.Fatalf("second run: exit %d\n%s\n%s", code, out, errs)
	}
	if b, _ := os.ReadFile(filepath.Join(sample, "hello.py")); string(b) != "print(1)\n" {
		t.Errorf("second run replaced the person's hello.py: %q", b)
	}
}

// TestSetupGuideUsesThisProject: started inside a project folder, the guide uses that folder, without asking.
func TestSetupGuideUsesThisProject(t *testing.T) {
	f := onFixture(t, "fresh") // the fixture's working folder is its project
	fakeProgram(t, "claude")
	code, out, errs := runGuide(t, "1\n")
	if code != identity.ExitOK || !strings.Contains(out, "✓ Using this folder: "+tildeHome(f.Project, f.Home)) {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	if strings.Contains(out, "tego-sample") {
		t.Errorf("made a sample project inside a project:\n%s", out)
	}
}

// TestSetupGuideAgentMissing: an agent that is not installed is offered for install. "n" shows the line that
// installs it and stops; "y" runs it and the guide carries on.
func TestSetupGuideAgentMissing(t *testing.T) {
	f := onFixture(t, "fresh")
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
	ran := ""
	guideInstall = func(_ context.Context, line string, _ io.Writer) error {
		ran, installed = line, true
		// What Anthropic's installer leaves: claude in ~/.local/bin.
		if err := os.MkdirAll(bin, 0o755); err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 0\n"), 0o755)
	}

	code, out, _ := runGuide(t, "1\nn\n")
	if code != identity.ExitFinding || ran != "" {
		t.Fatalf("no: exit %d, ran %q\n%s", code, ran, out)
	}
	for _, want := range []string{"✗ Claude Code isn't installed here", "Install it now? [Y/n]", "curl -fsSL https://claude.ai/install.sh | bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("no: stdout lacks %q\n%s", want, out)
		}
	}

	code, out, errs := runGuide(t, "1\ny\n")
	if code != identity.ExitOK || ran != "curl -fsSL https://claude.ai/install.sh | bash" {
		t.Fatalf("yes: exit %d, ran %q\n%s\n%s", code, ran, out, errs)
	}
	for _, want := range []string{"Installing...", "✓ Claude Code installed", "✓ Rules written to"} {
		if !strings.Contains(out, want) {
			t.Errorf("yes: stdout lacks %q\n%s", want, out)
		}
	}
}

// TestSetupGuideRulesArePicked: the person switches a rule off; the rules file leaves that preset out and the summary
// says what that allows.
func TestSetupGuideRulesArePicked(t *testing.T) {
	f := onFixture(t, "fresh")
	fakeProgram(t, "claude")
	t.Chdir(f.Home)
	code, out, errs := runGuide(t, "1\n2\n\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
	for _, want := range []string{"1. [x] Keep secrets away", "2. [ ] Reach only the hosts named", "may connect   anywhere"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q\n%s", want, out)
		}
	}
	line := out[strings.Index(out, "Rules written to ")+len("Rules written to "):]
	text, err := os.ReadFile(strings.Replace(strings.SplitN(line, "\n", 2)[0], "~", f.Home, 1))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(text), "no-prod") || !strings.Contains(string(text), "tego/no-secrets") {
		t.Errorf("rules file presets do not match the switches:\n%s", text)
	}
}
