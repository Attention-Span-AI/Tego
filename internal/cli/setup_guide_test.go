// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"errors"
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

// TestSetupGuideClaudeCode: a person picks Claude Code, names a new project folder and lets the guide create it; the
// guide writes the agent's rules file outside the project, says what it allows in plain words, and how to run it.
func TestSetupGuideClaudeCode(t *testing.T) {
	f := onFixture(t, "fresh")
	fakeProgram(t, "claude")
	project := filepath.Join(f.Home, "my-app")

	code, out, errs := runGuide(t, "1\n~/my-app\ny\n")
	if code != identity.ExitOK {
		t.Fatalf("exit %d\nstdout:\n%s\nstderr:\n%s", code, out, errs)
	}
	for _, want := range []string{
		"✓ This computer can protect your agents (Basic level, no admin needed)",
		"Connect your agent", "1. Claude Code", "2. Codex", "3. Another program",
		"✓ Claude Code is installed",
		"~/my-app doesn't exist. Create it?",
		"✓ Rules written to ~/",
		"may change    ~/my-app",
		"never reads   ~/.ssh, ~/.aws, .env files and other secrets",
		"may connect   api.anthropic.com",
		"cd ~/my-app && tego run my-app",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q\n%s", want, out)
		}
	}
	if fi, err := os.Stat(project); err != nil || !fi.IsDir() {
		t.Fatalf("project folder not created: %v", err)
	}
	line := out[strings.Index(out, "Rules written to ")+len("Rules written to "):]
	saved := strings.Replace(strings.SplitN(line, "\n", 2)[0], "~", f.Home, 1)
	if strings.HasPrefix(saved, project+"/") {
		t.Errorf("rules file %s is inside the project the agent may change", saved)
	}
	text, err := os.ReadFile(saved)
	if err != nil {
		t.Fatalf("rules file: %v", err)
	}
	// The project is "./": the folder tego run <name> is typed in, which the guide's last line cds into.
	if !strings.Contains(string(text), `- "./"`) || !strings.Contains(string(text), "harness: claude-code") {
		t.Errorf("rules file does not let Claude Code change the project it runs in:\n%s", text)
	}

	// A second run keeps the saved rules file.
	code, out, errs = runGuide(t, "1\n~/my-app\n")
	if code != identity.ExitOK || !strings.Contains(out, "✓ Rules written to") {
		t.Fatalf("second run: exit %d\n%s\n%s", code, out, errs)
	}
}

// TestSetupGuideAgentMissing: an agent that is not installed stops the guide with the line that installs it.
func TestSetupGuideAgentMissing(t *testing.T) {
	onFixture(t, "fresh")
	prev := guideLookPath
	guideLookPath = func(string) (string, error) { return "", errors.New("not found") }
	t.Cleanup(func() { guideLookPath = prev })

	code, out, _ := runGuide(t, "1\n")
	if code != identity.ExitFinding {
		t.Fatalf("exit %d, want %d\n%s", code, identity.ExitFinding, out)
	}
	for _, want := range []string{"✗ Claude Code isn't installed here", "curl -fsSL https://claude.ai/install.sh | bash"} {
		if !strings.Contains(out, want) {
			t.Errorf("stdout lacks %q\n%s", want, out)
		}
	}
}

// TestSetupGuideRefusesHome: the whole home folder is not a project; the guide asks again.
func TestSetupGuideRefusesHome(t *testing.T) {
	onFixture(t, "fresh")
	fakeProgram(t, "claude")
	code, out, errs := runGuide(t, "1\n~\n~/proj\ny\n")
	if code != identity.ExitOK || !strings.Contains(out, "Pick a project folder, not your whole home folder.") {
		t.Fatalf("exit %d\n%s\n%s", code, out, errs)
	}
}
