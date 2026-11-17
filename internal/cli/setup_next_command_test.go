// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/shellword"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

func TestStartNextCommandQuotesProject(t *testing.T) {
	f := onFixture(t, "fresh")
	noLogins(t)
	fakeProgram(t, "python3")
	t.Chdir(f.Home)
	app := filepath.Join(f.Home, "app;touch PWNED;#")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	code, out, errs := runGuide(t, "3\npython3\n2\n"+app+"\n1\n")
	if code != identity.ExitOK {
		t.Fatalf("%d %s %s", code, out, errs)
	}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "tego"), []byte("#!/bin/sh\npwd > \"$COMMAND_CWD\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+":"+os.Getenv("PATH"))
	capture := filepath.Join(f.Home, "cwd")
	t.Setenv("COMMAND_CWD", capture)
	for _, line := range strings.Split(out, "\n") {
		if i := strings.Index(line, "cd "); i >= 0 && strings.Contains(line, " && tego run ") {
			c := exec.Command("/bin/sh", "-c", line[i:])
			if b, err := c.CombinedOutput(); err != nil {
				t.Fatalf("paste: %v %s", err, b)
			}
		}
	}
	if _, err := os.Stat(filepath.Join(f.Home, "PWNED")); !os.IsNotExist(err) {
		t.Fatal("pasted command executed project name")
	}
	if b, _ := os.ReadFile(capture); strings.TrimSpace(string(b)) != app {
		t.Fatalf("wrong working folder: %s", b)
	}
}

func TestGuideNextStepsRepairThisShell(t *testing.T) {
	for _, onPath := range []bool{false, true} {
		t.Run(fmt.Sprintf("installed-on-path-%t", onPath), func(t *testing.T) {
			f := onFixture(t, "fresh")
			noLogins(t)
			t.Setenv("CODEX_API_KEY", "shell-token")
			t.Chdir(f.Home)
			bin := filepath.Join(f.Home, ".local", "bin")
			if err := os.MkdirAll(bin, 0700); err != nil {
				t.Fatal(err)
			}
			oldLook, oldInstall, oldUID := guideLookPath, guideInstall, learnEUID
			t.Cleanup(func() { guideLookPath, guideInstall, learnEUID = oldLook, oldInstall, oldUID })
			learnEUID = func() int { return 1000 }
			guideLookPath = func(program string) (string, error) {
				if program == "codex" {
					path := filepath.Join(bin, program)
					_, err := os.Stat(path)
					return path, err
				}
				return oldLook(program)
			}
			guideInstall = func(context.Context, string, io.Writer) error {
				return os.WriteFile(filepath.Join(bin, "codex"), []byte("#!/bin/sh\nexit 0\n"), 0700)
			}
			path := os.Getenv("PATH")
			if onPath {
				path = bin + ":" + path
			}
			t.Setenv("PATH", path)
			code, out, errs := runGuide(t, "2\n1\n1\n1\n")
			if code != identity.ExitOK {
				t.Fatalf("%d %s %s", code, out, errs)
			}
			_, next, _ := strings.Cut(out, "Next steps")
			export := "export PATH=" + shellword.Quote(bin) + ":\"$PATH\""
			if strings.Contains(next, export) == onPath {
				t.Fatalf("PATH guidance: %s", next)
			}
			if !onPath && strings.Index(next, export) > strings.Index(next, "tego run") {
				t.Fatalf("PATH export follows first run: %s", next)
			}
		})
	}
	for _, old := range []string{"old-token", "new-token", ""} {
		t.Run("saved-"+old, func(t *testing.T) {
			oldShell := guideShell
			t.Cleanup(func() { guideShell = oldShell })
			guideShell = func() string { return "bash" }
			f := onFixture(t, "fresh")
			noLogins(t)
			fakeProgram(t, "codex")
			t.Chdir(f.Home)
			if err := saveLogin(f.Home, "CODEX_API_KEY", "saved-token"); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CODEX_API_KEY", old)
			code, out, errs := runGuide(t, "2\n2\nnew-token\n1\n1\n1\n")
			if code != identity.ExitOK {
				t.Fatalf("%d %s %s", code, out, errs)
			}
			_, next, _ := strings.Cut(out, "Next steps")
			if strings.Contains(next, "unset CODEX_API_KEY") != (old != "new-token") {
				t.Fatalf("replacement guidance: %s", next)
			}
			if old != "new-token" && strings.Index(next, "unset CODEX_API_KEY") > strings.Index(next, "tego run") {
				t.Fatalf("unset follows first run: %s", next)
			}
		})
	}
	// fish has no unset: the line must be one fish runs.
	t.Run("saved-in-fish", func(t *testing.T) {
		oldShell := guideShell
		t.Cleanup(func() { guideShell = oldShell })
		guideShell = func() string { return "fish" }
		f := onFixture(t, "fresh")
		noLogins(t)
		fakeProgram(t, "codex")
		t.Chdir(f.Home)
		if err := saveLogin(f.Home, "CODEX_API_KEY", "saved-token"); err != nil {
			t.Fatal(err)
		}
		t.Setenv("CODEX_API_KEY", "old-token")
		code, out, errs := runGuide(t, "2\n2\nnew-token\n1\n1\n1\n")
		if code != identity.ExitOK {
			t.Fatalf("%d %s %s", code, out, errs)
		}
		_, next, _ := strings.Cut(out, "Next steps")
		if !strings.Contains(next, "set -e CODEX_API_KEY") || strings.Contains(next, "unset") {
			t.Fatalf("fish guidance: %s", next)
		}
		if strings.Index(next, "set -e CODEX_API_KEY") > strings.Index(next, "tego run") {
			t.Fatalf("erase follows first run: %s", next)
		}
	})
}

func TestUnsetLine(t *testing.T) {
	names := []string{"CLAUDE_CODE_OAUTH_TOKEN", "ANTHROPIC_API_KEY"}
	for shell, want := range map[string]string{
		"bash": "unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY",
		"zsh":  "unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY",
		"":     "unset CLAUDE_CODE_OAUTH_TOKEN ANTHROPIC_API_KEY",
		"fish": "set -e CLAUDE_CODE_OAUTH_TOKEN; set -e ANTHROPIC_API_KEY",
	} {
		if got := unsetLine(shell, names); got != want {
			t.Errorf("%q: %q, want %q", shell, got, want)
		}
	}
}
