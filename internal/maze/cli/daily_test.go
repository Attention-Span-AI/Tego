// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// setUpProject makes a home folder, a PATH and a project, points HOME and PATH at them, and saves the suggested
// rules with `maze init --yes`. It returns the project folder.
func setUpProject(t *testing.T) string {
	t.Helper()
	home, bin := t.TempDir(), t.TempDir()
	root := filepath.Join(t.TempDir(), "demo")
	for p, mode := range map[string]os.FileMode{
		filepath.Join(root, ".git", "HEAD"):       0o644,
		filepath.Join(root, ".env"):               0o644,
		filepath.Join(root, "package.json"):       0o644,
		filepath.Join(root, "config", "dev.json"): 0o644,
		filepath.Join(home, ".ssh", "id_ed25519"): 0o600,
		filepath.Join(bin, "claude"):              0o755,
		filepath.Join(bin, "node"):                0o755,
		filepath.Join(bin, "npm"):                 0o755,
		filepath.Join(bin, "git"):                 0o755,
		filepath.Join(bin, "make"):                0o755,
		filepath.Join(bin, "ls"):                  0o755,
		filepath.Join(bin, "cat"):                 0o755,
	} {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("{}\n"), mode); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", bin)
	if code, out, errOut := run(t, "init", "--yes", "-C", root); code != identity.ExitOK {
		t.Fatalf("init --yes = %d\n%s\n%s", code, out, errOut)
	}
	return root
}

// run runs maze with args and returns the exit code, stdout and stderr.
func run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	s, out, errOut := streams("")
	code := Main(context.Background(), args, s)
	return code, out.String(), errOut.String()
}

func TestAllowBlock(t *testing.T) {
	root := setUpProject(t)
	steps := []struct {
		args []string
		code int
		says string
	}{
		{[]string{"allow", "program", "make"}, identity.ExitOK, "Claude Code can run make."},
		{[]string{"allow", "cmd", "/usr/bin/make"}, identity.ExitOK, "can already run make"},
		{[]string{"block", "program", "npm"}, identity.ExitOK, "Claude Code can't run npm."},
		{[]string{"block", "program", "curl"}, identity.ExitOK, "already can't run curl"},
		{[]string{"allow", "program", "tego"}, identity.ExitFinding, "could change the rules"},
		{[]string{"allow", "website", "https://api.github.com/repos"}, identity.ExitOK, "can connect to api.github.com"},
		{[]string{"block", "net", "registry.npmjs.org"}, identity.ExitOK, "can't connect to registry.npmjs.org"},
		{[]string{"block", "file", "config/dev.json"}, identity.ExitOK, "can't read config/dev.json"},
		{[]string{"allow", "file", "config/dev.json"}, identity.ExitOK, "can read config/dev.json"},
		{[]string{"allow", "file", ".env"}, identity.ExitFinding, "always blocks .env"},
		{[]string{"block", "file", "nope.txt"}, identity.ExitFinding, "no file at nope.txt"},
		{[]string{"allow", "env", "OPENAI_API_KEY"}, identity.ExitOK, "can see $OPENAI_API_KEY"},
		{[]string{"block", "write"}, identity.ExitOK, "can't change files in demo"},
		{[]string{"block", "write"}, identity.ExitOK, "already can't change files in demo"},
		{[]string{"allow", "write"}, identity.ExitOK, "can change files in demo"},
		// Undo puts things back exactly: npm back into "node, npm", an added block goes away.
		{[]string{"block", "program", "npm"}, identity.ExitOK, "can't run npm"},
		{[]string{"allow", "program", "npm"}, identity.ExitOK, "can run npm"},
		{[]string{"block", "program", "make"}, identity.ExitOK, "can't run make"},
		// Locked files, however they are written.
		{[]string{"allow", "file", "./.env"}, identity.ExitFinding, "always blocks .env"},
		{[]string{"allow", "file", root + "/.env"}, identity.ExitFinding, "always blocks .env"},
		{[]string{"allow", "file", "~/.ssh/id_ed25519"}, identity.ExitFinding, "always blocks ~/.ssh/id_ed25519"},
		{[]string{"block", "file", "~/.ssh/id_ed25519"}, identity.ExitOK, "already can't read"},
		{[]string{"allow", "file", ".env.local"}, identity.ExitFinding, "always blocks"},
		{[]string{"allow", "env", "GITHUB_TOKEN"}, identity.ExitFinding, "push or publish as you"},
		{[]string{"block", "write", "src/"}, identity.ExitUsage, ""},
		{[]string{"allow", "make"}, identity.ExitUsage, "Did you mean: maze allow program make"},
		{[]string{"allow", "teleport", "x"}, identity.ExitUsage, ""},
		{[]string{"allow", "program"}, identity.ExitUsage, ""},
		{[]string{"allow"}, identity.ExitUsage, ""},
	}
	for _, st := range steps {
		code, out, errOut := run(t, append(st.args, "-C", root)...)
		if code != st.code || !strings.Contains(out+errOut, st.says) {
			t.Errorf("maze %v = %d, want %d saying %q\n%s%s", st.args, code, st.code, st.says, out, errOut)
		}
	}
	data, err := os.ReadFile(filepath.Join(root, ".maze", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"value: api.github.com", "value: node, npm"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("workspace.yaml lacks %q:\n%s", want, data)
		}
	}
	for _, gone := range []string{"value: make", "config/dev.json"} {
		if strings.Contains(string(data), gone) {
			t.Errorf("workspace.yaml still has %q after its undo:\n%s", gone, data)
		}
	}
	// Typing the command is the approval: status stays approved.
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitOK || !strings.Contains(out, "approved") {
		t.Errorf("status after allow/block = %d: %s", code, out)
	}
}

func TestAllowRefusesUnapproved(t *testing.T) {
	root := setUpProject(t)
	f := filepath.Join(root, ".maze", "workspace.yaml")
	data, _ := os.ReadFile(f)
	if err := os.WriteFile(f, append(data, []byte("  - {category: websites, verb: reach, value: evil.example, allow: true}\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, _, errOut := run(t, "allow", "program", "make", "-C", root); code != identity.ExitFinding || !strings.Contains(errOut, "changed since you approved") {
		t.Errorf("allow on changed rules = %d: %s", code, errOut)
	}
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitFinding || !strings.Contains(out, "changed since you approved") {
		t.Errorf("status on changed rules = %d: %s", code, out)
	}
}

func TestStatusShowDoctor(t *testing.T) {
	root := setUpProject(t)
	code, out, _ := run(t, "status", "--json", "-C", root)
	var st Status
	if err := json.Unmarshal([]byte(out), &st); err != nil || code != identity.ExitOK || !st.SetUp || !st.Approved || st.Active {
		t.Errorf("status --json = %d %+v %v\n%s", code, st, err, out)
	}
	if code, out, _ := run(t, "workspace", "show", "-C", root); code != identity.ExitOK || !strings.Contains(out, "FILES") || !strings.Contains(out, "can't") {
		t.Errorf("workspace show = %d:\n%s", code, out)
	}
	if code, out, _ := run(t, "profile", "show"); code != identity.ExitOK || !strings.Contains(out, "~/.ssh") {
		t.Errorf("profile show = %d:\n%s", code, out)
	}
	code, out, _ = run(t, "system", "doctor", "-C", root)
	for _, want := range []string{"Claude Code", "This project: demo", "approved", "not active yet"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	if code != identity.ExitOK {
		t.Errorf("doctor = %d, want 0", code)
	}
	if code, out, _ := run(t, "system", "version"); code != identity.ExitOK || !strings.HasPrefix(out, "maze ") {
		t.Errorf("system version = %d: %s", code, out)
	}
	// Flags after the subcommand count: --yes is not ignored.
	if code, out, errOut := run(t, "workspace", "remove", "--yes", "-C", root); code != identity.ExitOK || !strings.Contains(out, "Removed Maze") {
		t.Errorf("workspace remove --yes = %d: %s%s", code, out, errOut)
	}
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitFinding || !strings.Contains(out, "not set up") {
		t.Errorf("status after remove = %d: %s", code, out)
	}
}

func TestHelpCommand(t *testing.T) {
	for _, args := range [][]string{{"help"}, {"--help"}, {"help", "help"}} {
		if code, out, _ := run(t, args...); code != identity.ExitOK || !strings.Contains(out, "Every day") {
			t.Errorf("maze %v = %d:\n%s", args, code, out)
		}
	}
	if code, out, _ := run(t, "help", "allow"); code != identity.ExitOK || !strings.Contains(out, "maze allow program make") {
		t.Errorf("help allow = %d:\n%s", code, out)
	}
	if code, _, errOut := run(t, "help", "run"); code != identity.ExitUsage || !strings.Contains(errOut, "coming soon") {
		t.Errorf("help run = %d: %s", code, errOut)
	}
}

func TestParallelAllowsKeepEveryChange(t *testing.T) {
	root := setUpProject(t)
	var wg sync.WaitGroup
	codes := make([]int, 6)
	for i := range codes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s, _, _ := streams("")
			codes[i] = Main(context.Background(), []string{"allow", "program", fmt.Sprintf("tool%d", i), "-C", root}, s)
		}(i)
	}
	wg.Wait()
	data, _ := os.ReadFile(filepath.Join(root, ".maze", "workspace.yaml"))
	for i, c := range codes {
		if c != identity.ExitOK || !strings.Contains(string(data), fmt.Sprintf("value: tool%d", i)) {
			t.Errorf("tool%d: exit %d, in the file: %v", i, c, strings.Contains(string(data), fmt.Sprintf("tool%d", i)))
		}
	}
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitOK {
		t.Errorf("status after parallel allows = %d: %s", code, out)
	}
}

func TestBlockingGitStaysApproved(t *testing.T) {
	root := setUpProject(t)
	if code, out, errOut := run(t, "block", "program", "git", "-C", root); code != identity.ExitOK {
		t.Fatalf("block git = %d: %s%s", code, out, errOut)
	}
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitOK || !strings.Contains(out, "approved") {
		t.Errorf("status after blocking git = %d: %s", code, out)
	}
	if _, out, _ := run(t, "workspace", "show", "-C", root); !strings.Contains(out, "needs: run git") {
		t.Errorf("the commit row doesn't follow git:\n%s", out)
	}
}

func TestApprovingKeepsTheCommittedFile(t *testing.T) {
	root := setUpProject(t)
	f := filepath.Join(root, ".maze", "workspace.yaml")
	data, _ := os.ReadFile(f)
	committed := append(data, []byte("  - {category: websites, verb: reach, value: api.github.com, allow: true}\n")...)
	if err := os.WriteFile(f, committed, 0o644); err != nil {
		t.Fatal(err)
	}
	p, err := openProject(context.Background(), root)
	if err != nil || p.approval.Same {
		t.Fatalf("openProject = %+v, %v", p.approval, err)
	}
	p.r.keepFile = true
	if _, err := save(context.Background(), p.r, p.rules); err != nil {
		t.Fatal(err)
	}
	if now, _ := os.ReadFile(f); string(now) != string(committed) {
		t.Errorf("approving rewrote the committed file:\n%s", now)
	}
	if code, out, _ := run(t, "status", "-C", root); code != identity.ExitOK || !strings.Contains(out, "approved") {
		t.Errorf("status after approving = %d: %s", code, out)
	}
}
