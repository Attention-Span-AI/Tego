// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// saved writes a workspace with rules, approves it, and returns the project folder and home.
func saved(t *testing.T, rules []Rule) (root, home string) {
	t.Helper()
	root, home = t.TempDir(), t.TempDir()
	data, err := SaveWorkspace(root, Workspace{Name: "demo", Rules: rules})
	if err != nil {
		t.Fatal(err)
	}
	if err := Approve(home, root, data); err != nil {
		t.Fatal(err)
	}
	return root, home
}

// edit replaces old with new in the project's workspace file.
func edit(t *testing.T, root, old, new string) {
	t.Helper()
	f := filepath.Join(root, WorkspaceFile)
	data, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), old) {
		t.Fatalf("%q isn't in the file:\n%s", old, data)
	}
	if err := os.WriteFile(f, []byte(strings.Replace(string(data), old, new, 1)), 0o644); err != nil {
		t.Fatal(err)
	}
}

var sample = []Rule{
	{Category: "files", Verb: "read", Value: ".env", Allow: false, Always: true, Paths: []string{".env"}},
	{Category: "programs", Verb: "run", Value: "git", Allow: true, Programs: []string{"git"}},
	{Category: "programs", Verb: "run", Value: "anything else", Allow: false, Always: true},
	{Category: "websites", Verb: "reach", Value: "registry.npmjs.org", Allow: true, Why: "npm packages", Hosts: []string{"registry.npmjs.org"}},
}

func TestLockedRulesStayLocked(t *testing.T) {
	root, home := saved(t, sample)
	edit(t, root, "value: .env\n    allow: false", "value: .env\n    allow: true")
	w, _, err := LoadWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if w.Rules[0].Allow || len(w.Ignored) != 1 {
		t.Errorf("a file unlocked .env: %+v ignored %+v", w.Rules[0], w.Ignored)
	}
	a, _ := CheckApproval(home, root)
	if a.Same || len(a.Ignored) != 1 || len(a.Changes) != 0 {
		t.Errorf("approval after unlocking .env = %+v", a)
	}
}

func TestListAdditionsShow(t *testing.T) {
	root, home := saved(t, sample)
	edit(t, root, "programs:\n      - git", "programs:\n      - git\n      - curl")
	a, _ := CheckApproval(home, root)
	if a.Same || len(a.Changes) != 1 || a.Changes[0].Rule.Value != "curl" || a.Changes[0].Kind != "added" || !a.Changes[0].Rule.Allow {
		t.Errorf("curl slipped into git's row: %+v", a)
	}
	// A reworded note changes nothing that is enforced: no approval needed.
	root, home = saved(t, sample)
	edit(t, root, "why: npm packages", "why: npm stuff")
	if a, _ := CheckApproval(home, root); !a.Same {
		t.Errorf("a reworded note needs approval: %+v", a)
	}
}

func TestBadFilesRefused(t *testing.T) {
	for name, change := range map[string][2]string{
		"control character": {"value: git", "value: \"g\\e[2Jit\""},
		"unknown field":     {"value: git", "value: git\n    sneaky: true"},
		"unknown category":  {"category: websites", "category: rockets"},
	} {
		root, _ := saved(t, sample)
		edit(t, root, change[0], change[1])
		var bad *BadFileError
		if _, _, err := LoadWorkspace(root); !errors.As(err, &bad) {
			t.Errorf("%s: LoadWorkspace = %v, want a BadFileError", name, err)
		}
	}
	root, _ := saved(t, sample)
	if err := os.WriteFile(filepath.Join(root, WorkspaceFile), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWorkspace(root); err == nil || !strings.Contains(err.Error(), "empty") {
		t.Errorf("an empty file: %v", err)
	}
}

func TestLinkedMazeFolderRefused(t *testing.T) {
	root, elsewhere := t.TempDir(), t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, WorkspaceDir)); err != nil {
		t.Fatal(err)
	}
	if _, err := SaveWorkspace(root, Workspace{Name: "demo", Rules: sample}); err == nil || !strings.Contains(err.Error(), "is a link") {
		t.Errorf("SaveWorkspace through a linked .maze = %v", err)
	}
	if entries, _ := os.ReadDir(elsewhere); len(entries) != 0 {
		t.Errorf("Maze wrote outside the project: %v", entries)
	}
}

func TestRemoveRefusesHome(t *testing.T) {
	home := t.TempDir()
	if err := RemoveWorkspace(home, home); err == nil {
		t.Error("RemoveWorkspace removed the home folder's .maze")
	}
}

func TestFileCantDecideWhatIsFixed(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	rules := []Rule{
		// No `always: true`, and allowed: still a fixed, blocked rule.
		{Category: "logins", Verb: "push", Value: "GitHub", Allow: true},
		{Category: "files", Verb: "read", Value: "~/.ssh", Allow: true, Paths: []string{"~/.ssh"}},
		{Category: "files", Verb: "read", Value: "config/.ENV", Allow: true, Paths: []string{"config/.ENV"}},
		{Category: "logins", Verb: "see", Value: "GITHUB_TOKEN", Allow: true},
		{Category: "logins", Verb: "see", Value: "SSH_AUTH_SOCK", Allow: true},
		{Category: "programs", Verb: "run", Value: "anything else", Allow: true},
		// A label that hides what the row really allows.
		{Category: "websites", Verb: "reach", Value: "registry.npmjs.org", Why: "npm packages", Allow: true, Hosts: []string{"registry.npmjs.org", "evil.example"}},
		{Category: "programs", Verb: "run", Value: "basic tools", Allow: true, Programs: []string{"ls", "curl", "bash"}},
		// Things Add a rule refuses.
		{Category: "programs", Verb: "run", Value: "MAZE", Allow: true, Programs: []string{"MAZE"}},
		{Category: "websites", Verb: "reach", Value: "127.0.0.1", Allow: true, Hosts: []string{"127.0.0.1"}},
		{Category: "files", Verb: "write", Value: "/etc", Allow: true},
		// A note Maze never writes.
		{Category: "programs", Verb: "run", Value: "make", Why: "approved by security", Allow: true, Programs: []string{"make"}},
	}
	got, ignored := normalize(home, rules, false)
	byValue := map[string]Rule{}
	for _, r := range got {
		byValue[r.Value] = r
	}
	for _, v := range []string{"GitHub", "~/.ssh", "config/.ENV", "GITHUB_TOKEN", "SSH_AUTH_SOCK", "anything else"} {
		if r, ok := byValue[v]; !ok || r.Allow || !r.Always {
			t.Errorf("%s = %+v, want fixed and blocked", v, r)
		}
	}
	if r := byValue["registry.npmjs.org, evil.example"]; !r.Allow {
		t.Errorf("the hidden host isn't in the label: %+v", got)
	}
	if r, ok := byValue["curl"]; !ok || !r.Allow {
		t.Errorf("curl hid inside basic tools: %+v", got)
	}
	if r := byValue["basic tools"]; slices.Contains(r.Programs, "bash") || slices.Contains(r.Programs, "curl") {
		t.Errorf("basic tools still lists %v", r.Programs)
	}
	for _, v := range []string{"MAZE", "127.0.0.1", "/etc"} {
		if _, ok := byValue[v]; ok {
			t.Errorf("%s was kept", v)
		}
	}
	if r := byValue["make"]; r.Why != "" {
		t.Errorf("a made-up note was kept: %q", r.Why)
	}
	if len(ignored) < 9 {
		t.Errorf("only %d changes reported: %+v", len(ignored), ignored)
	}
}
