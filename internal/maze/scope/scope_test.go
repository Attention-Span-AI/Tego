// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func sampleRules() []Rule {
	return []Rule{
		{Scope: "workspace", Category: "files", Verb: "write", Value: "everything in demo", Allow: true},
		{Scope: "workspace", Category: "files", Verb: "read", Value: ".env", Allow: true, Paths: []string{".env"}},
		{Scope: "workspace", Category: "files", Verb: "read", Value: "keys/deploy.pem", Allow: false, Paths: []string{"keys/deploy.pem"}},
		{Scope: "workspace", Category: "programs", Verb: "run", Value: "node, npm", Allow: true, Programs: []string{"node", "npm"}},
		{Scope: "workspace", Category: "programs", Verb: "run", Value: "maze", Allow: true, Programs: []string{"maze"}},
		{Scope: "workspace", Category: "programs", Verb: "run", Value: "make", Allow: true, Programs: []string{"make"}, Added: true},
		{Scope: "workspace", Category: "websites", Verb: "reach", Value: "registry.npmjs.org", Allow: true, Hosts: []string{"registry.npmjs.org"}},
		{Scope: "workspace", Category: "logins", Verb: "push", Value: "GitHub", Allow: false, Always: true},
		{Scope: "personal", Category: "logins", Verb: "see", Value: "ANTHROPIC_API_KEY", Allow: true},
		{Scope: "personal", Category: "logins", Verb: "see", Value: "GITHUB_TOKEN", Allow: false},
		{Scope: "personal", Category: "files", Verb: "read", Value: "~/.zshrc", Allow: false, Paths: []string{"~/.zshrc"}},
	}
}

func project(t *testing.T) (root, home string) {
	t.Helper()
	root, home = filepath.Join(t.TempDir(), "demo"), t.TempDir()
	for _, f := range []string{filepath.Join(root, ".env"), filepath.Join(root, "keys", "deploy.pem"), filepath.Join(home, ".zshrc")} {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(f, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return root, home
}

func installed(name string) string {
	switch name {
	case "node", "npm", "bash":
		return "/usr/bin/" + name
	}
	return ""
}

func TestCompile(t *testing.T) {
	root, home := project(t)
	c, err := Compile(Input{Root: root, Home: home, Name: "demo", Rules: sampleRules(), LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	s := string(c.Contract)
	for _, want := range []string{
		`write: ["` + root + `"`,
		`deny_read: [`,
		`"` + filepath.Join(home, ".zshrc") + `"`,
		`"` + filepath.Join(root, "keys/deploy.pem") + `"`,
		`allow: ["bash", "node", "npm"]`,
		`"registry.npmjs.org:443"`,
		`pass: ["PATH", "HOME", "LANG", "TERM", "ANTHROPIC_API_KEY", "CLAUDE_CODE_OAUTH_TOKEN"]`,
		"record: full",
		"tier: cgroup",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("contract lacks %s:\n%s", want, s)
		}
	}
	for _, bad := range []string{"deny_read: []", "cost_usd", `"maze"`, `"make"`, "GITHUB_TOKEN"} {
		if strings.Contains(s, bad) {
			t.Errorf("contract contains %s:\n%s", bad, s)
		}
	}
	gaps := strings.Join(c.Gaps, "\n")
	for _, want := range []string{"read .env", "run make"} {
		if !strings.Contains(gaps, want) {
			t.Errorf("gaps lack %q: %v", want, c.Gaps)
		}
	}
	if !strings.Contains(string(c.Verdicts), "action: fs.read") || c.Checks == 0 {
		t.Errorf("verdicts:\n%s", c.Verdicts)
	}
}

// TestQuoteIsYAML: every string the contract quotes reads back as itself, control characters included (a raw
// newline in a double-quoted YAML scalar is folded into a space, which names another path).
func TestQuoteIsYAML(t *testing.T) {
	for _, s := range []string{"plain", "a\nb", "tab\there", `x"y\z`, "ü/ö", "\x1b[2J", "line\u2028sep", "nul\x00"} {
		var got string
		if err := yaml.Unmarshal([]byte("v: "+q(s)+"\n"), &struct{ V *string }{&got}); err != nil {
			t.Errorf("q(%q) = %s: %v", s, q(s), err)
			continue
		}
		if got != s {
			t.Errorf("q(%q) = %s reads back as %q", s, q(s), got)
		}
	}
}

// TestCompileRefusesAControlCharacterInTheRoot: the root is written raw into the contract's comment lines.
func TestCompileRefusesAControlCharacterInTheRoot(t *testing.T) {
	for _, root := range []string{"/tmp/app\nfs:\n  write: [\"/\"]", "/tmp/app\xff"} {
		if _, err := Compile(Input{Root: root, Home: t.TempDir(), Name: "demo", Rules: sampleRules(), LookPath: installed}); err == nil {
			t.Errorf("Compile accepted the root %q", root)
		}
	}
}

func TestReadOnlyProject(t *testing.T) {
	root, home := project(t)
	rules := sampleRules()
	rules[0].Allow = false
	c, err := Compile(Input{Root: root, Home: home, Name: "demo", Rules: rules, LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(c.Contract), `write: ["`+root+`"`) {
		t.Errorf("a read-only project is still writable:\n%s", c.Contract)
	}
	if !strings.Contains(string(c.Contract), "tier: auto") {
		t.Errorf("a read-only project pins a root tier it doesn't need:\n%s", c.Contract)
	}
	if !strings.Contains(string(c.Verdicts), "the project is read-only") {
		t.Errorf("no read-only check:\n%s", c.Verdicts)
	}
}

// TestSaveMakesTheHarnessFolder: the engine refuses a writable project's .claude/ only when it exists, so saving a
// writable contract makes it (and a read-only one, which the agent can't change at all, leaves the project be).
func TestSaveMakesTheHarnessFolder(t *testing.T) {
	root, home := project(t)
	rules := sampleRules()
	c, err := Compile(Input{Root: root, Home: home, Name: "demo", Rules: rules, LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	if !c.Writable {
		t.Fatal("the sample project is not writable")
	}
	if _, err := SaveCompiled(home, root, c, "claude"); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Lstat(filepath.Join(root, ".claude")); err != nil || !fi.IsDir() {
		t.Errorf(".claude after saving a writable contract: %v, %v", fi, err)
	}
	if _, err := SaveCompiled(home, root, c, "claude"); err != nil {
		t.Errorf("a second save with .claude present: %v", err)
	}

	ro, home2 := project(t)
	rules[0].Allow = false
	c, err = Compile(Input{Root: ro, Home: home2, Name: "demo", Rules: rules, LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveCompiled(home2, ro, c, "claude"); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(ro, ".claude")); !os.IsNotExist(err) {
		t.Errorf(".claude after saving a read-only contract: %v", err)
	}

	linked, home3 := project(t)
	if err := os.Symlink(t.TempDir(), filepath.Join(linked, ".claude")); err != nil {
		t.Fatal(err)
	}
	rules[0].Allow = true
	c, err = Compile(Input{Root: linked, Home: home3, Name: "demo", Rules: rules, LookPath: installed})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SaveCompiled(home3, linked, c, "claude"); err == nil {
		t.Error("a linked .claude was accepted")
	}
}

func TestSaveLoadApproveRemove(t *testing.T) {
	root, home := project(t)
	var ws, pers []Rule
	for _, r := range sampleRules() {
		if r.Scope == "personal" {
			pers = append(pers, r)
		} else {
			ws = append(ws, r)
		}
	}
	data, err := SaveWorkspace(root, Workspace{Name: "demo", Owner: "sam", Agent: "claude", Rules: ws})
	if err != nil {
		t.Fatal(err)
	}
	if err := SavePersonal(home, Personal{Rules: pers}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(filepath.Join(home, PersonalFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("personal file mode = %v, %v", fi, err)
	}
	if _, err := SaveWorkspace(root, Workspace{Name: "demo", Rules: ws}); err != nil {
		t.Fatal(err)
	}
	gi, _ := os.ReadFile(filepath.Join(root, ".gitignore"))
	if strings.Count(string(gi), ".maze/state/") != 1 {
		t.Errorf(".gitignore = %q, want the line once", gi)
	}
	w, ok, err := LoadWorkspace(root)
	// The sample allows reading .env (a fixed rule: put back) and running maze (refused: dropped).
	if err != nil || !ok || len(w.Rules) != len(ws)-1 || w.Rules[0].Scope != "workspace" || len(w.Ignored) != 2 {
		t.Fatalf("LoadWorkspace = %+v, %v, %v", w, ok, err)
	}

	a, _ := CheckApproval(home, root)
	if a.Recorded || a.Same || len(a.Rules) != len(ws)-1 {
		t.Errorf("never-approved rules = %+v, want them all listed", a)
	}
	if err := Approve(home, root, data); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, WorkspaceFile), []byte(strings.Replace(string(data), "allow: false", "allow: true", 1)), 0o644); err != nil {
		t.Fatal(err)
	}
	a, _ = CheckApproval(home, root)
	if a.Same || len(a.Changes) != 1 || a.Changes[0].Kind != "flipped" {
		t.Errorf("after a flip = %+v", a)
	}
	if err := Restore(home, root); err != nil {
		t.Fatal(err)
	}
	if a, _ = CheckApproval(home, root); !a.Same {
		t.Errorf("after restore = %+v, want same", a)
	}

	if err := RemoveWorkspace(home, root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(root, WorkspaceDir)); !os.IsNotExist(err) {
		t.Errorf(".maze still there: %v", err)
	}
	if _, ok, _ := readFile(approvalPath(home, root)); ok {
		t.Error("approval record still there")
	}
	if gi, _ := os.ReadFile(filepath.Join(root, ".gitignore")); strings.Contains(string(gi), ".maze") {
		t.Errorf(".gitignore still has Maze's lines: %q", gi)
	}
	if err := RemovePersonal(home); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := LoadPersonal(home); ok {
		t.Error("personal file still there")
	}
}

func TestLinkRefused(t *testing.T) {
	root, _ := project(t)
	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, WorkspaceDir), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, WorkspaceFile)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := LoadWorkspace(root); err == nil {
		t.Error("a workspace file that is a link was read")
	}
	if _, err := SaveWorkspace(root, Workspace{Name: "demo"}); err == nil {
		t.Error("a workspace file that is a link was replaced")
	}
	if data, _ := os.ReadFile(target); string(data) != "x" {
		t.Errorf("the link's target was changed: %q", data)
	}
}
