// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/maze/scan"
)

// withSettings writes Claude Code settings into the fixture's project (.claude/settings.json and
// settings.local.json) and home, then reads them the way setup does.
func withSettings(t *testing.T, r Report, shared, local, personal string) Report {
	t.Helper()
	for path, body := range map[string]string{
		filepath.Join(r.Workspace.Root, ".claude", "settings.json"):       shared,
		filepath.Join(r.Workspace.Root, ".claude", "settings.local.json"): local,
		filepath.Join(r.Home, ".claude", "settings.json"):                 personal,
	} {
		if body == "" {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var problems []string
	r.Claude, problems = scan.ClaudeRules(r.env, r.Workspace.Root)
	r.ClaudeProblem = strings.Join(problems, "; ")
	return r
}

// how is the translation line for a rule, by the rule as written.
func how(t *testing.T, tr translation, rule string) Translation {
	t.Helper()
	for _, x := range tr.lines {
		if x.Rule == rule {
			return x
		}
	}
	t.Fatalf("no line for %s in %+v", rule, tr.lines)
	return Translation{}
}

func TestClaudeTranslation(t *testing.T) {
	r := fixture(t, true)
	r = withSettings(t, r,
		`{"permissions":{"deny":["Bash(npm)","Bash(git push*)","Read(~/.aws/**)"],"allow":["Bash(make*)","WebFetch(domain:api.github.com)","Read(~/.ssh/**)"]}}`,
		`{"permissions":{"allow":["Bash(OPENAI_API_KEY=sk-PLANTED-x python3 run.py)","Bash(curl -H \"Authorization: Bearer ghp_PLANTEDtoken\" x)","WebFetch(domain:example.org)"]}}`,
		`{"permissions":{"allow":["Bash(make)"],"deny":["WebFetch(domain:api.github.com)"]}}`)
	rules := buildRules(r, true)
	tr := translateClaude(r, rules)

	for _, x := range tr.lines {
		if strings.Contains(x.Rule, "PLANTED") {
			t.Errorf("a secret was printed: %s", x.Rule)
		}
	}
	if x := how(t, tr, "Read(~/.aws/**)"); !x.Covered {
		t.Errorf("deny ~/.aws isn't covered: %+v", x)
	}
	if x := how(t, tr, "Read(~/.ssh/**)"); !x.Covered || !strings.Contains(x.How, "stricter") {
		t.Errorf("allow ~/.ssh: %+v", x)
	}
	// A deny anywhere beats an allow: the personal deny on api.github.com keeps the shared allow out.
	if x := how(t, tr, "WebFetch(domain:api.github.com)"); x.List == "allow" && x.Covered {
		t.Errorf("an allow beat a deny: %+v", x)
	}
	// Local and personal allows are listed, never copied into the shared file.
	if x := how(t, tr, "WebFetch(domain:example.org)"); x.Covered || !strings.Contains(x.How, "yours alone") {
		t.Errorf("a local allow was imported: %+v", x)
	}
	// A whole-program deny switches off Maze's own suggestion.
	for _, rl := range rules {
		if rl.Category == "programs" && rl.Allow && strings.Contains(strings.Join(rl.Programs, ","), "npm") {
			t.Errorf("npm is still suggested although Claude Code denies it: %+v", rl)
		}
	}
	// Imported rules aren't counted as the person's changes.
	for _, rl := range rules {
		if strings.HasPrefix(rl.Why, "from ") && (rl.Added || rl.Allow != rl.Suggested) {
			t.Errorf("an imported rule counts as a change: %+v", rl)
		}
	}
}

func TestClaudeBrokenFileKeepsOthers(t *testing.T) {
	r := fixture(t, true)
	r = withSettings(t, r, `{not json`, `{"permissions":{"deny":["Bash(git push*)"]}}`, "")
	if !strings.Contains(r.ClaudeProblem, "settings.json isn't valid JSON") {
		t.Errorf("problem = %q", r.ClaudeProblem)
	}
	if len(r.Claude) != 1 {
		t.Errorf("the good file's rules were dropped: %+v", r.Claude)
	}
}

func TestMaskSecrets(t *testing.T) {
	for _, in := range []string{
		`Bash(curl -u admin:PLANTEDbasicpw https://x)`,
		`Bash(mysql -pPLANTEDmysqlpw db)`,
		`Bash(curl -H "X-Api-Key: PLANTEDapikeyheader123" x)`,
		`Bash(curl -H "Authorization: Bearer PLANTEDtoken" x)`,
		`Bash(aws configure set aws_secret_access_key PLANTEDawsSecret1234567890abcdefghijk)`,
		`Bash(curl -H "Cookie: session=PLANTEDcookie" x)`,
		`Bash(echo eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJQTEFOVEVEIn0.PLANTEDsignaturePart)`,
		`Bash(psql postgres://user:PLANTEDpw@host/db)`,
		`Bash(OPENAI_API_KEY=PLANTED python3 run.py)`,
		// By structure: the value after a flag or setting named like a secret, whatever its shape.
		`Bash(docker login -u me -p PLANTEDhunter2pass)`,
		`Bash(mysql --password PLANTEDs3cretpw)`,
		`Bash(tool --api-key PLANTEDs3cr3tvalue)`,
		`Bash(tool --secret PLANTEDhunter2)`,
		`Bash(tool --token=PLANTEDt0k)`,
		`Bash(aws configure set aws_secret_access_key PLANTEDwJalrXUtnFEMIK7MDENG)`,
		`Bash(tool --password "PLANTED two words" next)`,
		`Bash(tool --auth-token PLANTEDx*)`,
		`Bash(mysql -u root -p PLANTEDdbpw)`,
	} {
		if got := maskSecrets(in); strings.Contains(got, "PLANTED") {
			t.Errorf("maskSecrets(%s) = %s", in, got)
		}
	}
	// What isn't secret stays readable.
	for _, plain := range []string{"Bash(npm run test:*)", "Bash(mkdir -p build)", "Bash(git commit --author me -m x)",
		"Bash(ssh --key-file id.pub host)", "Bash(git push --no-verify)"} {
		if got := maskSecrets(plain); got != plain {
			t.Errorf("a plain rule changed: %s -> %s", plain, got)
		}
	}
	for in, want := range map[string]string{
		`Bash(mysql --password s3cretpw)`:         `Bash(mysql --password •••)`,
		`Bash(tool --password "a b" next)`:        `Bash(tool --password ••• next)`,
		`Bash(tool --auth-token x*)`:              `Bash(tool --auth-token •••)`,
		`Bash(docker login -u me -p hunter2pass)`: `Bash(docker login -u me -p •••)`,
		`Bash(tool --api-key=v1 --secret v2 cmd)`: `Bash(tool --api-key=••• --secret ••• cmd)`,
	} {
		if got := maskSecrets(in); got != want {
			t.Errorf("maskSecrets(%s) = %s, want %s", in, got, want)
		}
	}
	if got := maskSecrets(`Bash(curl -H "Authorization: Bearer PLANTED" x)`); !strings.Contains(got, "Bearer •••") {
		t.Errorf("the Bearer mask hid the wrong word: %s", got)
	}
}

// The approval screen says whether a git command changed the rules file at the same moment.
func TestChangeSource(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, ".maze", "workspace.yaml")
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 10, 4, 14, 2, 0, 0, time.Local)
	if err := os.Chtimes(file, when, when); err != nil {
		t.Fatal(err)
	}
	now := when.Add(time.Hour)
	if got := changeSource(root, now); !strings.Contains(got, "today at 14:02, not by a git command") {
		t.Errorf("no git: %q", got)
	}
	logs := filepath.Join(root, ".git", "logs")
	if err := os.MkdirAll(logs, 0o755); err != nil {
		t.Fatal(err)
	}
	commit := fmt.Sprintf("aaa bbb Dana <dana@x.io> %d -0400\tcommit: start\n", when.Add(time.Second).Unix())
	if err := os.WriteFile(filepath.Join(logs, "HEAD"), []byte(commit), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := changeSource(root, now); !strings.Contains(got, "not by a git command") {
		t.Errorf("a commit writes no files, yet: %q", got)
	}
	line := fmt.Sprintf("aaa bbb Dana <dana@x.io> %d -0400\tpull: Fast-forward\n", when.Add(time.Second).Unix())
	if err := os.WriteFile(filepath.Join(logs, "HEAD"), []byte(line), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := changeSource(root, now); !strings.Contains(got, "by git: pull: Fast-forward") {
		t.Errorf("after a pull: %q", got)
	}
}
