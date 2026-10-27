// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestTokenStoreCreatedDuringRunIsRefused (ADR 0067 D3): a built-in deny_read row
// that does not exist when the contract compiles is still refused when it is created during the run, at tier
// landlock. The realistic case: the harness's directory exists (~/.codex holding only config.toml) and the person
// runs `codex login` or `claude` in another terminal while a long-running agent is going. Compile records the
// absent rows (RuleTable.AbsentDenyRead) and the Landlock ruleset enumerates the directory each would appear in, so a
// name created there later gets no grant; before, only a row directly in the home directory was refused, and only
// when ~/.ssh happened to make Landlock enumerate the home directory. No ~/.ssh is planted here for that reason.
// The files the harnesses keep beside their token stay readable.
//
// A row that is a symlink leading nowhere at compile (~/.vault-token linked into a
// dotfiles directory) is refused once the login writes through the link (RCSD2-2), and under record: full each refused
// read is recorded refused, read_denied, named by its row, where the ledger said allow, unmatched, for a read that
// never happened (RCSD2-1, R2-1).
func TestTokenStoreCreatedDuringRunIsRefused(t *testing.T) {
	sh, _ := filepath.EvalSymlinks("/bin/sh")
	sl, _ := filepath.EvalSymlinks("/usr/bin/sleep")
	if sh == "" || sl == "" {
		t.Skip("needs /bin/sh and /usr/bin/sleep")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	// The directories exist at compile time, their token files do not; the files kept beside them do.
	keep := []string{".codex/config.toml", ".claude/settings.json", ".cargo/config.toml", ".copilot/mcp-config.json"}
	for _, d := range []string{".codex", ".claude", ".cargo", ".terraform.d", ".copilot", "dotfiles"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for _, k := range keep {
		if err := os.WriteFile(filepath.Join(home, k), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "dotfiles", "vault-token"), filepath.Join(home, ".vault-token")); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: tokenlater
command: [%q]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: [%q, %q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: full
`, sh, sh, sl)
	f := newFixtureIn(t, home, contract, nil)
	// Created during the run: file rows in a directory that existed, rows directly in the home directory, a file row
	// whose directory did not exist either, a directory row created with its secret inside, and a row written through
	// the link it was at compile. Each with the row its refusal is named by.
	later := []struct{ path, row string }{
		{".codex/auth.json", ".codex/auth.json"}, {".claude/.credentials.json", ".claude/.credentials.json"},
		{".cargo/credentials.toml", ".cargo/credentials.toml"},
		{".terraform.d/credentials.tfrc.json", ".terraform.d/credentials.tfrc.json"},
		{".copilot/config.json", ".copilot/config.json"},
		{".pgpass", ".pgpass"}, {".claude.json", ".claude.json"}, {".vault-token", ".vault-token"},
		{".gemini/oauth_creds.json", ".gemini/oauth_creds.json"},
		{".azure/msal_token_cache.json", ".azure"}, {".copilot/mcp-secrets/index.json", ".copilot/mcp-secrets"},
	}
	var laterAbs, keepAbs []string
	for _, r := range later {
		laterAbs = append(laterAbs, filepath.Join(home, r.path))
	}
	for _, k := range keep {
		keepAbs = append(keepAbs, filepath.Join(home, k))
	}
	script := `
for f in ` + strings.Join(keepAbs, " ") + `; do
  if (exec 3< "$f"); then echo "KEEP-READ $f"; else echo "KEEP-DENIED $f"; fi
done
echo ready > "$HOME/out/ready"
i=0
while [ ! -e "$HOME/out/go" ] && [ $i -lt 400 ]; do ` + sl + ` 0.05; i=$((i+1)); done
for f in ` + strings.Join(laterAbs, " ") + `; do
  if [ ! -e "$f" ]; then echo "LATER-MISSING $f"; elif (exec 3< "$f"); then echo "LATER-READ $f"; else echo "LATER-DENIED $f"; fi
done
`
	scriptPath := filepath.Join(home, "out", "probe.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	created := make(chan error, 1)
	go func() {
		ready := filepath.Join(home, "out", "ready")
		deadline := time.Now().Add(20 * time.Second)
		for {
			if _, err := os.Stat(ready); err == nil {
				break
			}
			if time.Now().After(deadline) {
				created <- fmt.Errorf("the agent never wrote %s", ready)
				return
			}
			time.Sleep(25 * time.Millisecond)
		}
		for _, p := range laterAbs {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				created <- err
				return
			}
			// Through the link where the row is one, as a login that opens its path with O_CREAT writes.
			if err := os.WriteFile(p, []byte("SECRET"), 0o644); err != nil {
				created <- err
				return
			}
		}
		created <- os.WriteFile(filepath.Join(home, "out", "go"), nil, 0o644)
	}()
	out, code := runProbe(t, f, sh, scriptPath)
	if err := <-created; err != nil {
		t.Fatal(err)
	}
	if code != 0 {
		t.Fatalf("agent exit %d:\n%s", code, out)
	}
	for _, p := range keepAbs {
		if !strings.Contains(out, "KEEP-READ "+p+"\n") {
			t.Errorf("%s, kept beside a token store, is not readable:\n%s", p, out)
		}
	}
	for _, p := range laterAbs {
		if !strings.Contains(out, "LATER-DENIED "+p+"\n") {
			t.Errorf("%s, a built-in row created during the run, was not refused:\n%s", p, out)
		}
	}
	// The record says what the ruleset did: each later read refused, read_denied, by its row (the link's by the
	// place its walk lands as well as by the row's own name).
	lines := openLines(t, f.root)
	for i, r := range later {
		p, rule := laterAbs[i], "fs.deny_read["+filepath.Join(home, r.row)+"]"
		ls := lines[p]
		if r.path == ".vault-token" {
			ls = append(ls, lines[filepath.Join(home, "dotfiles", "vault-token")]...)
		}
		if len(ls) == 0 {
			t.Errorf("no open line for %s", p)
		}
		for _, e := range ls {
			if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != rule {
				t.Errorf("%s: line verdict=%s reason=%s rule=%s, want refused read_denied %s", p, e.Verdict, e.Reason, e.Rule, rule)
			}
		}
	}
	for _, p := range keepAbs {
		for _, e := range lines[p] {
			if e.Verdict != record.VerdictAllow {
				t.Errorf("%s, which the agent read, is recorded %s %s", p, e.Verdict, e.Rule)
			}
		}
	}
}

// TestTokenStoreMadeBeforeTheRunIsRefused: the Landlock builder's other
// states of an absent row. A row written after compile and before the run starts (~/.codex/auth.json, and ~/.netrc
// directly in the home directory) is held then and denied, and recorded so; a row beneath a regular file
// (~/.cargo/credentials with ~/.cargo a file) is no row the ruleset leaves out, and ~/.cargo reads as before.
func TestTokenStoreMadeBeforeTheRunIsRefused(t *testing.T) {
	sh, _ := filepath.EvalSymlinks("/bin/sh")
	if sh == "" {
		t.Skip("needs /bin/sh")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".codex"), 0o755); err != nil {
		t.Fatal(err)
	}
	cargo := filepath.Join(home, ".cargo")
	if err := os.WriteFile(cargo, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	contract := fmt.Sprintf(`version: 0
name: heldnow
command: [%q]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: [%q]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 128
record: full
`, sh, sh)
	f := newFixtureIn(t, home, contract, nil)
	auth, netrc := filepath.Join(home, ".codex", "auth.json"), filepath.Join(home, ".netrc")
	for _, p := range []string{auth, netrc} {
		if err := os.WriteFile(p, []byte("SECRET"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scriptPath := filepath.Join(home, "out", "probe.sh")
	script := `for f in ` + auth + ` ` + netrc + ` ` + cargo + `; do
  if (exec 3< "$f"); then echo "READ $f"; else echo "DENIED $f"; fi
done
`
	if err := os.WriteFile(scriptPath, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, code := runProbe(t, f, sh, scriptPath)
	if code != 0 {
		t.Fatalf("agent exit %d:\n%s", code, out)
	}
	for _, c := range []struct{ path, want string }{{auth, "DENIED"}, {netrc, "DENIED"}, {cargo, "READ"}} {
		if !strings.Contains(out, c.want+" "+c.path+"\n") {
			t.Errorf("%s: want %s:\n%s", c.path, c.want, out)
		}
	}
	lines := openLines(t, f.root)
	for _, p := range []string{auth, netrc} {
		if len(lines[p]) == 0 {
			t.Errorf("no open line for %s", p)
		}
		for _, e := range lines[p] {
			if e.Verdict != record.VerdictRefused || e.Reason != record.ReasonReadDenied || e.Rule != "fs.deny_read["+p+"]" {
				t.Errorf("%s: line verdict=%s reason=%s rule=%s, want refused read_denied by its row", p, e.Verdict, e.Reason, e.Rule)
			}
		}
	}
}

// runProbe runs script under f's table with sh and returns what it printed and its exit code.
func runProbe(t *testing.T, f *fixture, sh, script string) (string, int) {
	t.Helper()
	outFile := filepath.Join(t.TempDir(), "stdout")
	o, err := os.Create(outFile)
	if err != nil {
		t.Fatal(err)
	}
	d := f.deps(t, nil)
	d.Stdio.Out = o
	res, err := Run(context.Background(), f.rt, []string{sh, script}, d)
	o.Close()
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), res.ExitCode
}

// openLines is the run's fs open lines by the path each names.
func openLines(t *testing.T, root string) map[string][]*record.Event {
	t.Helper()
	dirs := runDirs(t, root)
	if len(dirs) != 1 {
		t.Fatalf("%d run directories, want 1", len(dirs))
	}
	out := map[string][]*record.Event{}
	for _, e := range events(t, dirs[0]) {
		var p record.FSPayload
		if e.Kind != record.KindFS || e.DecodePayload(&p) != nil || p.Op != record.FSOpen {
			continue
		}
		out[p.Path] = append(out[p.Path], e)
	}
	return out
}
