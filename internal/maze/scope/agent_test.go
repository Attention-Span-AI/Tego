// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// gitIn runs git in dir with env added, failing the test on error.
func gitIn(t *testing.T, dir string, env []string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
	return string(out)
}

func TestAgentKeySignsCommits(t *testing.T) {
	for _, tool := range []string{"git", "ssh-keygen"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s isn't installed", tool)
		}
	}
	home := t.TempDir()
	k, err := EnsureAgentKey(home)
	if err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(k.Private); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode = %v, %v", fi, err)
	}
	// ssh-keygen reads the key Maze wrote and derives the same public key.
	derived, err := exec.Command("ssh-keygen", "-y", "-f", k.Private).Output()
	if err != nil {
		t.Fatalf("ssh-keygen can't read the key: %v", err)
	}
	pub, _ := os.ReadFile(k.Public)
	if got, want := strings.Fields(string(derived))[1], strings.Fields(string(pub))[1]; got != want {
		t.Fatalf("derived public key %s, want %s", got, want)
	}
	// A second call keeps the key.
	if _, err := EnsureAgentKey(home); err != nil {
		t.Fatal(err)
	}
	if again, _ := os.ReadFile(k.Public); string(again) != string(pub) {
		t.Error("EnsureAgentKey replaced an existing key")
	}

	repo := t.TempDir()
	clean := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null"}
	gitIn(t, repo, clean, "init", "-q")
	var env []string
	for _, kv := range GitIdentityEnv(k) {
		env = append(env, kv[0]+"="+kv[1])
	}
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("hi\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, clean, "add", "a.txt")
	gitIn(t, repo, append(clean, env...), "commit", "-q", "-m", "agent change")
	out := gitIn(t, repo, append(clean, env...), "log", "--show-signature", "-1")
	for _, want := range []string{`Good "git" signature for ` + AgentEmail, "Author: " + AgentName + " <" + AgentEmail + ">"} {
		if !strings.Contains(out, want) {
			t.Errorf("git log lacks %q:\n%s", want, out)
		}
	}
}
