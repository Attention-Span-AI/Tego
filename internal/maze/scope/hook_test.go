// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// push runs git push in repo with env added, in a new session so there is no terminal to ask in, and returns
// its output and whether it succeeded.
func push(t *testing.T, repo string, env []string) (string, bool) {
	t.Helper()
	cmd := exec.Command("git", "push", "-q", "origin", "HEAD:main")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), env...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	return string(out), err == nil
}

func TestPrePushCheck(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed")
	}
	home := t.TempDir()
	clean := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Sam", "GIT_AUTHOR_EMAIL=sam@example.com", "GIT_COMMITTER_NAME=Sam", "GIT_COMMITTER_EMAIL=sam@example.com"}
	remote, repo := t.TempDir(), t.TempDir()
	gitIn(t, remote, clean, "init", "-q", "--bare")
	gitIn(t, repo, clean, "init", "-q")
	gitIn(t, repo, clean, "remote", "add", "origin", remote)
	commit := func(env []string, msg string) {
		if err := os.WriteFile(filepath.Join(repo, msg+".txt"), []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		gitIn(t, repo, env, "add", ".")
		gitIn(t, repo, env, "commit", "-q", "-m", msg)
	}

	// The person's own hook, which must keep running.
	hooks := filepath.Join(repo, ".git", "hooks")
	ran := filepath.Join(t.TempDir(), "ran")
	if err := os.WriteFile(filepath.Join(hooks, "pre-push"), []byte("#!/bin/sh\ncat >/dev/null\ntouch "+ran+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err := InstallPrePush(home, repo)
	if err != nil || !res.Installed || !res.Chained {
		t.Fatalf("InstallPrePush = %+v, %v", res, err)
	}
	if _, err := InstallPrePush(home, repo); err != nil { // again: an update, not a second chain
		t.Fatalf("second install: %v", err)
	}

	commit(clean, "mine")
	if out, ok := push(t, repo, clean); !ok {
		t.Fatalf("a push of the person's own commit was stopped:\n%s", out)
	}
	if _, err := os.Stat(ran); err != nil {
		t.Error("the person's own pre-push hook didn't run")
	}

	agent := append(clean[:3:3], "GIT_AUTHOR_NAME="+AgentName, "GIT_AUTHOR_EMAIL="+AgentEmail,
		"GIT_COMMITTER_NAME="+AgentName, "GIT_COMMITTER_EMAIL="+AgentEmail)
	commit(agent, "agents")
	out, ok := push(t, repo, clean)
	if ok || !strings.Contains(out, "commits Claude Code made") || !strings.Contains(out, "agents") || !strings.Contains(out, "no terminal") {
		t.Fatalf("a push with an agent commit went through (ok=%v):\n%s", ok, out)
	}
	if out, ok := push(t, repo, append(clean, "MAZE_ALLOW_AGENT_PUSH=1")); !ok {
		t.Fatalf("MAZE_ALLOW_AGENT_PUSH=1 didn't let it through:\n%s", out)
	}

	if err := RemovePrePush(repo); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(filepath.Join(hooks, "pre-push"))
	if strings.Contains(string(data), hookMark) || !strings.Contains(string(data), "touch") {
		t.Errorf("remove didn't put the person's hook back:\n%s", data)
	}
}

func TestPrePushSkips(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	if res, err := InstallPrePush(home, repo); err != nil || res.Installed || !strings.Contains(res.Skipped, "not a git repo") {
		t.Errorf("no .git: %+v, %v", res, err)
	}
	if err := os.MkdirAll(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\thooksPath = .husky\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if res, err := InstallPrePush(home, repo); err != nil || res.Installed || !strings.Contains(res.Skipped, ".husky") {
		t.Errorf("husky: %+v, %v", res, err)
	}
}

func TestPrePushClosesBypasses(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed")
	}
	home := t.TempDir()
	sam := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Sam", "GIT_AUTHOR_EMAIL=sam@example.com", "GIT_COMMITTER_NAME=Sam", "GIT_COMMITTER_EMAIL=sam@example.com"}
	remote, repo, other := t.TempDir(), t.TempDir(), t.TempDir()
	gitIn(t, remote, sam, "init", "-q", "--bare")
	gitIn(t, repo, sam, "init", "-q", "-b", "main")
	gitIn(t, repo, sam, "remote", "add", "origin", remote)
	commit := func(dir string, env []string, msg string) {
		if err := os.WriteFile(filepath.Join(dir, msg+".txt"), []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		gitIn(t, dir, env, "add", ".")
		gitIn(t, dir, env, "commit", "-q", "-m", msg)
	}
	commit(repo, sam, "base")
	if _, ok := push(t, repo, sam); !ok {
		t.Fatal("first push failed")
	}
	// A teammate pushes a commit this clone never fetches.
	gitIn(t, other, sam, "clone", "-q", "-b", "main", remote, ".")
	commit(other, sam, "teammate")
	gitIn(t, other, sam, "push", "-q", "origin", "HEAD:main")

	if res, err := InstallPrePush(home, repo); err != nil || !res.Installed {
		t.Fatalf("InstallPrePush = %+v, %v", res, err)
	}
	// The agent commits with Sam's name as author: the committer still gives it away.
	forged := append(sam[:3:3], "GIT_AUTHOR_NAME=Sam", "GIT_AUTHOR_EMAIL=sam@example.com",
		"GIT_COMMITTER_NAME="+AgentName, "GIT_COMMITTER_EMAIL="+AgentEmail)
	commit(repo, forged, "sneaky")
	cmd := exec.Command("git", "push", "-q", "--force", "origin", "HEAD:main")
	cmd.Dir = repo
	cmd.Env = append(os.Environ(), sam...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "sneaky") {
		t.Fatalf("a force push of a forged agent commit went through:\n%s", out)
	}
}

func TestPrePushHuskyHelper(t *testing.T) {
	home, repo := t.TempDir(), t.TempDir()
	if err := os.MkdirAll(filepath.Join(repo, ".git", "hooks"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".git", "config"), []byte("[core]\n\thooksPath = .husky\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	res, err := InstallPrePush(home, repo)
	if err != nil || res.Installed || !strings.Contains(res.Helper, "maze-pre-push") {
		t.Fatalf("husky: %+v, %v", res, err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "maze-pre-push")); err != nil {
		t.Errorf("the helper isn't there: %v", err)
	}
	if err := RemovePrePush(repo); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(repo, ".git", "hooks", "maze-pre-push")); err == nil {
		t.Error("remove left the helper behind")
	}
}

func TestHuskyLineStopsAndThenGetsOutOfTheWay(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git isn't installed")
	}
	home := t.TempDir()
	sam := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Sam", "GIT_AUTHOR_EMAIL=sam@example.com", "GIT_COMMITTER_NAME=Sam", "GIT_COMMITTER_EMAIL=sam@example.com"}
	remote, repo := t.TempDir(), t.TempDir()
	gitIn(t, remote, sam, "init", "-q", "--bare")
	gitIn(t, repo, sam, "init", "-q", "-b", "main")
	gitIn(t, repo, sam, "remote", "add", "origin", remote)
	gitIn(t, repo, sam, "config", "core.hooksPath", ".husky")
	res, err := InstallPrePush(home, repo)
	if err != nil || res.Helper == "" {
		t.Fatalf("InstallPrePush = %+v, %v", res, err)
	}
	// Sam's husky hook, run by plain sh (no -e), with Maze's line last.
	if err := os.MkdirAll(filepath.Join(repo, ".husky"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".husky", "pre-push"), []byte("#!/bin/sh\necho husky ran\n"+res.Helper+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	agent := append(sam[:3:3], "GIT_AUTHOR_NAME="+AgentName, "GIT_AUTHOR_EMAIL="+AgentEmail,
		"GIT_COMMITTER_NAME="+AgentName, "GIT_COMMITTER_EMAIL="+AgentEmail)
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, agent, "add", "a.txt")
	gitIn(t, repo, agent, "commit", "-q", "-m", "agent work")
	if out, ok := push(t, repo, sam); ok || !strings.Contains(out, "commits Claude Code made") {
		t.Fatalf("the husky line didn't stop an agent push (ok=%v):\n%s", ok, out)
	}
	// Maze removed: the line in Sam's hook must not break his pushes.
	if err := RemovePrePush(repo); err != nil {
		t.Fatal(err)
	}
	if out, ok := push(t, repo, sam); !ok {
		t.Fatalf("after removing Maze, the husky line broke the push:\n%s", out)
	}
}

func TestPrePushCatchesTheAgentsKey(t *testing.T) {
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
	sam := []string{"HOME=" + home, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_AUTHOR_NAME=Sam", "GIT_AUTHOR_EMAIL=sam@example.com", "GIT_COMMITTER_NAME=Sam", "GIT_COMMITTER_EMAIL=sam@example.com"}
	remote, repo := t.TempDir(), t.TempDir()
	gitIn(t, remote, sam, "init", "-q", "--bare")
	gitIn(t, repo, sam, "init", "-q", "-b", "main")
	gitIn(t, repo, sam, "remote", "add", "origin", remote)
	if _, err := InstallPrePush(home, repo); err != nil {
		t.Fatal(err)
	}
	// Sam's name everywhere, but signed with the agent's key: the agent changed its email, not its key.
	signed := append([]string(nil), sam...)
	for _, kv := range GitIdentityEnv(k) {
		if strings.HasPrefix(kv[0], "GIT_CONFIG_") {
			signed = append(signed, kv[0]+"="+kv[1])
		}
	}
	if err := os.WriteFile(filepath.Join(repo, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	gitIn(t, repo, signed, "add", "a.txt")
	gitIn(t, repo, signed, "commit", "-q", "-m", "disguised")
	if out, ok := push(t, repo, sam); ok || !strings.Contains(out, "disguised") {
		t.Fatalf("a commit signed with the agent's key went through under Sam's name (ok=%v):\n%s", ok, out)
	}
}
