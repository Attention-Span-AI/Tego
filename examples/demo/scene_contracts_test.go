// SPDX-License-Identifier: Apache-2.0

//go:build integration

package demo

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
)

// sceneContracts is the inventory of the contracts the scenes write while they run: for each scene, the files it
// generates under the stage, and the folder tego runs them from (the paths in them are relative to it). TestSceneContractsCompile
// runs every scene with DEMO_DRY=1, finds what it wrote, and holds the files found to this list both ways: a scene
// that writes a contract the list does not name, or a listed file no scene writes, fails; so does a contract that does
// not compile. A scene whose contract comes from somewhere else is not listed here: presets (written by `tego init`)
// and reason-hook (the stand-in Claude Code's, a template filled with a live port, whose unfilled form
// pkg/spec/agent's mount-compatibility test holds).
var sceneContracts = []struct {
	scene []string
	files map[string]string // file under the stage -> the folder, under the stage, tego runs it from
}{
	{[]string{"setup"}, map[string]string{"project/agent.yaml": "project"}},
	{[]string{"rule", "read"}, map[string]string{"c/read.yaml": "project"}},
	{[]string{"rule", "write"}, map[string]string{"c/write.yaml": "project"}},
	{[]string{"rule", "command"}, map[string]string{"c/command.yaml": "project"}},
	{[]string{"rule", "net"}, map[string]string{"c/net.yaml": "project"}},
	{[]string{"rule", "process"}, map[string]string{"c/process.yaml": "project"}},
	{[]string{"always"}, map[string]string{"c/sockets.yaml": "project", "c/privesc.yaml": "project"}},
	{[]string{"limits"}, map[string]string{"c/fork.yaml": "project", "c/memory.yaml": "project"}},
	{[]string{"deny-write"}, map[string]string{"c/hooks.yaml": "project"}},
	{[]string{"ask"}, map[string]string{"c/ask.yaml": "project"}},
	{[]string{"network"}, map[string]string{"project/network.yaml": "project"}},
	{[]string{"claude"}, map[string]string{"claude-code.yaml": "claude-code"}},
	{[]string{"codex"}, map[string]string{"codex.yaml": "codex"}},
	{[]string{"always-on"}, map[string]string{"always-on/project/agent.yaml": "always-on/project",
		"always-on/project/always-on.yaml": "always-on/project"}},
}

// TestSceneContractsCompile: the contracts the scenes generate (a heredoc in a scene, a template with the stage, the
// interpreter and the host's lookup sockets filled in) were never compiled by any test but the Act 2 one, so a scene
// could write a contract tego refuses and nothing said so before a presenter ran it. Each scene is run dry
// (DEMO_DRY=1: it prints its commands and runs none, but writes its contracts), and every contract it wrote is
// compiled, with no error, from the folder the scene runs it in.
func TestSceneContractsCompile(t *testing.T) {
	k := newKit(t)
	// The real-agent scenes need a claude and a codex on PATH to write their contracts; stand-ins are enough, since
	// the scene is dry and compile only looks the command up.
	stubs := stubBin(t, map[string]string{"claude": "exit 0\n", "codex": "exit 0\n", "codex-code-mode-host": "exit 0\n"})
	env := append(append([]string{}, k.env...), "DEMO_DRY=1")
	for i, kv := range env {
		if v, ok := strings.CutPrefix(kv, "PATH="); ok {
			env[i] = "PATH=" + stubs + ":" + v
		}
	}
	// Every scene runs on the one stage, from which what an earlier scene wrote is cleared first, so what is found
	// after a scene is that scene's.
	for _, sc := range sceneContracts {
		name := strings.Join(sc.scene, " ")
		for _, old := range []string{"c", "project", "always-on", "claude-code.yaml", "codex.yaml"} {
			if err := os.RemoveAll(filepath.Join(k.stage, old)); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.Command("sh", append([]string{"demo.sh"}, sc.scene...)...)
		cmd.Env = env
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("demo.sh %s (dry): %v\n%s", name, err, out)
		}
		// The contracts the scene wrote, but for the project's agent.yaml, which every scene that lays the world out
		// writes the same (the setup row holds it) and which the always-on scene writes in its own project.
		var found []string
		for _, root := range []string{"c", "project", "always-on/project", "."} {
			entries, _ := os.ReadDir(filepath.Join(k.stage, root))
			for _, e := range entries {
				rel := filepath.ToSlash(filepath.Join(root, e.Name()))
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") && (rel != "project/agent.yaml" || name == "setup") {
					found = append(found, strings.TrimPrefix(rel, "./"))
				}
			}
		}
		var listed []string
		for rel := range sc.files {
			if rel != "project/agent.yaml" || name == "setup" {
				listed = append(listed, rel)
			}
		}
		sort.Strings(found)
		sort.Strings(listed)
		if !slices.Equal(found, listed) {
			t.Errorf("scene %q writes %v, sceneContracts lists %v: list every contract a scene writes, so it is compiled", name, found, listed)
		}
		for rel, from := range sc.files {
			path := filepath.Join(k.stage, rel)
			b, err := os.ReadFile(path)
			if err != nil {
				t.Errorf("scene %q writes no %s: %v", name, rel, err)
				continue
			}
			for _, ln := range strings.Split(string(b), "\n") {
				if !strings.HasPrefix(strings.TrimSpace(ln), "#") && strings.Contains(ln, "@@") {
					t.Errorf("scene %q: %s still holds a placeholder: %s", name, rel, ln)
				}
			}
			dir := filepath.Join(k.stage, from)
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			compile := exec.Command(k.bin, "rules", "check", path)
			compile.Dir, compile.Env = dir, env
			out, err := compile.CombinedOutput()
			if err != nil {
				t.Errorf("scene %q: tego rules check %s: %v\n%s", name, rel, err, out)
				continue
			}
			for _, ln := range strings.Split(string(out), "\n") {
				if strings.HasPrefix(ln, "error") {
					t.Errorf("scene %q: tego rules check %s: %s", name, rel, ln)
				}
			}
		}
	}
}
