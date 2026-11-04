// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/presets"
)

func TestMovedProjectUsesItsNewCacheAndTempFolders(t *testing.T) {
	old := project(t, "go.mod", "src/")
	r := compose(t, Options{Name: "demo", Dir: old, Presets: []string{"no-secrets,repo-only-writes"}, Writes: []string{"src/"}})
	moved := filepath.Join(t.TempDir(), "clone")
	if err := os.Rename(old, moved); err != nil {
		t.Fatal(err)
	}
	rt := compile(t, moved, t.TempDir(), r.Contract)
	for key, suffix := range map[string]string{"GOCACHE": ".tego/cache/go-build", "GOMODCACHE": ".tego/cache/go-mod", "TMPDIR": ".tego/tmp"} {
		if got := rt.Set[key]; got != filepath.Join(moved, suffix) {
			t.Errorf("%s = %q", key, got)
		}
	}
	if strings.Contains(string(r.Contract), old) || !strings.Contains(string(r.Contract), agent.ProjectDirToken) {
		t.Fatal("contract is tied to its original directory")
	}
}

func TestHarnessPromptIsLiteralAndModelIsForwarded(t *testing.T) {
	for _, h := range Harnesses() {
		t.Run(h.Name, func(t *testing.T) {
			dir := project(t, "src/")
			prompt := "Explain 'a'; $(touch nope)\nand stop"
			r, err := Compose(Options{Name: "demo", Agent: h.Name, Prompt: prompt, Dir: dir, Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"src/"}})
			if err != nil {
				t.Fatal(err)
			}
			c, ds, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), r.Contract, (&agent.ProfileChain{}).WithBuiltin(presets.Source{}))
			if err != nil || agent.HasErrors(ds) {
				t.Fatalf("load: %v %v", err, ds)
			}
			if c.Command[len(c.Command)-1] != prompt || c.Command[0] == "/bin/sh" || c.Command[len(c.Command)-2] != "--" {
				t.Fatalf("prompt argv: %q", c.Command)
			}
			if len(c.Models) != 1 {
				t.Fatalf("models: %+v", c.Models)
			}
			golden(t, "agent-"+h.Name, dir, r.Contract)
		})
	}
}

func TestClaudeSetupStartsOnePrintTaskWithFreshState(t *testing.T) {
	for _, prompt := range []string{"", "Explain 'a'; $(touch nope)\nand stop"} {
		dir := project(t)
		r, err := Compose(Options{Name: "demo", Agent: "claude-code", Prompt: prompt, Dir: dir, Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"out/"}})
		if err != nil {
			t.Fatal(err)
		}
		c, ds, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), r.Contract, (&agent.ProfileChain{}).WithBuiltin(presets.Source{}))
		if err != nil || agent.HasErrors(ds) {
			t.Fatalf("load: %v %v", err, ds)
		}
		args := c.Command
		sep := slices.Index(args, "--")
		if sep < 0 || (!slices.Contains(args[:sep], "-p") && !slices.Contains(args[:sep], "--print")) {
			t.Fatalf("fresh Claude must use print mode through the forwarder, got %q", args)
		}
		if len(args) != sep+2 || args[sep+1] == "" || (prompt != "" && args[sep+1] != prompt) {
			t.Fatalf("one literal task is required: %q", args)
		}
		if !strings.Contains(strings.Join(r.Notes, "\n"), "print mode") {
			t.Fatalf("setup must explain its noninteractive launch: %v", r.Notes)
		}
	}
}

func TestCodexCredentialGrantIsSpecificToTheChosenSetup(t *testing.T) {
	dir := project(t, "src/")
	for _, explicit := range []bool{false, true} {
		o := Options{Name: "demo", Dir: dir, Presets: []string{"no-secrets,no-prod,repo-only-writes"}, Writes: []string{"src/"}, Command: "codex", AgentNeeds: true}
		want, absent := "OPENAI_API_KEY", "CODEX_API_KEY"
		if explicit {
			o.Agent, o.Command = "codex", ""
			want, absent = absent, want
		}
		r, err := Compose(o)
		if err != nil {
			t.Fatal(err)
		}
		c, ds, err := agent.LoadBytes(filepath.Join(dir, "agent.yaml"), r.Contract, (&agent.ProfileChain{}).WithBuiltin(presets.Source{}))
		if err != nil || agent.HasErrors(ds) {
			t.Fatalf("%v %v", err, ds)
		}
		if !slices.Contains(c.Env.Pass, want) || slices.Contains(c.Env.Pass, absent) {
			t.Errorf("explicit exec=%v: pass %v; want %s without %s", explicit, c.Env.Pass, want, absent)
		}
	}
}
