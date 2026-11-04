// SPDX-License-Identifier: Apache-2.0

package agents

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/cli"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// setupStep is one thing an example's comments have a reader do before its first compile, on a machine that has the
// agent's own tools and nothing else set up (bareMachine).
type setupStep struct {
	// says is the instruction's own words, which the example must contain: the step the test takes is one a reader
	// is told to take.
	says string
	// do takes the step on the stand-in machine.
	do func(t *testing.T, m standIn)
}

var (
	// installProfiles copies examples/profiles into the profiles directory the machine config names, as the README's
	// commands do: the directory follows the machine config's trust rule, which a checkout under umask 002
	// (group-writable directories) fails.
	installProfiles = setupStep{says: "examples/profiles", do: func(t *testing.T, m standIn) {
		t.Helper()
		if err := os.CopyFS(m.profiles, os.DirFS(filepath.Join(filepath.Dir(pkgDir), "profiles"))); err != nil {
			t.Fatal(err)
		}
		if err := filepath.WalkDir(m.profiles, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			mode := os.FileMode(0o644)
			if d.IsDir() {
				mode = 0o755
			}
			return os.Chmod(p, mode)
		}); err != nil {
			t.Fatal(err)
		}
	}}
	// installPrices installs examples/prices.example.yaml as the price table the machine config names, mode 0600, as
	// the `install -m 600` of its header does.
	installPrices = setupStep{says: "examples/prices.example.yaml", do: func(t *testing.T, m standIn) {
		t.Helper()
		b, err := os.ReadFile(samplePrices)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(m.prices, b, 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(m.prices, 0o600); err != nil {
			t.Fatal(err)
		}
	}}
	// installSDK is the Claude Agent SDK installed into the project's ./.deps, the directory claude-agent-sdk.yaml's
	// exec entry names: an exec directory must exist.
	installSDK = setupStep{says: "pip install --target .deps", do: func(t *testing.T, m standIn) {
		t.Helper()
		mkdirs(t, filepath.Join(m.work, ".deps"))
	}}
	claudePrivateRuntime = setupStep{says: "install -d -m 700 .claude-state .claude-state/tmp", do: func(t *testing.T, m standIn) {
		t.Helper()
		for _, sub := range []string{"tmp"} {
			if err := os.MkdirAll(filepath.Join(m.work, ".claude-state", sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
	}}

	// makeConfigDir is the project's ./config, which retriever.yaml watches: a watched directory must exist.
	makeConfigDir = setupStep{says: "a config/ directory", do: func(t *testing.T, m standIn) {
		t.Helper()
		mkdirs(t, filepath.Join(m.work, "config"))
	}}
	// codexFiles are the files of a Codex account the Codex examples deny by name, which their CHANGE line has a
	// reader list as they exist on the machine (a deny_read of a missing path is refused); the directory as a whole is
	// not denied, since Codex's own installation lives in it.
	codexFiles = setupStep{says: "CHANGE: the files of your real ~/.codex that exist", do: func(t *testing.T, m standIn) {
		t.Helper()
		mkdirs(t, filepath.Join(m.home, ".codex", "sessions"))
		for _, f := range []string{"auth.json", "config.toml", "history.jsonl"} {
			if err := os.WriteFile(filepath.Join(m.home, ".codex", f), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}}
	// codexChatGPTHome is the Codex home codex-chatgpt.yaml grants, which its header has a reader make (a write
	// entry's parent must exist).
	codexChatGPTHome = setupStep{says: "mkdir -p ~/.local/share/tego/codex-chatgpt", do: func(t *testing.T, m standIn) {
		t.Helper()
		mkdirs(t, filepath.Join(m.home, ".local", "share", "tego", "codex-chatgpt"))
	}}
)

// mkdirs makes each directory and its parents.
func mkdirs(t *testing.T, dirs ...string) {
	t.Helper()
	for _, d := range dirs {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
}

// freshSetup is, for every example, the setup its comments name before its first compile. A file missing here fails
// TestEveryExampleCompilesOnAFreshMachine, so an example added later says what a stranger must do first, and one that
// needs nothing says so with an empty list.
var freshSetup = map[string][]setupStep{
	"anthropic-sdk-python.yaml":    {installProfiles, installPrices},
	"claude-agent-sdk.yaml":        {installSDK, installProfiles, installPrices},
	"claude-code-interactive.yaml": {claudePrivateRuntime},
	"claude-code.yaml":             {installPrices},
	"codex-chatgpt.yaml":           {codexChatGPTHome, codexFiles},
	"codex.yaml":                   {codexFiles},
	"custom-agent.yaml":            {installPrices},
	"retriever.yaml":               {installProfiles, installPrices, makeConfigDir},
}

// TestEveryExampleCompilesOnAFreshMachine is the README's promise to a stranger: on a machine that has the agent's own
// tools and none of a developer's setup (no ~/.ssh, ~/.aws, ~/.netrc or ~/.codex, no profiles, no price table), every
// example compiles once the setup its comments name is done, with no warning that its run will be refused for a
// budget nothing counts ([budget-unmetered]) or that its cost budget cannot price a response (any limits.cost_usd
// budget warning), and the instructions it gives are the steps the test takes. An example that names no setup compiles
// there as it is. Before, compile refused custom-agent.yaml and retriever.yaml for credential files and a /work the
// machine lacked, the profile-extending examples for a profile no default directory held, and claude-code.yaml's run
// for a price table the repository did not ship.
func TestEveryExampleCompilesOnAFreshMachine(t *testing.T) {
	files, err := filepath.Glob(filepath.Join(pkgDir, "*.yaml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no examples: %v", err)
	}
	seen := map[string]bool{}
	for _, f := range files {
		f = filepath.Base(f)
		seen[f] = true
		t.Run(f, func(t *testing.T) {
			steps, ok := freshSetup[f]
			if !ok {
				t.Fatalf("freshSetup does not say what %s needs before its first compile: add it, with the setup its comments name", f)
			}
			src, err := os.ReadFile(filepath.Join(pkgDir, f))
			if err != nil {
				t.Fatal(err)
			}
			m := bareMachine(t)
			for _, s := range steps {
				if !bytes.Contains(src, []byte(s.says)) {
					t.Errorf("%s never tells its reader %q, a step this test takes for it", f, s.says)
				}
				s.do(t, m)
			}
			path := placeOn(t, m, f)
			var out, errb bytes.Buffer
			if code := cli.Main([]string{"tego", "compile", path, "--offline"}, &out, &errb); code != identity.ExitOK {
				t.Fatalf("tego compile %s on a fresh machine, after the setup its comments name: exit %d:\n%s", f, code, errb.String())
			}
			for _, never := range []string{"[budget-unmetered]", "limits.cost_usd budget"} {
				if strings.Contains(errb.String(), never) {
					t.Errorf("tego compile %s on a fresh machine, after the setup its comments name, warns %q:\n%s", f, never, errb.String())
				}
			}
		})
	}
	for name := range freshSetup {
		if !seen[name] {
			t.Errorf("freshSetup names %s, which is no example here", name)
		}
	}
}
