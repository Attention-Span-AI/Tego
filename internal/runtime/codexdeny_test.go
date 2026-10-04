// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// A deny_read over the user's codex config keeps the launcher from copying it into the run's own, which the
// agent reads (capture-derive.md R19b).
func TestCodexConfigUnderDenyReadIsNotCopied(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("a root launcher writes no CODEX_HOME")
	}
	userHome := t.TempDir()
	if err := os.WriteFile(filepath.Join(userHome, "config.toml"), []byte("secret = \"x\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, deny := range []string{userHome, filepath.Join(userHome, "config.toml")} {
		t.Setenv("XDG_RUNTIME_DIR", privateTempDir(t))
		rt := &agent.RuleTable{FS: []agent.FSRule{{Path: deny, Kind: agent.FSDenyRead}}}
		const base = "http://127.0.0.1:41001/v1"
		r := &runner{
			id: "r-00000000-000000000000a-aaaaaa", rt: rt, log: slog.New(slog.DiscardHandler),
			deps: Deps{
				Capture: []source.Source{&fakeLoopback{name: "forwarder", vars: map[string]string{envOpenAIBaseURL: base}}},
				Environ: []string{"HOME=/nonexistent", identity.EnvCodexHome + "=" + userHome},
			},
		}
		if err := r.createRuntimeDir(); err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(r.runtimeDir, codexHomeName, codexConfigFile))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(got), "secret") {
			t.Fatalf("deny_read %s: the denied config was copied:\n%s", deny, got)
		}
	}
}
