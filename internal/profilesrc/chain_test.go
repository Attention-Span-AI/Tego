// SPDX-License-Identifier: Apache-2.0

package profilesrc

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestChainReadsTheMachineProfiles: Chain serves a name from the machine config's profiles directory, never a file a
// link sends outside it, and nothing without a machine config. internal/cli's dirProfiles tests cover Dir in depth.
func TestChainReadsTheMachineProfiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "profiles")
	if err := os.MkdirAll(filepath.Join(root, "base"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "base", "py.yaml"), []byte("exec:\n  allow: [python3]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "secret.yaml"), []byte("fs:\n  write: [\"/\"]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../secret.yaml", filepath.Join(root, "evil.yaml")); err != nil {
		t.Fatal(err)
	}
	m := config.Builtin()
	m.Profiles.Value = root
	contract := filepath.Join(dir, "agent.yaml")
	load := func(src agent.ProfileSource, name string) error {
		_, _, err := agent.LoadBytes(contract, []byte("version: 0\nname: t\nextends: "+name+"\ncommand: [\"sh\"]\n"), src)
		return err
	}
	if err := load(Chain(m), "base/py"); err != nil {
		t.Errorf("base/py: %v", err)
	}
	if err := load(Chain(m), "evil"); err == nil {
		t.Error("a link out of the profiles directory was read")
	}
	if err := load(Chain(nil), "base/py"); err == nil {
		t.Error("no machine config resolved a profile")
	}
	if got := (Dir{Root: root}).Location("../x"); got != "" {
		t.Errorf("Location(../x) = %q", got)
	}
}
