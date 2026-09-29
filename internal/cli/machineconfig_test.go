// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestLoadMachineAppliesTheLayersInPrecedenceOrder is limits-check-doctor-cli.md R24 at the seam every
// command uses: loadMachine resolves the layers once, the later layer (the per-user file, then
// $TEGO_CONFIG) wins a setting, and a ceiling a later layer names above an earlier one's stays where the
// earlier layer put it, because ceilings are only lowered.
func TestLoadMachineAppliesTheLayersInPrecedenceOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	user := write("user.yaml", "retention: 7d\nstop_grace: 20s\ntier: cgroup\nledger_root: "+filepath.Join(dir, "runs")+"\n")
	env := write("env.yaml", "retention: 3d\ntier: bpflsm\n")

	prev := machineSources
	t.Cleanup(func() { machineSources = prev })
	machineSources = func(uid int, secure bool) (config.Sources, string, []config.Diagnostic) {
		return config.Sources{User: user, EnvFile: env}, dir, nil
	}
	m, diags, err := loadMachine(config.TrustWarn)
	for _, d := range diags {
		t.Log(d.String())
	}
	if err != nil {
		t.Fatalf("loadMachine: %v", err)
	}
	if got, want := m.Retention.Value, 3*24*time.Hour; got != want {
		t.Errorf("retention %v, want the $TEGO_CONFIG layer's %v (last layer wins)", got, want)
	}
	if got, want := m.StopGrace.Value, 20*time.Second; got != want {
		t.Errorf("stop_grace %v, want the user layer's %v (a layer that does not name a setting leaves it)", got, want)
	}
	if !m.Tier.Bounded || m.Tier.Value.Tier != "cgroup" {
		t.Errorf("tier ceiling %+v: a later layer must not raise it above the user layer's cgroup", m.Tier)
	}
}
