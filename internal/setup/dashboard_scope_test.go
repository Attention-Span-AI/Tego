// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestDashboardScopeRetainsConfiguredLedger(t *testing.T) {
	dir := t.TempDir()
	served := filepath.Join(dir, "served")
	machine := config.Builtin()
	machine.LedgerRoot.Value = filepath.Join(dir, "configured-before")
	_, before, err := DashboardScope(machine, served)
	if err != nil {
		t.Fatal(err)
	}
	machine.LedgerRoot.Value = served
	_, after, err := DashboardScope(machine, served)
	if err != nil {
		t.Fatal(err)
	}
	if before == after {
		t.Fatal("an explicit served ledger erased a change in the loaded machine's ledger setting")
	}
}

// Configuration identity includes the baseline and the selected source digest,
// even when the ordinary effective settings happen to remain equal.
func TestDashboardScopeRetainsPrivateConfigurationState(t *testing.T) {
	for _, changed := range []string{
		"version: 0\nbaseline: {fs: {deny_read: [/two]}}\n",
		"version: 0\nbaseline: {fs: {deny_read: [/one]}}\n# changed source\n",
	} {
		t.Run(changed, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, "machine.yaml")
			load := func(text string) *config.Machine {
				t.Helper()
				if err := os.WriteFile(file, []byte(text), 0600); err != nil {
					t.Fatal(err)
				}
				m, ds, err := config.LoadSources(config.Sources{User: file}, dir, os.Getuid(), config.TrustAbort)
				if err != nil || config.HasErrors(ds) {
					t.Fatalf("load: %v %v", err, ds)
				}
				return m
			}
			before := load("version: 0\nbaseline: {fs: {deny_read: [/one]}}\n")
			_, a, err := DashboardScope(before, dir)
			if err != nil {
				t.Fatal(err)
			}
			after := load(changed)
			_, b, err := DashboardScope(after, dir)
			if err != nil || a == b {
				t.Fatalf("configuration change did not invalidate scope: %q %q %v", a, b, err)
			}
			_, unchanged, err := DashboardScope(before, dir)
			if err != nil || a != unchanged {
				t.Fatal("scope reread a changed source instead of its loaded snapshot")
			}
		})
	}
}
