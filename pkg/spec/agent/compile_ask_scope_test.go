// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

func TestAskScopeDoesNotGrantWriteAndKeepsProtectedConfiguration(t *testing.T) {
	root := t.TempDir()
	configDir, work, home := filepath.Join(root, "config"), filepath.Join(root, "work"), filepath.Join(root, "home")
	for _, path := range []string{configDir, work, home, filepath.Join(work, ".claude")} {
		if err := os.MkdirAll(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	c, ds, err := LoadBytes(filepath.Join(configDir, "agent.yaml"), []byte("version: 0\nname: ask-scope\ncommand: [/bin/true]\nfs: {deny_read: []}\n"), nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	// Exercise compiled scope protections directly, independently of the loader.
	// Exercise the compiler boundary directly while that integration is in flight.
	c.FS.Ask = []string{work}
	rt, ds, err := Compile(c, &config.Machine{}, Offline(), WithCwd(work), WithHome(home), WithMountInfo(""))
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	if len(rt.FSAsk) != 1 || len(ordinaryDenyWriteRows(rt)) != 0 {
		t.Fatal("ask scope changed ordinary write authority")
	}
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		if got := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(work, "result")}, tier); got.Verdict != VerdictRefused {
			t.Fatalf("ask silently grants write at %s: %+v", tier, got)
		}
	}
	if _, protected := rt.AskDenyWriteTarget(filepath.Join(work, ".claude", "settings.json"), false); !protected {
		t.Fatal("approval scope lost harness guard")
	}
	c.FS.Ask = []string{filepath.Join(work, ".claude")}
	rt, ds, err = Compile(c, &config.Machine{}, Offline(), WithCwd(work), WithHome(home), WithMountInfo(""))
	if err != nil {
		t.Fatalf("compile explicit leaf: %v %v", err, ds)
	}
	if _, protected := rt.AskDenyWriteTarget(filepath.Join(work, ".claude", "settings.json"), false); !protected {
		t.Fatal("explicit ask leaf regranted protected config")
	}
	c.FS.Ask = []string{configDir}
	if _, _, err := Compile(c, &config.Machine{}, Offline(), WithCwd(work), WithHome(home), WithMountInfo("")); err == nil {
		t.Fatal("contract directory became approvable")
	}
}
