// SPDX-License-Identifier: Apache-2.0

package decide_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestHeldReadsKeepAWriteEntryInsideABuiltInHomePath is compile --test's answer for a contract that writes beneath a
// built-in home deny_read (~/.ssh/out/) and holds its reads at tier landlock for a .env the scan found inside its
// other write entry: the read the nearer write entry grants is allowed at landlock as at the root tiers, and the rest
// of ~/.ssh stays refused (ADR 0069 D3 (a) and (c), SEMANTICS §2's nearest entry). Before the fix the held-read
// floor's home pattern refused it at landlock alone.
func TestHeldReadsKeepAWriteEntryInsideABuiltInHomePath(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	for _, d := range []string{filepath.Join(home, ".ssh", "out"), filepath.Join(home, ".config", "gh", "out"),
		filepath.Join(root, "app"), filepath.Join(root, "ledger")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "app", ".env"), []byte("SECRET=1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "agent.yaml")
	data := []byte("version: 0\nname: held\ncommand: [\"/bin/sh\"]\nfs:\n  write: [\"app/\", \"~/.ssh/out/\", \"~/.config/gh/out/\"]\n")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	c, ds, err := agent.LoadBytes(path, data, nil)
	if err != nil {
		t.Fatalf("load: %v %v", err, ds)
	}
	m := config.Builtin()
	m.LedgerRoot.Value = filepath.Join(root, "ledger")
	rt, ds, err := agent.Compile(c, m, agent.WithCwd(root), agent.WithHome(home), agent.WithMountInfo(""), agent.Offline())
	if err != nil {
		t.Fatalf("compile: %v %v", err, ds)
	}
	if !rt.ReadsHeldAt(backend.TierLandlock) {
		t.Fatalf("app/.env is nested in app/, yet reads are not held at landlock: %+v", rt.Reads)
	}
	ev := decide.NewEvaluator(rt)
	for _, tc := range []struct {
		path    string
		verdict agent.Verdict
	}{
		{filepath.Join(home, ".ssh", "out", "x"), agent.VerdictAllow},
		{filepath.Join(home, ".config", "gh", "out", "hosts.yml"), agent.VerdictAllow},
		{filepath.Join(home, ".ssh", "id_ed25519"), agent.VerdictRefused},
		{filepath.Join(home, ".config", "gh", "hosts.yml"), agent.VerdictRefused},
		{filepath.Join(root, "app", ".env"), agent.VerdictRefused},
	} {
		for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierBPFLSM} {
			a := agent.Action{Kind: agent.ActionFSRead, Path: tc.path}
			for _, got := range []agent.EvalResult{decide.Evaluate(rt, a, tier), ev.Evaluate(a, tier)} {
				if got.Verdict != tc.verdict {
					t.Errorf("read %s at %s: %s via %s, want %s", tc.path, tier, got.Verdict, got.Rule, tc.verdict)
				}
			}
		}
	}
}
