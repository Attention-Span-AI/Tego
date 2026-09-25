// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// A symlinked entry governs its target's inode in tier 1, and tier 2 matches both spellings, so Evaluate
// matches the target's path as well as the declared one.
func TestEvaluateMatchesSymlinkedEntryUnderItsTarget(t *testing.T) {
	f := newFixture(t)
	safe := filepath.Join(f.root, "safe")
	realOut := filepath.Join(f.root, "realout")
	for _, d := range []string{safe, realOut} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	f.file(filepath.Join(safe, "key"), "k", 0o600)
	if err := os.Symlink(safe, filepath.Join(f.project, "secretlink")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(realOut, filepath.Join(f.project, "outlink")); err != nil {
		t.Skip(err)
	}
	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\nfs:\n  write: [\"outlink/\"]\n  deny_read: [\"secretlink\"]\n"))
	t.Log(render(ds))
	for _, tier := range []backend.Tier{backend.TierLandlock, backend.TierCgroup, backend.TierBPFLSM} {
		r := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(safe, "key")}, tier)
		if r.Verdict != VerdictRefused || r.Rule != "fs.deny_read[secretlink]" {
			t.Errorf("%s: read %s (target of deny_read secretlink) = %+v, want refused under fs.deny_read[secretlink]", tier, filepath.Join(safe, "key"), r)
		}
		w := rt.Evaluate(Action{Kind: ActionFSWrite, Path: filepath.Join(realOut, "x")}, tier)
		if w.Verdict != VerdictAllow || w.Rule != "fs.write[outlink/]" {
			t.Errorf("%s: write %s (target of write outlink/) = %+v, want allow under fs.write[outlink/]", tier, filepath.Join(realOut, "x"), w)
		}
	}
}
