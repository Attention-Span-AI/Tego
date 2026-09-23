// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestEvaluateDenyReadSymlinkedOutOfAWriteEntryStaysEnforced is the other direction of E8's
// resolved-containment rule, and the one Evaluate was left behind on. A deny_read entry that *is* a
// symlink pointing out of a write entry governs its target's inode, because the run opens it O_PATH
// without O_NOFOLLOW — so the write entry does not shadow it and tier 1 can enforce the deny.
//
// Compile says so (compile_fs.go unenforced, on Resolved) and the Landlock backend agrees, since its
// I5 cross-check asks the same question of FSRule.Governed
// (internal/runtime/enforce/landlock/enumerate.go). Evaluate's own recomputation still compared the
// declared names, so `compile --test` was the one component reporting the secret as readable —
// contradicting both the table it was handed and the kernel that will run it.
func TestEvaluateDenyReadSymlinkedOutOfAWriteEntryStaysEnforced(t *testing.T) {
	f := newFixture(t)
	safe := filepath.Join(f.root, "safe")
	if err := os.MkdirAll(safe, 0o755); err != nil {
		t.Fatal(err)
	}
	f.file(filepath.Join(safe, "key"), "k", 0o600)
	link := filepath.Join(f.project, "out", "linkdir")
	if err := os.Symlink(safe, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	rt, ds := f.compile(f.load("version: 0\nname: a\ncommand: [python]\ntier: landlock\nfs:\n  write: [\"out/\"]\n  deny_read: [\"out/linkdir\"]\n"))

	r := findFS(rt, FSDenyRead, link)
	if r == nil {
		t.Fatalf("no deny_read rule for %s:\n%s", link, render(ds))
	}
	if r.Unenforced {
		t.Fatalf("compile marked %s (-> %s) unenforced although no write entry encloses its target", link, r.Resolved)
	}
	if hasCode(ds, CodeUnenforced) {
		t.Fatalf("compile warned unenforced for a deny_read that resolves outside every write entry:\n%s", render(ds))
	}

	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: filepath.Join(link, "key")}, backend.TierLandlock)
	if got.Verdict != VerdictRefused || got.Reason != record.ReasonReadDenied {
		t.Errorf("landlock read of %s = %+v, want refused/%s: the deny is enforceable", filepath.Join(link, "key"), got, record.ReasonReadDenied)
	}
	if strings.HasSuffix(got.Rule, UnenforcedSuffix) {
		t.Errorf("rule %q carries the unenforced marker compile did not set", got.Rule)
	}
}

// TestDenyUnenforcedFallsBackToDeclaredPaths keeps the recomputation working on a table assembled in
// code, where Compile never filled Resolved in: the declared path is then all there is, and the
// answer must stay the fail-safe one rather than comparing against "".
func TestDenyUnenforcedFallsBackToDeclaredPaths(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierLandlock, FS: []FSRule{
		{Path: "/w", Kind: FSWrite, Access: AccessWriteSet},
		{Path: "/w/secret", Kind: FSDenyRead},
		{Path: "/elsewhere/secret", Kind: FSDenyRead},
	}}
	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: "/w/secret/key"}, backend.TierLandlock)
	if got.Verdict != VerdictAllow || !strings.HasSuffix(got.Rule, UnenforcedSuffix) {
		t.Errorf("deny_read inside the write entry = %+v, want allow with the unenforced marker", got)
	}
	got = rt.Evaluate(Action{Kind: ActionFSRead, Path: "/elsewhere/secret/key"}, backend.TierLandlock)
	if got.Verdict != VerdictRefused {
		t.Errorf("deny_read outside every write entry = %+v, want refused", got)
	}
}

// TestDenyUnenforcedCatchesTheEqualPathCase covers E26's degenerate shape on the recomputation side:
// a write entry and a deny_read target that are the same path. Landlock cannot deny beneath its own
// allow, so the deny is unenforceable; the backend's own check compares the target for exactly this
// reason, and asking only about the target's parent missed it.
func TestDenyUnenforcedCatchesTheEqualPathCase(t *testing.T) {
	rt := &RuleTable{Tier: backend.TierLandlock, FS: []FSRule{
		{Path: "/w/secret", Kind: FSWrite, Access: AccessWriteSet},
		{Path: "/w/secret", Kind: FSDenyRead},
	}}
	got := rt.Evaluate(Action{Kind: ActionFSRead, Path: "/w/secret/key"}, backend.TierLandlock)
	if got.Verdict != VerdictAllow || !strings.HasSuffix(got.Rule, UnenforcedSuffix) {
		t.Errorf("deny_read equal to the write entry = %+v, want allow with the unenforced marker", got)
	}
}
