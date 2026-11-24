// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// The review of A35-L (F1-F4): a block follows the object it landed on until it is removed, a move or a creation
// racing the rows' fill is keyed before sync returns, and a block the plane cannot key whole (a mount point it cannot
// open beneath the target, other names the mount table could not list in full) refuses its classes whole.

func blockScene(t *testing.T) (proj, secret string, w *fakeBlockWriter, p *planeBlocks, now liveblock.Clock) {
	t.Helper()
	root := t.TempDir()
	proj = filepath.Join(root, "proj")
	secret = filepath.Join(proj, "secret.txt")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(secret, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	w = &fakeBlockWriter{}
	p = newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	return proj, secret, w, p, liveblock.Clock{Wall: time.Now(), Boot: time.Hour}
}

// TestPlaneBlocksKeepTheObjectAMoveTookAway is review finding F1's test: the agent (or the host) renames the blocked file away
// after its row landed. The next tick keys the path's new state, and the original object, now at .hide, keeps its row.
func TestPlaneBlocksKeepTheObjectAMoveTookAway(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	entries := []liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}
	p.sync(entries, nil, nil, nil, now)
	orig := statKey(t, secret)
	if r, ok := w.rows[orig]; !ok || r.Write == 0 {
		t.Fatalf("first sync: no write row on the target: %+v", w.rows)
	}
	hide := filepath.Join(proj, ".hide")
	if err := os.Rename(secret, hide); err != nil {
		t.Fatal(err)
	}
	p.sync(entries, nil, nil, nil, now)
	if r, ok := w.rows[orig]; !ok || r.Write == 0 {
		t.Errorf("after the tick the original object (now %s) has no write row: writable again (%v)", hide, w.calls)
	}
	if r, ok := w.rows[nameKey(t, proj, "secret.txt")]; !ok || r.Write == 0 {
		t.Errorf("the path's now-missing name has no name row: %+v", w.rows)
	}
	// Removing the block deletes every row it ever keyed.
	p.sync(nil, nil, nil, nil, now)
	if len(w.rows) != 0 || len(p.applied) != 0 || len(p.held) != 0 {
		t.Errorf("after removal %d rows, %d applied, %d held", len(w.rows), len(p.applied), len(p.held))
	}
}

// TestPlaneBlocksKeepTheFileUnderAMovedAncestor: a host-side rename of the blocked file's folder (a git checkout, an
// IDE) leaves the file blocked under its new path.
func TestPlaneBlocksKeepTheFileUnderAMovedAncestor(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	entries := []liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}
	p.sync(entries, nil, nil, nil, now)
	orig := statKey(t, secret)
	old := proj + "-old"
	if err := os.Rename(proj, old); err != nil {
		t.Fatal(err)
	}
	p.sync(entries, nil, nil, nil, now)
	if r, ok := w.rows[orig]; !ok || r.Write == 0 {
		t.Errorf("the file under the moved folder (%s) has no write row", filepath.Join(old, "secret.txt"))
	}
}

// TestPlaneBlocksKeyAMoveThatRacedTheFill: the blocked file is moved away and another object put at its path while
// the first rows land. sync walks again before it returns, so both the object it keyed and the one now at the path
// carry rows, with no tick in between.
func TestPlaneBlocksKeyAMoveThatRacedTheFill(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	orig := statKey(t, secret)
	w.onFill = func() {
		if err := os.Rename(secret, filepath.Join(proj, ".hide")); err != nil {
			t.Error(err)
		}
		if err := os.WriteFile(secret, []byte("new"), 0o644); err != nil {
			t.Error(err)
		}
	}
	p.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}, nil, nil, nil, now)
	if r, ok := w.rows[orig]; !ok || r.Write == 0 {
		t.Errorf("the object keyed before the move has no write row")
	}
	if r, ok := w.rows[statKey(t, secret)]; !ok || r.Write == 0 {
		t.Errorf("the object put at the path during the fill has no write row before sync returned: %v", w.calls)
	}
}

// TestPlaneBlocksKeyANameMadeDuringTheFill is review finding F2: a block on a name that does not exist; the agent creates it
// between the launcher's lookup and the name row landing. The object is keyed before sync returns.
func TestPlaneBlocksKeyANameMadeDuringTheFill(t *testing.T) {
	proj, _, w, p, now := blockScene(t)
	absent := filepath.Join(proj, "absent.txt")
	w.onFill = func() {
		if err := os.WriteFile(absent, []byte("made"), 0o644); err != nil {
			t.Error(err)
		}
	}
	p.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: absent}}, nil, nil, nil, now)
	if r, ok := w.rows[statKey(t, absent)]; !ok || r.Write == 0 {
		t.Errorf("the file made at the blocked name during the fill has no write row before sync returned: %v", w.calls)
	}
	if _, ok := w.rows[nameKey(t, proj, "absent.txt")]; !ok {
		t.Errorf("the name row is gone")
	}
}

// TestPlaneBlocksRefuseWholeWhatTheyCannotKey is review findings F3 and F4: a mount point beneath the target that cannot be
// opened (not one that is gone), and a value whose other names the mount table could not list in full, each set the
// block's class in overflow.
func TestPlaneBlocksRefuseWholeWhatTheyCannotKey(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens a mode-0 folder's child")
	}
	proj, secret, w, _, now := blockScene(t)
	locked := filepath.Join(proj, "locked")
	if err := os.MkdirAll(filepath.Join(locked, "mnt"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(locked, 0o755) })
	entries := []liveblock.Entry{{Kind: liveblock.KindWrite, Value: proj}}
	gone := newPlaneBlocks(w, &liveRules{}, []string{filepath.Join(proj, "gone", "mnt")}, true, nil)
	gone.sync(entries, nil, nil, nil, now)
	if st := gone.state; st.Over != 0 {
		t.Errorf("a mount point gone since Prepare overflowed: %+v", st)
	}
	w2 := &fakeBlockWriter{}
	unopenable := newPlaneBlocks(w2, &liveRules{}, []string{filepath.Join(locked, "mnt")}, true, nil)
	unopenable.sync(entries, nil, nil, nil, now)
	if st := unopenable.state; st.Over&bpf.PlaneBlockWrite == 0 || st.OverWrite == 0 {
		t.Errorf("a mount point beneath the target that cannot be opened left the write class in force by rows: %+v", st)
	}
	w3 := &fakeBlockWriter{}
	partial := newPlaneBlocks(w3, &liveRules{}, nil, true, nil)
	partial.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}, nil,
		map[string]string{secret: "mountinfo unreadable"}, nil, now)
	if st := partial.state; st.Over&bpf.PlaneBlockWrite == 0 {
		t.Errorf("a value whose other names are partial left the write class in force by rows: %+v", st)
	}
}
