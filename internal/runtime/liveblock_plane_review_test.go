// SPDX-License-Identifier: Apache-2.0

// The confirmation review of A35-L: the reviewer's tests, adopted as written, with N4's close test.

package runtime

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
)

// hookWriter runs hooks[i] at the i-th Fill that writes rows (before it takes them).
type hookWriter struct {
	*fakeBlockWriter
	hooks []func()
	n     int
}

func (h *hookWriter) Fill(rows []enforce.PlaneBlockFill) ([]enforce.PlaneBlockResult, error) {
	if len(rows) > 0 && !rows[0].Delete {
		if h.n < len(h.hooks) && h.hooks[h.n] != nil {
			h.hooks[h.n]()
		}
		h.n++
	}
	return h.fakeBlockWriter.Fill(rows)
}

func swapIn(t *testing.T, dir, path, body string) func() {
	return func() {
		tmp := filepath.Join(dir, fmt.Sprintf(".tmp-%s", body))
		if err := os.WriteFile(tmp, []byte(body), 0o644); err != nil {
			t.Error(err)
			return
		}
		if err := os.Rename(tmp, path); err != nil {
			t.Error(err)
		}
	}
}

// Case B: the object at the path is swapped by rename-over during pass 1's fill and again during pass 2's fill.
func TestPlaneBlocksReviewSwapInEveryFill(t *testing.T) {
	proj, secret, base, _, now := blockScene(t)
	w := &hookWriter{fakeBlockWriter: base}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	w.hooks = []func(){swapIn(t, proj, secret, "n1"), swapIn(t, proj, secret, "n2")}
	p.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}, nil, nil, nil, now)
	if r, ok := base.rows[statKey(t, secret)]; !ok || r.Write == 0 {
		t.Errorf("RVB7b-1: after sync returned (before live-block-added) the object at the path has no write row; fills=%d calls=%v", w.n, base.calls)
	}
}

// Same with one swap only in pass 1 (the claimed conclusive case): must pass.
func TestPlaneBlocksReviewSwapInFirstFillOnly(t *testing.T) {
	proj, secret, base, _, now := blockScene(t)
	w := &hookWriter{fakeBlockWriter: base}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	w.hooks = []func(){swapIn(t, proj, secret, "n1")}
	p.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}, nil, nil, nil, now)
	if r, ok := base.rows[statKey(t, secret)]; !ok || r.Write == 0 {
		t.Errorf("RVB7b-1b: object at path has no row")
	}
}

// Overflow retry: map full on first pass, then room; object moves meanwhile.
func TestPlaneBlocksReviewOverflowRetryKeepsMovedObject(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	entries := []liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}
	orig := statKey(t, secret)
	w.full = true
	p.sync(entries, nil, nil, nil, now)
	if len(p.pending) == 0 {
		t.Fatalf("nothing pending: %+v", p.applied)
	}
	if err := os.Rename(secret, filepath.Join(proj, ".hide")); err != nil {
		t.Fatal(err)
	}
	w.full = false
	p.sync(entries, nil, nil, nil, now)
	if r, ok := w.rows[orig]; !ok || r.Write == 0 {
		t.Errorf("RVB7b-2: object moved while pending lost its row")
	}
	if len(p.pending) != 0 {
		t.Errorf("pending not drained: %d", len(p.pending))
	}
	if p.state.Over != 0 {
		t.Errorf("overflow not cleared: %+v", p.state)
	}
}

// Two blocks sharing an object; the object moves; remove one, then the other.
func TestPlaneBlocksReviewSharedObject(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: secret}
	b := liveblock.Entry{Kind: liveblock.KindPath, Value: secret}
	orig := statKey(t, secret)
	p.sync([]liveblock.Entry{a, b}, nil, nil, nil, now)
	if err := os.Rename(secret, filepath.Join(proj, ".hide")); err != nil {
		t.Fatal(err)
	}
	p.sync([]liveblock.Entry{a, b}, nil, nil, nil, now)
	r := w.rows[orig]
	if r.Write == 0 || r.Read == 0 {
		t.Errorf("shared row after move: %+v", r)
	}
	p.sync([]liveblock.Entry{b}, nil, nil, nil, now) // a removed
	r = w.rows[orig]
	if r.Read == 0 || r.Write == 0 {
		t.Errorf("after removing write block the path block's row is gone/weak: %+v", r)
	}
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now) // b gone, a re-added
	r, ok := w.rows[orig]
	t.Logf("after b removed and a back: ok=%v %+v", ok, r)
	p.sync(nil, nil, nil, nil, now)
	if _, ok := w.rows[orig]; ok || len(w.rows) != 0 {
		t.Errorf("rows remain after all removed: %d", len(w.rows))
	}
}

// Block removal then re-add of the same block: the old object is released (new walk only).
func TestPlaneBlocksReviewReAddReleases(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: secret}
	orig := statKey(t, secret)
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	if err := os.Rename(secret, filepath.Join(proj, ".hide")); err != nil {
		t.Fatal(err)
	}
	p.sync(nil, nil, nil, nil, now)
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	_, ok := w.rows[orig]
	t.Logf("re-added block keeps the object that moved while removed: %v (expected false)", ok)
}

// Host atomic replace N times: rows and descriptors grow by one per replacement.
func TestPlaneBlocksReviewReplaceGrowth(t *testing.T) {
	proj, secret, w, p, now := blockScene(t)
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: secret}
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	for i := 0; i < 50; i++ {
		swapIn(t, proj, secret, fmt.Sprintf("v%d", i))()
		p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	}
	t.Logf("after 50 host-side atomic replacements: rows=%d applied=%d held=%d", len(w.rows), len(p.applied), len(p.held[a.Key()]))
}

// Role downgrade: the target dir D moved to proj/e and the path's last element becomes a link into e: D becomes a guard.
func TestPlaneBlocksReviewRoleDowngrade(t *testing.T) {
	root := t.TempDir()
	d := filepath.Join(root, "d")
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "x"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d, "other"), []byte("o"), 0o644); err != nil {
		t.Fatal(err)
	}
	w := &fakeBlockWriter{}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	now := liveblock.Clock{}
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: d}
	orig := statKey(t, d)
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	r0 := w.rows[orig]
	e := filepath.Join(root, "e")
	if err := os.Rename(d, e); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(e, "x"), d); err != nil {
		t.Fatal(err)
	}
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	r1 := w.rows[orig]
	t.Logf("D row before %+v flags=%x ; after %+v flags=%x (SELF|BENEATH=%x)", r0.Write, r0.Flags, r1.Write, r1.Flags, bpf.PlaneBlockSelf|bpf.PlaneBlockBeneath)
	if r1.Flags&bpf.PlaneBlockBeneath == 0 || r1.Write == 0 {
		t.Errorf("RVB7b-3: the moved target directory lost its SELF/BENEATH write row: %+v", r1)
	}
}

// Deleted original: row stays (pinned); a new file at the path gets its own, and ino differs.
func TestPlaneBlocksReviewDeletedOriginal(t *testing.T) {
	_, secret, w, p, now := blockScene(t)
	a := liveblock.Entry{Kind: liveblock.KindWrite, Value: secret}
	orig := statKey(t, secret)
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	if err := os.Remove(secret); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		f := fmt.Sprintf("%s.%d", secret, i)
		if err := os.WriteFile(f, nil, 0o644); err != nil {
			t.Fatal(err)
		}
		if statKey(t, f) == orig {
			t.Errorf("inode %v reused while pinned", orig)
		}
	}
	if err := os.WriteFile(secret, []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	p.sync([]liveblock.Entry{a}, nil, nil, nil, now)
	if _, ok := w.rows[orig]; !ok {
		t.Errorf("row of deleted original dropped")
	}
	if _, ok := w.rows[statKey(t, secret)]; !ok {
		t.Errorf("new file at path not keyed")
	}
}

// TestPlaneBlocksReviewCloseReleasesPending is the review's N4: a row the full map refused is held with its descriptor;
// close releases it as it releases the applied rows' descriptors.
func TestPlaneBlocksReviewCloseReleasesPending(t *testing.T) {
	_, secret, w, p, now := blockScene(t)
	w.full = true
	p.sync([]liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}, nil, nil, nil, now)
	if len(p.pending) == 0 {
		t.Fatal("nothing pending under a full map")
	}
	fds := make([]*sys.FD, 0, len(p.pending))
	for _, a := range p.pending {
		fds = append(fds, a.fd)
	}
	p.close()
	if len(p.pending) != 0 {
		t.Errorf("%d pending rows after close", len(p.pending))
	}
	for _, fd := range fds {
		if err := fd.Borrow(func(int) error { return nil }); !errors.Is(err, sys.ErrClosed) {
			t.Errorf("a pending row's descriptor lends after close: %v", err)
		}
	}
}

// TestPlaneBlocksReviewSwapBeyondTheBoundOverflows is N1's bound: an agent that renames a fresh file over the blocked
// path during every fill keeps every pass putting rows. When sync returns (before live-block-added) the write class is
// refused whole, and the sync after the loop stops keys the path's object and clears the overflow.
func TestPlaneBlocksReviewSwapBeyondTheBoundOverflows(t *testing.T) {
	proj, secret, base, _, now := blockScene(t)
	w := &hookWriter{fakeBlockWriter: base}
	p := newPlaneBlocks(w, &liveRules{}, nil, true, nil)
	for i := 0; i < 3*blockSyncPasses; i++ {
		w.hooks = append(w.hooks, swapIn(t, proj, secret, fmt.Sprintf("s%d", i)))
	}
	entries := []liveblock.Entry{{Kind: liveblock.KindWrite, Value: secret}}
	p.sync(entries, nil, nil, nil, now)
	_, keyed := base.rows[statKey(t, secret)]
	if !keyed && p.state.Over&bpf.PlaneBlockWrite == 0 {
		t.Fatalf("the path's object is unkeyed and the write class is not refused whole: %+v", p.state)
	}
	if w.n != blockSyncPasses {
		t.Errorf("%d fills, want the bound %d", w.n, blockSyncPasses)
	}
	w.hooks = nil // the loop stops
	p.sync(entries, nil, nil, nil, now)
	if r, ok := base.rows[statKey(t, secret)]; !ok || r.Write == 0 {
		t.Errorf("after the loop stopped the path's object has no write row")
	}
	if p.state.Over != 0 || p.chased.over != 0 {
		t.Errorf("the overflow stayed once the sync settled: %+v", p.state)
	}
}
