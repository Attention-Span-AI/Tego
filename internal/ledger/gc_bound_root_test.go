// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// requireLentRun fails the test unless dir lends the run directory want names (its device and inode, read before
// any swap) and that directory's lock is held, as it is by the sweep's own Writer while the hook runs.
func requireLentRun(t *testing.T, dir sys.Lender, want unix.Stat_t) {
	t.Helper()
	var st unix.Stat_t
	if err := dir.Borrow(func(n int) error { return unix.Fstat(n, &st) }); err != nil {
		t.Fatalf("the lent run directory: %v", err)
	}
	if st.Dev != want.Dev || st.Ino != want.Ino {
		t.Fatalf("the hook was lent %d:%d, want the held run's directory %d:%d", st.Dev, st.Ino, want.Dev, want.Ino)
	}
	if free, err := probeLock(OpenRegularAt(dir, LockFile, LockFile)); err != nil || free {
		t.Fatalf("the lent run's lock: free=%v, %v; want held by the sweep's Writer", free, err)
	}
}

// statDir is path's own status, for requireLentRun.
func statDir(t *testing.T, path string) unix.Stat_t {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		t.Fatal(err)
	}
	return st
}

// A root swapped out for the decision and back for deletion used to skip the real lost run's sweep:
// the decoy said it was ended, and sameRoot saw the restored directory. Both the decision and the
// runtime hook must now read the held root (the hook is lent the held run's directory itself), and the Writer
// must append there before retention removes it.
func TestGCSwapBackStillSweepsTheHeldRun(t *testing.T) {
	base := t.TempDir()
	root, decoy := filepath.Join(base, "runs"), filepath.Join(base, "decoy")
	for _, dir := range []string{root, decoy} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	real := makeRun(t, root, fixedStart, "bound1", StateLost)
	held := statDir(t, filepath.Join(root, real.ID))
	makeRun(t, decoy, fixedStart, "bound1", StateEnded)
	before, err := os.ReadFile(filepath.Join(decoy, real.ID, EventsFile))
	if err != nil {
		t.Fatal(err)
	}
	moved := root + ".held"
	swapped, restored, hooked := false, false, false
	swap := func(o *gcOptions) {
		o.opened = func() {
			if err := os.Rename(root, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(decoy, root); err != nil {
				t.Fatal(err)
			}
			swapped = true
		}
	}
	clock := func() time.Time {
		if !restored {
			if err := os.Remove(root); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(moved, root); err != nil {
				t.Fatal(err)
			}
			restored = true
		}
		return fixedStart.Add(40 * 24 * time.Hour)
	}
	hook := func(_ context.Context, dir sys.Lender, ref record.RunRef) error {
		hooked = true
		if ref.ID != real.ID {
			t.Fatalf("hook run = %s", ref.ID)
		}
		// sweep owns the real Writer's lock while calling the hook; the decoy is ended.
		requireLentRun(t, dir, held)
		return nil
	}
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, swap, WithNow(clock),
		WithSweepHook(hook), WithWriterOptions(WithAnchor(&memAnchor{})))
	if err != nil || len(rep.Errors) != 0 {
		t.Fatalf("GC: %v, %v", err, rep.Errors)
	}
	if !swapped || !restored || !hooked || len(rep.Swept) != 1 || len(rep.Deleted) != 1 {
		t.Fatalf("swap=%v restore=%v hook=%v report=%+v", swapped, restored, hooked, rep)
	}
	after, err := os.ReadFile(filepath.Join(decoy, real.ID, EventsFile))
	if err != nil || string(after) != string(before) {
		t.Fatalf("decoy changed: %v", err)
	}
}

// The indexed path and its missing-index fallback must sweep the same root they opened,
// even while the configured name points at a decoy that claims the real orphan already ended.
func TestSweepLiveUsesHeldRootWithAndWithoutIndex(t *testing.T) {
	for _, indexed := range []bool{false, true} {
		name := "fallback"
		if indexed {
			name = "indexed"
		}
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			root, decoy := filepath.Join(base, "runs"), filepath.Join(base, "decoy")
			for _, dir := range []string{root, decoy} {
				if err := os.Mkdir(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			real := makeRun(t, root, fixedStart, "bound2", StateLost)
			held := statDir(t, filepath.Join(root, real.ID))
			makeRun(t, decoy, fixedStart, "bound2", StateEnded)
			if indexed {
				for _, dir := range []string{root, decoy} {
					if err := MarkLive(dir, real.ID); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.ReadFile(filepath.Join(decoy, real.ID, EventsFile))
			if err != nil {
				t.Fatal(err)
			}
			moved := root + ".held"
			swap := func(o *gcOptions) {
				o.opened = func() {
					if err := os.Rename(root, moved); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(decoy, root); err != nil {
						t.Fatal(err)
					}
				}
			}
			hooked := false
			hook := func(_ context.Context, dir sys.Lender, _ record.RunRef) error {
				hooked = true
				requireLentRun(t, dir, held)
				return nil
			}
			rep, err := SweepLive(context.Background(), root, swap, WithSweepHook(hook),
				WithWriterOptions(WithAnchor(&memAnchor{})))
			if err != nil || len(rep.Errors) != 0 || !hooked || len(rep.Swept) != 1 {
				t.Fatalf("SweepLive: hook=%v report=%+v error=%v", hooked, rep, err)
			}
			state, err := NewRunRepository(moved).State(context.Background(), real.ID)
			if err != nil || state != StateEnded {
				t.Fatalf("real state = %s, %v; want ended", state, err)
			}
			after, err := os.ReadFile(filepath.Join(decoy, real.ID, EventsFile))
			if err != nil || string(after) != string(before) {
				t.Fatalf("decoy changed: %v", err)
			}
			if indexed && (listed(t, moved, real.ID) || !listed(t, decoy, real.ID)) {
				t.Fatal("the real index entry must clear and the decoy entry must remain")
			}
		})
	}
}

// A nil anchor option has the Writer's ordinary default semantics even though anchor repair reads its
// run under the held root. The fallback pass for a missing index must preserve that declared location too.
func TestSweepLiveNilAnchorUsesDeclaredRoot(t *testing.T) {
	for _, indexed := range []bool{true, false} {
		name := "indexed-ended-repair"
		if !indexed {
			name = "fallback-lost-writer"
		}
		t.Run(name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "runs")
			anchor := NewFileChainAnchor(filepath.Join(filepath.Dir(root), ChainLogFile))
			var ref record.RunRef
			if indexed {
				ref = endedUnanchored(t, root, anchor, "nilanc")
			} else {
				ref = makeRun(t, root, fixedStart, "nilanc", StateLost)
			}
			rep, err := SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(nil)))
			if err != nil || len(rep.Errors) != 0 {
				t.Fatalf("SweepLive: %+v %v", rep, err)
			}
			vr, err := VerifyRunDir(context.Background(), filepath.Join(root, ref.ID), anchor)
			if err != nil || !vr.Anchored || !vr.Ended {
				t.Fatalf("declared-root anchor: %+v %v", vr, err)
			}
			if indexed && listed(t, root, ref.ID) {
				t.Fatal("repaired entry remains listed")
			}
		})
	}
}
