// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGCSweepsARunWhoseLockFileIsGone pins record-ledger.md E27: a run directory with no lock file (a fixture, or
// a tool that bypassed Open) reads as free, so gc's sweep operates on it rather than erroring: an ended run past
// retention is deleted, and one within retention is kept, neither reported as an error.
func TestGCSweepsARunWhoseLockFileIsGone(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	old := makeRun(t, root, fixedStart, "e27001", StateEnded)
	fresh := makeRun(t, root, now.Add(-time.Hour), "e27002", StateEnded)
	for _, ref := range []record.RunRef{old, fresh} {
		if err := os.Remove(filepath.Join(root, ref.ID, LockFile)); err != nil {
			t.Fatal(err)
		}
		if s := stateOf(t, filepath.Join(root, ref.ID)); s != StateEnded {
			t.Fatalf("%s without a lock file reads %s, want ended", ref.ID, s)
		}
	}
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 0 || !sameSet(rep.Deleted, []string{old.ID}) || !sameSet(rep.Kept, []string{fresh.ID}) {
		t.Fatalf("gc report %+v, want %s deleted and %s kept, no errors", rep, old.ID, fresh.ID)
	}
	if _, err := os.Stat(filepath.Join(root, old.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("the lock-less run past retention is still there: %v", err)
	}
}

// TestGCUnlinksARunUnderAnOpenReader pins record-ledger.md E21: a reader that opened a run before gc deleted it
// keeps reading it (unlink-while-open), and an open after the deletion gets os.ErrNotExist.
func TestGCUnlinksARunUnderAnOpenReader(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	ref := makeRun(t, root, fixedStart, "e21001", StateEnded)
	dir := filepath.Join(root, ref.ID)
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()

	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatal(err)
	}
	if !sameSet(rep.Deleted, []string{ref.ID}) {
		t.Fatalf("gc report %+v, want %s deleted", rep, ref.ID)
	}
	n := 0
	for _, err := range r.Iter() {
		if err != nil {
			t.Fatalf("read after the unlink: %v", err)
		}
		n++
	}
	if n == 0 {
		t.Fatal("the reader opened before the deletion read nothing")
	}
	if _, err := OpenReader(dir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("open after the deletion: %v, want os.ErrNotExist", err)
	}
}

// TestOpenTakesALedgerDirAsGiven pins record-ledger.md E17: Open resolves dir as given, with no symlink defense of
// its own, so a relative path and a path through a symlink each write the run where they point.
func TestOpenTakesALedgerDirAsGiven(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	if err := os.Mkdir(real, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	for _, tc := range []struct{ name, root, rand6 string }{
		{"relative", "real", "e17001"},
		{"symlinked", "link", "e17002"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ref := record.RunRef{ID: runID(fixedStart, tc.rand6), Agent: "retriever"}
			w, err := Open(filepath.Join(tc.root, ref.ID), ref, WithAnchor(&memAnchor{}),
				WithClock(newStepClock(fixedStart, 1, time.Millisecond)))
			if err != nil {
				t.Fatalf("Open under a %s ledger root: %v", tc.name, err)
			}
			startRun(t, w, 1)
			if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(filepath.Join(real, ref.ID, EventsFile)); err != nil {
				t.Fatalf("the run is not where the %s root points: %v", tc.name, err)
			}
		})
	}
}
