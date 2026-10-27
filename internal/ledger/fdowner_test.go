// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLedgerDescriptorsCloseOnEveryPath is ADR 0023 C10's table check over the ledger's owners: a Writer
// opened by path and through a lent directory (OpenAt), closed, abandoned and refused (a second Open of a
// locked run, a fresh-directory check that fails, a closed lender), its activity sidecar and last-refusal
// mirror (replaced once), a blob, the live index, a placed file, and a GC and SweepLive pass over the root
// leave no descriptor behind.
func TestLedgerDescriptorsCloseOnEveryPath(t *testing.T) {
	testutil.NoFDLeak(t)
	root := t.TempDir()
	anchor := &memAnchor{}
	clock := newStepClock(fixedStart, 1, time.Millisecond)
	opts := []Option{WithAnchor(anchor), WithClock(clock)}
	ctx := context.Background()

	ref := record.RunRef{ID: runID(fixedStart, "fdown1"), Agent: "retriever"}
	dir := filepath.Join(root, ref.ID)
	if err := MakeRunDir(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	w, err := Open(dir, ref, append(opts, WithFreshRunDir())...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, ref, opts...); !errors.Is(err, ErrRunLocked) {
		t.Fatalf("a second Open of a locked run = %v, want ErrRunLocked", err)
	}
	if _, err := Open(dir, ref, append(opts, WithFreshRunDir())...); err == nil {
		t.Fatal("a fresh-directory Open of a directory that holds a ledger succeeded")
	}
	act, err := w.OpenActivity()
	if err != nil {
		t.Fatal(err)
	}
	if err := act.Publish(7); err != nil {
		t.Fatal(err)
	}
	if err := act.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := w.MirrorLastRefusal(t.TempDir()); err != nil {
			t.Fatal(err)
		}
	}
	// A mirror directory this process's uid does not own is refused, its descriptor closed: one of root's for
	// anyone else, one handed to nobody for root.
	foreign := "/etc"
	if os.Geteuid() == 0 {
		foreign = t.TempDir()
		if err := os.Chown(foreign, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.MirrorLastRefusal(foreign); err == nil {
		t.Fatalf("MirrorLastRefusal of %s, a directory another uid owns, succeeded", foreign)
	}
	if _, err := w.Blob(make([]byte, 2*BlobThreshold)); err != nil {
		t.Fatal(err)
	}
	f, err := w.OpenDirPath()
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
	// A lock the Writer holds, taken again under the run's directory (tryLockAt): held, and nothing kept.
	rundir, err := openDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	if held, unlock, err := tryLockAt(rundir, dir); err != nil || !held || unlock != nil {
		t.Fatalf("tryLockAt of a lock the Writer holds: held=%v, %v", held, err)
	}
	if err := rundir.Close(); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := w.MirrorLastRefusal(t.TempDir()); !errors.Is(err, ErrClosed) {
		t.Fatalf("MirrorLastRefusal after Close = %v, want ErrClosed", err)
	}
	if err := ClearLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}

	// The reaper's form: the run directory lent by its caller, which keeps it.
	ref2 := record.RunRef{ID: runID(fixedStart, "fdown2"), Agent: "retriever"}
	if err := MakeRunDir(root, ref2.ID); err != nil {
		t.Fatal(err)
	}
	d, err := sys.Own(unix.Open(filepath.Join(root, ref2.ID), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0))
	if err != nil {
		t.Fatal(err)
	}
	w2, err := OpenAt(d, filepath.Join(root, ref2.ID), ref2, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := w2.Abandon(); err != nil {
		t.Fatal(err)
	}
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenAt(d, filepath.Join(root, ref2.ID), ref2, opts...); !errors.Is(err, sys.ErrClosed) {
		t.Fatalf("OpenAt through a closed lender = %v, want sys.ErrClosed", err)
	}
	if _, err := OpenAt(nil, filepath.Join(root, ref2.ID), ref2, opts...); !errors.Is(err, sys.ErrClosed) {
		t.Fatalf("OpenAt through no lender = %v, want sys.ErrClosed", err)
	}

	if err := PlaceNewFile(t.TempDir(), "marker", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := PlaceNewFileThen(ctx, t.TempDir(), "marker", []byte("x"), func(bool) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if _, err := GC(ctx, root, time.Hour, true, WithWriterOptions(opts...)); err != nil {
		t.Fatal(err)
	}
	if _, err := SweepLive(ctx, root, WithWriterOptions(opts...)); err != nil {
		t.Fatal(err)
	}
	if _, err := LiveEntries(root); err != nil {
		t.Fatal(err)
	}
	// A run directory with no ledger yet, read under a lent directory: refused, the reopened directory closed.
	ref3 := record.RunRef{ID: runID(fixedStart, "fdown3"), Agent: "retriever"}
	if err := MakeRunDir(root, ref3.ID); err != nil {
		t.Fatal(err)
	}
	d3, err := openDir(filepath.Join(root, ref3.ID), false)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenReaderAt(d3, filepath.Join(root, ref3.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenReaderAt of a run with no ledger = %v, want os.ErrNotExist", err)
	}
	if err := d3.Close(); err != nil {
		t.Fatal(err)
	}
	// Retention removes every run, the one with a blobs directory too (removeAllAt's recursion).
	later := WithNow(func() time.Time { return fixedStart.Add(24 * time.Hour) })
	if rep, err := GC(ctx, root, time.Hour, false, later, WithWriterOptions(opts...)); err != nil || len(rep.Deleted) != 3 {
		t.Fatalf("GC removal: %+v, %v; want the three runs deleted", rep, err)
	}
}
