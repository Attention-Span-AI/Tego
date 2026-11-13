// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// The tests below pin the O_NOFOLLOW of each open in the ledger that a link at the name would otherwise redirect
// (an open with O_CREAT|O_EXCL refuses a link by itself and needs none): each plants the link where the open looks
// and checks that what it names is neither read, written, nor created.

// TestGCRemovalLockFollowsNoLink: retention's lock open (lockForRemoval) creates the lock file when it is missing,
// so without O_NOFOLLOW a lock planted as a link to a missing path outside the root made that file. The run is kept
// with an error, and nothing is created where the link points.
func TestGCRemovalLockFollowsNoLink(t *testing.T) {
	base := t.TempDir()
	root, target := filepath.Join(base, "runs"), filepath.Join(base, "made-through-the-link")
	ref := makeRun(t, root, fixedStart, "nflock", StateEnded)
	lock := filepath.Join(root, ref.ID, LockFile)
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, lock); err != nil {
		t.Fatal(err)
	}
	later := WithNow(func() time.Time { return fixedStart.Add(48 * time.Hour) })
	rep, err := GC(context.Background(), root, time.Hour, false, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Deleted) != 0 || rep.Errors[ref.ID] == nil {
		t.Errorf("GC over a run whose lock is a link: %+v, want it kept with an error", rep)
	}
	// The pass refuses the run before its removal (its lock probe follows no link either), so the removal's own
	// lock open is called directly too.
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	if d, f, err := pinnedRepository(root, rd).lockForRemoval(ref.ID); err == nil {
		_ = f.Close()
		_ = d.Close()
		t.Error("lockForRemoval opened the lock through a link")
	}
	if _, err := os.Lstat(target); !os.IsNotExist(err) {
		t.Fatalf("the lock open went through the link: %s exists (%v)", target, err)
	}
}

// TestOpenRunFollowsNoLink: the pinned repository opens a run under the held root only as a directory, never
// through a link at the run's name (openRun).
func TestOpenRunFollowsNoLink(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "runs")
	elsewhere := makeRun(t, filepath.Join(base, "elsewhere"), fixedStart, "nfrun1", StateEnded)
	id := runID(fixedStart, "nfrun2")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "elsewhere", elsewhere.ID), filepath.Join(root, id)); err != nil {
		t.Fatal(err)
	}
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	if d, err := pinnedRepository(root, rd).openRun(id); err == nil {
		_ = d.Close()
		t.Fatal("openRun opened a run through a link at its name")
	}
}

// TestWriterBlobsFollowNoLink: a Writer opens its blobs directory under the run directory with a link refused, so
// a blobs planted as a link to a directory elsewhere fails the Open and receives nothing.
func TestWriterBlobsFollowNoLink(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "runs"), filepath.Join(base, "outside")
	ref := record.RunRef{ID: runID(fixedStart, "nfblob"), Agent: "retriever"}
	if err := MakeRunDir(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ref.ID, BlobsDir)); err != nil {
		t.Fatal(err)
	}
	w, err := Open(filepath.Join(root, ref.ID), ref, WithAnchor(&memAnchor{}))
	if err == nil {
		_, berr := w.Blob(make([]byte, 2*BlobThreshold))
		_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		t.Errorf("Open with blobs a link succeeded (a blob: %v)", berr)
	}
	if names, err := os.ReadDir(outside); err != nil || len(names) != 0 {
		t.Fatalf("the link's target holds %v (%v), want nothing", names, err)
	}
}

// TestRegularOpensFollowNoLink: a run file is read only from the name itself, by path (openRegular) and under a
// lent directory (OpenRegularAt), never from what a link there names.
func TestRegularOpensFollowNoLink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, EventsFile)); err != nil {
		t.Fatal(err)
	}
	if f, err := openRegular(filepath.Join(dir, EventsFile)); err == nil {
		_ = f.Close()
		t.Error("openRegular read through a link")
	}
	d, err := openDir(dir, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	if f, err := OpenRegularAt(d, EventsFile, filepath.Join(dir, EventsFile)); err == nil {
		_ = f.Close()
		t.Error("OpenRegularAt read through a link")
	}
}
