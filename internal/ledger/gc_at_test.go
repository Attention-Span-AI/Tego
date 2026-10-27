// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestGCRemovalFollowsNoLink: retention removes an aged run whole — its blobs directory, a nested directory, its
// files — and a link inside it goes as a link: the directory and the file it names, outside the ledger root,
// stay (removeAllAt, an *at() walk under the held root that follows nothing).
func TestGCRemovalFollowsNoLink(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "runs"), filepath.Join(base, "outside")
	for _, dir := range []string{root, filepath.Join(outside, "deep")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	precious := filepath.Join(outside, "deep", "precious")
	if err := os.WriteFile(precious, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	ref := makeRun(t, root, fixedStart, "rmat01", StateEnded)
	dir := filepath.Join(root, ref.ID)
	if err := os.MkdirAll(filepath.Join(dir, BlobsDir, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, BlobsDir, "nested", "f"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for link, target := range map[string]string{
		filepath.Join(dir, "out"):                   outside,
		filepath.Join(dir, BlobsDir, "deep"):        filepath.Join(outside, "deep"),
		filepath.Join(dir, BlobsDir, "nested", "p"): precious,
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	now := fixedStart.Add(48 * time.Hour)
	rep, err := GC(context.Background(), root, time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil || len(rep.Errors) != 0 || len(rep.Deleted) != 1 || rep.Deleted[0] != ref.ID {
		t.Fatalf("GC: %+v %v, want the run deleted", rep, err)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("run directory still there: %v", err)
	}
	if b, err := os.ReadFile(precious); err != nil || string(b) != "keep" {
		t.Fatalf("a file outside the ledger root, named by links in the run, changed: %q %v", b, err)
	}
}

// TestRemoveAllAtOfAMissingNameIsNoError: a run a concurrent gc already removed is no error to remove again.
func TestRemoveAllAtOfAMissingNameIsNoError(t *testing.T) {
	root := t.TempDir()
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	if err := removeAllAt(rd, "r-gone", filepath.Join(root, "r-gone")); err != nil {
		t.Fatal(err)
	}
}

// TestRemoveAllAtFollowsNoDirectorySwappedForALink: a directory the walk found (its unlinkat answered EISDIR)
// and that is swapped for a link to a directory outside the root before the walk opens it is not entered: the
// open refuses the link (O_NOFOLLOW), and what the link names keeps its contents.
func TestRemoveAllAtFollowsNoDirectorySwappedForALink(t *testing.T) {
	base := t.TempDir()
	root, outside := filepath.Join(base, "runs"), filepath.Join(base, "outside")
	run := filepath.Join(root, "r-swap")
	for _, dir := range []string{filepath.Join(run, "blobs"), outside} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keep := filepath.Join(outside, "keep")
	if err := os.WriteFile(keep, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	prev := removeAllAtOpenHook
	t.Cleanup(func() { removeAllAtOpenHook = prev })
	removeAllAtOpenHook = func(path string) {
		if path != filepath.Join(run, "blobs") {
			return
		}
		if err := os.Rename(path, filepath.Join(base, "moved")); err != nil {
			t.Error(err)
		}
		if err := os.Symlink(outside, path); err != nil {
			t.Error(err)
		}
	}
	rd, err := openDir(root, false)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rd.Close() }()
	if err := removeAllAt(rd, "r-swap", run); err == nil {
		t.Error("removeAllAt over a directory swapped for a link reported nothing")
	}
	if _, err := os.Stat(keep); err != nil {
		t.Fatalf("the link's target lost its contents: %v", err)
	}
}
