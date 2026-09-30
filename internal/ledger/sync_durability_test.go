// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"strings"
	"syscall"
	"testing"
)

// A store over a path reaches its directory through an O_PATH descriptor, which syncfs(2) refuses: the
// overflow Sync must go through a readable one (R15).
func TestPathBlobStoreOverflowSyncs(t *testing.T) {
	run := t.TempDir()
	if err := os.Mkdir(filepath.Join(run, BlobsDir), 0o700); err != nil {
		t.Fatal(err)
	}
	s := NewBlobRepository(run).(*blobStore)
	for i := range maxPendingBlobs + 1 {
		if _, err := s.Put([]byte(strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	if !s.overflow {
		t.Fatal("overflow not set")
	}
	if err := s.Sync(); err != nil {
		t.Fatalf("Sync over a path store: %v", err)
	}
}

// A duplicate streamed body leaves the blob already there in place.
func TestPutStreamLeavesAnExistingBlob(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	content := bytes.Repeat([]byte("dup"), 100)
	sha, _, err := w.BlobFrom(bytes.NewReader(content))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, BlobsDir, sha)
	st1, _ := os.Stat(p)
	if _, _, err := w.BlobFrom(bytes.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	st2, _ := os.Stat(p)
	if !os.SameFile(st1, st2) {
		t.Error("a duplicate PutStream replaced the blob's inode")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, BlobsDir))
	if len(entries) != 1 {
		t.Errorf("%d entries, want the blob alone", len(entries))
	}
}

// The new chain.log entry is fsynced through a descriptor fsync accepts, and a failure is not dropped (R6).
func TestAnchorCreateSyncsItsDirectoryReadably(t *testing.T) {
	var calls, bad int
	prev := fsyncDir
	fsyncDir = func(d *sys.FD) error {
		calls++
		if err := d.Fsync(); err != nil {
			bad++
			return err
		}
		return nil
	}
	t.Cleanup(func() { fsyncDir = prev })
	if err := ProbeAnchor(filepath.Join(t.TempDir(), "sub", "chain.log")); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || bad != 0 {
		t.Fatalf("fsyncDir called %d times, %d failed; want one that succeeds", calls, bad)
	}
	fsyncDir = func(*sys.FD) error { return syscall.EIO }
	if err := ProbeAnchor(filepath.Join(t.TempDir(), "chain.log")); err == nil {
		t.Fatal("an fsync failure on the anchor directory was dropped")
	}
}

// R9a: query names are opaque, independent of length.
func TestRedactTargetDropsALongName(t *testing.T) {
	n16, n17 := strings.Repeat("n", 16), strings.Repeat("n", 17)
	for in, want := range map[string]string{
		"/v1/messages?QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVo=": "/v1/messages?redacted",
		"/f?a=1&sk-ant-api03-AAAAAAAAAAAAAAAAAAAAAAAA==":    "/redacted?redacted",
		"/f?" + n16 + "=v&" + n17 + "=v":                    "/redacted?redacted",
	} {
		if got := RedactTarget(in); got != want {
			t.Errorf("RedactTarget(%q) = %q, want %q", in, got, want)
		}
	}
}
