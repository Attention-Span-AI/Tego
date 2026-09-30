// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestWriterBlobGetRefusesLinkAndFIFO: the Writer-held store opens a blob as a Reader does (E12): a symlink at
// blobs/<sha> is not followed and a FIFO does not hang the open.
func TestWriterBlobGetRefusesLinkAndFIFO(t *testing.T) {
	w, dir := startedWriter(t)
	defer func() { _ = w.Close(record.RunEndPayload{Reason: record.RunEndExit}) }()
	secret := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(secret, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	linkSHA := strings.Repeat("a", 64)
	if err := os.Symlink(secret, filepath.Join(dir, BlobsDir, linkSHA)); err != nil {
		t.Fatal(err)
	}
	if rc, err := w.blobs.Get(linkSHA); err == nil {
		_ = rc.Close()
		t.Fatal("Get followed a symlink planted at blobs/<sha>")
	}
	fifoSHA := strings.Repeat("b", 64)
	if err := syscall.Mkfifo(filepath.Join(dir, BlobsDir, fifoSHA), 0o600); err != nil {
		t.Fatal(err)
	}
	if rc, err := w.blobs.Get(fifoSHA); err == nil {
		_ = rc.Close()
		t.Fatal("Get opened a FIFO planted at blobs/<sha>")
	}
}

// TestClosedWriterStoreRefusesPathFallback: after Close the Writer's store answers Has, Get and Put with
// ErrClosed rather than falling back to the blobs path, which may name another directory by then. Put of a
// body already on disk, the one path a Blob racing Close can reach, reported success without it.
func TestClosedWriterStoreRefusesPathFallback(t *testing.T) {
	w, _ := startedWriter(t)
	body := []byte("a blob that exists before Close")
	sha, err := w.Blob(body)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if ok, err := w.blobs.Has(sha); !errors.Is(err, ErrClosed) {
		t.Errorf("Has after Close = %v, %v; want ErrClosed", ok, err)
	}
	if rc, err := w.blobs.Get(sha); !errors.Is(err, ErrClosed) {
		if rc != nil {
			_ = rc.Close()
		}
		t.Errorf("Get after Close = %v; want ErrClosed", err)
	}
	if _, err := w.blobs.Put(body); !errors.Is(err, ErrClosed) {
		t.Errorf("Put of an existing blob after Close = %v; want ErrClosed", err)
	}
}
