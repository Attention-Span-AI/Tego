// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestOpenBlobChecks: OpenBlob refuses what ReadBlob refuses, under the caller's own bound, and says which refusal it
// is: content that does not hash to its name (ErrBlobHash), a symlinked blob (not followed: ELOOP), a symlinked blobs
// folder, a FIFO (refused without blocking), a file over the bound (ErrBlobTooBig; MaxBlobBytes when max is 0), a name
// that is not a sha256 one, a missing file. A good blob streams back exactly, a blob past MaxBlobBytes too when the
// bound allows it, and a stream read to its end stays at io.EOF.
func TestOpenBlobChecks(t *testing.T) {
	dir := t.TempDir()
	good := []byte(`["bash","-c","curl -d @id_ed25519 http://127.0.0.1:4880"]`)
	sha := putBlob(t, dir, good)
	badSum := sha256.Sum256([]byte("something else"))
	bad := hex.EncodeToString(badSum[:])
	if err := os.WriteFile(filepath.Join(dir, "blobs", bad), good, 0o644); err != nil {
		t.Fatal(err)
	}
	other := t.TempDir()
	if err := os.MkdirAll(filepath.Join(other, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "blobs", sha), filepath.Join(other, "blobs", sha)); err != nil {
		t.Fatal(err)
	}
	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, "blobs"), filepath.Join(linked, "blobs")); err != nil {
		t.Fatal(err)
	}
	fifoSum := sha256.Sum256([]byte("fifo"))
	fifo := hex.EncodeToString(fifoSum[:])
	if err := syscall.Mkfifo(filepath.Join(dir, "blobs", fifo), 0o644); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("0123456789abcdef"), MaxBlobBytes/16+1)
	bigSHA := putBlob(t, dir, big)

	for _, c := range []struct {
		name, dir, sha string
		max            int64
		want           error
	}{
		{"content does not hash to its name", dir, bad, 0, ErrBlobHash},
		{"symlinked blob", other, sha, 0, syscall.ELOOP},
		{"symlinked blobs directory", linked, sha, 0, ErrBlob},
		{"fifo", dir, fifo, 0, ErrBlob},
		{"over its bound", dir, sha, 10, ErrBlobTooBig},
		{"over MaxBlobBytes when max is 0", dir, bigSHA, 0, ErrBlobTooBig},
		{"not a sha256 name", dir, strings.ToUpper(sha), 0, ErrBlob},
		{"missing", dir, strings.Repeat("0", 64), 0, os.ErrNotExist},
	} {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan error, 1)
			go func() {
				b, err := OpenBlob(c.dir, c.sha, c.max)
				if err == nil {
					_ = b.Close()
				}
				done <- err
			}()
			select {
			case err := <-done:
				if !errors.Is(err, c.want) {
					t.Fatalf("OpenBlob: %v, want %v", err, c.want)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("OpenBlob blocked")
			}
		})
	}

	for _, c := range []struct {
		sha     string
		max     int64
		content []byte
	}{{sha, 0, good}, {bigSHA, 2 * MaxBlobBytes, big}} {
		b, err := OpenBlob(dir, c.sha, c.max)
		if err != nil {
			t.Fatalf("a good blob of %d bytes under %d: %v", len(c.content), c.max, err)
		}
		got, err := io.ReadAll(b)
		if err != nil || !bytes.Equal(got, c.content) || b.Size() != int64(len(c.content)) {
			t.Errorf("a good blob streamed %d bytes of %d (Size %d): %v", len(got), len(c.content), b.Size(), err)
		}
		if n, err := b.Read(make([]byte, 8)); n != 0 || err != io.EOF {
			t.Errorf("a Read past the end: %d, %v; want 0, io.EOF", n, err)
		}
		_ = b.Close()
	}
}

// TestOpenBlobStreams: a 10 MiB blob, forty times what ReadBlob reads, streams through a 32 KiB buffer under the
// download's bound and hashes to its name.
func TestOpenBlobStreams(t *testing.T) {
	dir := t.TempDir()
	content := make([]byte, 10<<20)
	for i := range content {
		content[i] = byte(i % 251)
	}
	sha := putBlob(t, dir, content)
	b, err := OpenBlob(dir, sha, 16<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = b.Close() }()
	h := sha256.New()
	n, err := io.CopyBuffer(h, b, make([]byte, 32<<10))
	if err != nil || n != int64(len(content)) || b.Size() != n {
		t.Fatalf("streamed %d of %d bytes (Size %d): %v", n, len(content), b.Size(), err)
	}
	if got := hex.EncodeToString(h.Sum(nil)); got != sha {
		t.Errorf("the stream hashes to %s, want %s", got[:12], sha[:12])
	}
}

// TestOpenBlobChangedAsItStreams: a blob that changes after OpenBlob checked it never reads to io.EOF. A byte changed
// in place or bytes added stop it with ErrBlobHash before it hands out the bytes that would complete it; a file cut
// short stops it where it ends. The error stays.
func TestOpenBlobChangedAsItStreams(t *testing.T) {
	content := bytes.Repeat([]byte("0123456789abcdef"), 64<<10) // 1 MiB
	size := int64(len(content))
	for _, c := range []struct {
		name   string
		change func(*os.File) error
	}{
		{"a byte changed in place", func(f *os.File) error { _, err := f.WriteAt([]byte{'X'}, size-1); return err }},
		{"bytes added", func(f *os.File) error { _, err := f.WriteAt([]byte("more"), size); return err }},
		{"cut short", func(f *os.File) error { return f.Truncate(size / 2) }},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			sha := putBlob(t, dir, content)
			b, err := OpenBlob(dir, sha, 2*size)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = b.Close() }()
			buf := make([]byte, 32<<10)
			n, err := b.Read(buf)
			if err != nil || n == 0 {
				t.Fatalf("the first read: %d, %v", n, err)
			}
			got := int64(n)
			f, err := os.OpenFile(filepath.Join(dir, "blobs", sha), os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			if err := c.change(f); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			for err == nil {
				n, err = b.Read(buf)
				got += int64(n)
			}
			if !errors.Is(err, ErrBlobHash) {
				t.Fatalf("the stream ended with %v after %d bytes, want ErrBlobHash", err, got)
			}
			if got >= size {
				t.Errorf("handed out %d bytes of a %d-byte blob that changed: want it stopped short", got, size)
			}
			if _, again := b.Read(buf); !errors.Is(again, ErrBlobHash) {
				t.Errorf("a Read after the refusal: %v, want ErrBlobHash again", again)
			}
		})
	}
}

// TestEmptyBlob: an empty file named by the sha256 of nothing reads back empty; under any other name it is refused,
// since the hash is checked even when there is no byte to hand out.
func TestEmptyBlob(t *testing.T) {
	dir := t.TempDir()
	sha := putBlob(t, dir, nil)
	if b, err := ReadBlob(dir, sha, 0); err != nil || len(b) != 0 {
		t.Errorf("the empty blob: %q, %v", b, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", strings.Repeat("ab", 32)), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadBlob(dir, strings.Repeat("ab", 32), 0); !errors.Is(err, ErrBlobHash) {
		t.Errorf("an empty file under another name: %v, want ErrBlobHash", err)
	}
	if _, err := OpenBlob(dir, strings.Repeat("ab", 32), 0); !errors.Is(err, ErrBlobHash) {
		t.Errorf("OpenBlob of an empty file under another name: %v, want ErrBlobHash", err)
	}
}
