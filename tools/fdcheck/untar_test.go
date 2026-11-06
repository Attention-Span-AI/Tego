// SPDX-License-Identifier: Apache-2.0

package main

import (
	"archive/tar"
	"bytes"
	"io"
	"testing"
	"time"
)

// TestUntarReadsThePaddingPastTheEndMarker: git archive pads its tar past the end-of-archive marker to a whole
// 10240-byte record, and untar must read that padding too. Left in a pipe smaller than it, it blocks git and
// extractAt's Wait never returns: TestTotalCheck hung for its 10-minute timeout on a box whose new pipes were
// 8192 bytes. An io.Pipe holds no byte, so here any byte left unread blocks the writer.
func TestUntarReadsThePaddingPastTheEndMarker(t *testing.T) {
	var b bytes.Buffer
	tw := tar.NewWriter(&b)
	src := []byte("package a\n")
	if err := tw.WriteHeader(&tar.Header{Name: "a.go", Mode: 0o644, Size: int64(len(src)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(src); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	b.Write(make([]byte, 10240-b.Len()))
	pr, pw := io.Pipe()
	t.Cleanup(func() { _ = pr.Close() })
	wrote := make(chan error, 1)
	go func() {
		_, err := pw.Write(b.Bytes())
		_ = pw.Close()
		wrote <- err
	}()
	files, err := untar(pr, t.TempDir())
	if err != nil || len(files) != 1 || files[0] != "a.go" {
		t.Fatalf("untar = %q, %v; want [a.go]", files, err)
	}
	select {
	case err := <-wrote:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("untar returned with the archive's padding unread: its writer is still blocked")
	}
}
