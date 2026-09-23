// SPDX-License-Identifier: Apache-2.0

package httpstream

import (
	"bytes"
	"compress/gzip"
	"compress/zlib"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andybalholm/brotli"
	"github.com/klauspost/compress/zstd"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

var update = flag.Bool("update", false, "rewrite the golden files in testdata")

// testKey is the connection every golden runs on: an uprobe-traced SSL* in one cgroup.
var testKey = ConnKey{Src: record.SourceSSL, CgroupID: 41, PidTgid: 1 << 32, SSLPtr: 0xdeadbeef}

// wire is one side of a conversation: the bytes and which half they belong to.
type wire struct {
	dir  Direction
	data []byte
}

func req(s string) wire  { return wire{DirRequest, []byte(s)} }
func resp(s string) wire { return wire{DirResponse, []byte(s)} }

func respBytes(b []byte) wire { return wire{DirResponse, b} }

// run feeds a conversation to a fresh assembler one wire element at a time and returns the messages, the
// gaps and the first error. split>0 feeds each element in slices of that many bytes, which is how the
// goldens prove that a chunk boundary anywhere makes no difference (edge case #17).
func run(t *testing.T, opts Options, split int, closeAtEnd bool, ws []wire) ([]*Message, []Gap, error) {
	t.Helper()
	a := NewAssembler(opts)
	var msgs []*Message
	var firstErr error
	var seq uint32 // one sequence for the connection, both directions (Chunk.Seq)
	ts := time.Unix(1700000000, 0).UTC()
	var mono uint64 = 1_000_000
	for _, w := range ws {
		parts := [][]byte{w.data}
		if split > 0 {
			parts = chop(w.data, split)
		}
		for _, p := range parts {
			seq++
			mono += 1_000_000
			got, err := a.Feed(testKey, w.dir, Chunk{Data: p, Seq: seq, TS: ts, MonoNS: mono})
			msgs = append(msgs, got...)
			if err != nil && firstErr == nil {
				firstErr = err
			}
		}
	}
	if closeAtEnd {
		msgs = append(msgs, a.Close(testKey)...)
	}
	return msgs, a.Gaps(), firstErr
}

// chop splits b into runs of at most n bytes; an empty input still yields one empty chunk, which exercises
// the assembler's handling of a zero-length write.
func chop(b []byte, n int) [][]byte {
	if len(b) == 0 {
		return [][]byte{nil}
	}
	var out [][]byte
	for len(b) > n {
		out = append(out, b[:n])
		b = b[n:]
	}
	return append(out, b)
}

// render turns messages and gaps into the stable text a golden file holds.
func render(msgs []*Message, gaps []Gap) []byte {
	var b strings.Builder
	for i, m := range msgs {
		fmt.Fprintf(&b, "message %d %s index=%d request_index=%d\n", i, m.Dir, m.Index, m.RequestIndex)
		if m.Dir == DirRequest {
			fmt.Fprintf(&b, "  start %s %s %s\n", m.Method, m.Path, m.Proto)
		} else {
			fmt.Fprintf(&b, "  start %s %d %s\n", m.Proto, m.Status, m.Reason)
		}
		keys := make([]string, 0, len(m.Header))
		for k := range m.Header {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			for _, v := range m.Header[k] {
				fmt.Fprintf(&b, "  header %s: %s\n", k, v)
			}
		}
		fmt.Fprintf(&b, "  content_encoding %q sse %t truncated %t\n", m.ContentEncoding, m.SSE, m.Truncated)
		fmt.Fprintf(&b, "  body %d %s\n", len(m.Body), strconv.Quote(string(m.Body)))
	}
	for _, g := range gaps {
		fmt.Fprintf(&b, "gap %s count=%d\n", g.Why, g.Count)
	}
	return []byte(b.String())
}

// checkGolden compares rendered output against testdata/<name>.golden, rewriting it under -update.
func checkGolden(t *testing.T, name string, got []byte) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	if *update {
		if err := os.WriteFile(path, got, 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}
	want, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("golden %s mismatch\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

// body builders for the encoding goldens.

func gzipBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := gzip.NewWriter(&out)
	mustWrite(t, w, b)
	mustClose(t, w)
	return out.Bytes()
}

func zlibBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	mustWrite(t, w, b)
	mustClose(t, w)
	return out.Bytes()
}

func brotliBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w := brotli.NewWriter(&out)
	mustWrite(t, w, b)
	mustClose(t, w)
	return out.Bytes()
}

func zstdBytes(t *testing.T, b []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := zstd.NewWriter(&out)
	if err != nil {
		t.Fatalf("zstd writer: %v", err)
	}
	mustWrite(t, w, b)
	mustClose(t, w)
	return out.Bytes()
}

type writeCloser interface {
	Write([]byte) (int, error)
	Close() error
}

func mustWrite(t *testing.T, w writeCloser, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustClose(t *testing.T, w writeCloser) {
	t.Helper()
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// httpResponse builds a Content-Length framed response carrying body.
func httpResponse(status string, headers []string, body []byte) []byte {
	var b bytes.Buffer
	b.WriteString("HTTP/1.1 " + status + "\r\n")
	for _, h := range headers {
		b.WriteString(h + "\r\n")
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)
	return b.Bytes()
}

// newGzipWriterForTest is the gzip writer the encoding tests share.
func newGzipWriterForTest(w *bytes.Buffer) writeCloser { return gzip.NewWriter(w) }
