// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestBlobFieldKeyAuthorizesFromTheLine: a blob is served for a line when one of the line's own blob fields holds its
// name, and that is decided from that line's keys alone, without explaining the line: not by a blob that names the same
// sha in another kind of field, not by a splice field, not by another line, and not by reading and hashing the other
// blobs the line names.
func TestBlobFieldKeyAuthorizesFromTheLine(t *testing.T) {
	x := newXRun(t, "r-3f9c2a1b-0dmeggtrb9ncn-blobkey")
	dir := filepath.Join(x.root, x.run)
	argv := putBlob(t, dir, []byte(`["/bin/bash","-c","true"]`))
	big := putBlob(t, dir, bytes.Repeat([]byte("x"), MaxBlobBytes-1))
	body := putBlob(t, dir, []byte(`{"content":"hello"}`))
	missing := "00" + argv[2:]
	x.add(100, `"kind":"run_start","source":"supervisor","command":["codex"],"cwd":"/p","launcher_pid":100,"launcher_start_ns":5`)
	exec := x.add(200, `"kind":"exec","source":"seccomp","rule":"exec[bash]","verdict":"allow","authority":"rule","argv_blob":"`+argv+`","env_blob":"`+big+`","gone_blob":"`+missing+`","note":"`+body+`","exec_id":"r/200/6","parent_exec_id":"r/100/5","path":"/bin/bash"`)
	ssl := x.add(100, `"kind":"ssl_response","source":"forwarder","status":200,"latency_ms":3,"parser_version":"anthropic/1","blob":"`+body+`"`)
	req := x.add(100, `"kind":"ssl_request","source":"forwarder","endpoint":"anthropic","method":"POST","body_sha256":"`+body+`","frame":"`+body+`","messages":"`+body+`"`)
	other := x.add(100, `"kind":"gap","source":"supervisor","what":"x","why":"y"`)
	r := x.write(t)
	for _, c := range []struct {
		name string
		seq  uint64
		sha  string
		want string
	}{
		{"argv_blob", exec, argv, "argv_blob"},
		{"a large sibling", exec, big, "env_blob"},
		{"a blob whose file is gone is still the line's own field", exec, missing, "gone_blob"},
		{"a sha in a field that is no blob field", exec, body, ""},
		{"a sha the line does not name", exec, "ab" + argv[2:], ""},
		{"the body of a response", ssl, body, "blob"},
		{"a request body's splice is no blob", req, body, ""},
		{"another line", other, argv, ""},
	} {
		got, err := BlobFieldKey(x.root, r, c.seq, c.sha)
		if err != nil || got != c.want {
			t.Errorf("%s: key %q, error %v, want %q", c.name, got, err, c.want)
		}
	}
	if _, err := BlobFieldKey(x.root, r, 999, argv); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a line the run does not hold: %v", err)
	}
	// It reads the line and nothing else: Explain also reads and hashes the large sibling, and BlobFieldKey does not.
	alloc := func(f func()) uint64 {
		var a, b runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&a)
		f()
		runtime.ReadMemStats(&b)
		return b.TotalAlloc - a.TotalAlloc
	}
	bf := alloc(func() { _, _ = BlobFieldKey(x.root, r, exec, argv) })
	ex := alloc(func() { _, _ = Explain(x.root, r, exec) })
	if bf > MaxBlobBytes/2 || ex < 4*bf {
		t.Errorf("BlobFieldKey allocated %d bytes and Explain %d: the first should read no blob (under %d, one read buffer), the second reads the %d-byte sibling", bf, ex, MaxBlobBytes/2, MaxBlobBytes-1)
	}
}
