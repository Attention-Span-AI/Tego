// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

func sslRequest(headers map[string]string, extra map[string]any) *record.Event {
	e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder, PID: 3, TID: 3}
	p := map[string]any{"endpoint": "anthropic", "method": "POST", "path": "/v1/messages",
		"host": "api.anthropic.com", "size": 512}
	if headers != nil {
		p["headers"] = headers
	}
	for k, v := range extra {
		p[k] = v
	}
	_ = e.SetPayload(p)
	return e
}

// Also pins record-ledger.md R9: the header allow/deny transform is the RedactStage, case-insensitive, on
// both source legs.
func TestRedactStage(t *testing.T) {
	secret := "sk-ant-api03-SECRET"
	tests := []struct {
		name    string
		source  record.Source
		headers map[string]string
		want    map[string]string
	}{
		{"ssl leg", record.SourceSSL,
			map[string]string{"x-api-key": secret, "Authorization": "Bearer " + secret, "anthropic-version": "2023-06-01",
				"Content-Type": "application/json", "cookie": "s=" + secret, "Proxy-Authorization": secret, "x-custom": "z"},
			map[string]string{"anthropic-version": "2023-06-01", "content-type": "application/json"}},
		{"forwarder leg", record.SourceForwarder,
			map[string]string{"X-API-KEY": secret, "traceparent": "00-aa-bb-01", "User-Agent": "anthropic-sdk-python", "Tracestate": "tego=r"},
			map[string]string{"traceparent": "00-aa-bb-01", "user-agent": "anthropic-sdk-python", "tracestate": "tego=r"}},
		{"duplicate casings", record.SourceSSL,
			map[string]string{"Request-Id": "first", "request-id": "second", "REQUEST-ID": "third"},
			map[string]string{"request-id": "third"}}, // lexically first original key: "REQUEST-ID"
		{"nothing allowed", record.SourceSSL, map[string]string{"x-api-key": secret}, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := sslRequest(tc.headers, nil)
			e.Source = tc.source
			var got *record.Event
			sink := RedactStage(func(e *record.Event) error { got = e; return nil })
			if err := sink(e); err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(got.Payload, []byte(secret)) {
				t.Fatalf("secret survived: %s", got.Payload)
			}
			for _, d := range DeniedHeaders {
				if strings.Contains(strings.ToLower(string(got.Payload)), d) {
					t.Fatalf("denied header %s survived: %s", d, got.Payload)
				}
			}
			var p struct {
				Headers map[string]string `json:"headers"`
			}
			if err := got.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if len(p.Headers) != len(tc.want) {
				t.Fatalf("headers = %v, want %v", p.Headers, tc.want)
			}
			for k, v := range tc.want {
				if p.Headers[k] != v {
					t.Errorf("header %s = %q, want %q", k, p.Headers[k], v)
				}
			}
			if tc.want == nil && bytes.Contains(got.Payload, []byte(`"headers"`)) {
				t.Fatalf("empty headers object must be dropped: %s", got.Payload)
			}
		})
	}
}

func TestRedactOddShapes(t *testing.T) {
	e := sslRequest(nil, map[string]any{"headers": []string{"x-api-key: s"}})
	if err := Redact(e); err != nil || bytes.Contains(e.Payload, []byte("headers")) {
		t.Fatalf("non-object headers must be dropped whole: %v %s", err, e.Payload)
	}
	e = sslRequest(nil, nil)
	before := string(e.Payload)
	if err := Redact(e); err != nil || string(e.Payload) != before {
		t.Fatalf("no headers: payload must be untouched")
	}
	e = gapEvent("x")
	e.Payload = json.RawMessage(`{"headers":`)
	if err := Redact(e); err == nil {
		t.Fatal("malformed payload must error")
	}
	w := &Writer{}
	if w.RedactStage(func(*record.Event) error { return nil })(sslRequest(nil, nil)) != nil {
		t.Fatal("method form")
	}
}

// TestCredentialsNeverOnDisk is the I2 grep test: a captured request with every credential header, run
// through the composed pipeline, leaves no trace of the secret anywhere under the run directory.
//
// Also pins record-ledger.md I2: no credential value survives the pipeline's redaction ahead of Append.
func TestCredentialsNeverOnDisk(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	startRun(t, w, 0)
	secret := "sk-ant-api03-NEVER-ON-DISK"
	body := strings.Repeat("{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}", 200)
	e := sslRequest(map[string]string{"x-api-key": secret, "authorization": "Bearer " + secret,
		"cookie": "a=" + secret, "proxy-authorization": secret, "anthropic-version": "2023-06-01"},
		map[string]any{"body": body})
	pipeline := w.RedactStage(w.SplitBlobsStage(w.Append))
	if err := pipeline(e); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if bytes.Contains(b, []byte(secret)) {
			t.Errorf("secret found in %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var p record.SSLRequestPayload
	events := readAll(t, dir)
	if err := events[1].DecodePayload(&p); err != nil || p.Headers["anthropic-version"] != "2023-06-01" || !IsSHA(p.Blob) {
		t.Fatalf("ssl_request after pipeline: %+v %v", p, err)
	}
	if bytes.Contains(events[1].Payload, []byte(`"body"`)) {
		t.Fatalf("body must be split: %s", events[1].Payload)
	}
	r, _ := OpenReader(dir)
	defer r.Close()
	rc, err := r.Blob(p.Blob)
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != body {
		t.Fatal("blob content differs from the body")
	}
}

func TestSplitBlobsThreshold(t *testing.T) {
	w, _, _ := openTestWriter(t)
	defer w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	startRun(t, w, 0)
	tests := []struct {
		name  string
		field string
		value any
		split bool
		key   string
	}{
		{"string at threshold stays", "note", strings.Repeat("a", BlobThreshold-2), false, ""},
		{"string over threshold", "note", strings.Repeat("a", BlobThreshold-1), true, "note_blob"},
		{"body lands in blob", "body", strings.Repeat("b", 5000), true, "blob"},
		{"object over threshold", "usage", map[string]string{"k": strings.Repeat("c", 5000)}, true, "usage_blob"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			e := sslRequest(nil, map[string]any{tc.field: tc.value})
			var got *record.Event
			if err := w.SplitBlobsStage(func(e *record.Event) error { got = e; return nil })(e); err != nil {
				t.Fatal(err)
			}
			var m map[string]json.RawMessage
			_ = json.Unmarshal(got.Payload, &m)
			if !tc.split {
				if _, ok := m[tc.field]; !ok {
					t.Fatalf("field must stay inline: %s", got.Payload)
				}
				return
			}
			if _, still := m[tc.field]; still {
				t.Fatalf("field still inline: %s", got.Payload)
			}
			var sha string
			if err := json.Unmarshal(m[tc.key], &sha); err != nil || !IsSHA(sha) {
				t.Fatalf("%s = %s", tc.key, m[tc.key])
			}
			want := sha256.Sum256(blobContent(t, tc.value))
			if sha != hex.EncodeToString(want[:]) {
				t.Fatalf("sha of stored content differs")
			}
			if ok, _ := w.blobs.Has(sha); !ok {
				t.Fatal("blob not stored")
			}
		})
	}
}

// blobContent is what the split stage stores for a value: decoded bytes for a string, compact JSON otherwise.
func blobContent(t *testing.T, v any) []byte {
	if s, ok := v.(string); ok {
		return []byte(s)
	}
	return mustJSON(t, v)
}

// Also pins record-ledger.md R14, I8: a colliding rename target is dedup success; the blob name is the
// content's sha256.
func TestBlobStore(t *testing.T) {
	w, dir, _ := openTestWriter(t)
	content := bytes.Repeat([]byte("tego"), 1000)
	sha, err := w.Blob(content)
	if err != nil {
		t.Fatal(err)
	}
	want := sha256.Sum256(content)
	if sha != hex.EncodeToString(want[:]) {
		t.Fatalf("sha %s", sha)
	}
	if got := fileMode(t, filepath.Join(dir, BlobsDir, sha)); got != 0o600 {
		t.Errorf("blob mode %o", got)
	}
	st1, _ := os.Stat(filepath.Join(dir, BlobsDir, sha))
	again, err := w.Blob(content)
	if err != nil || again != sha {
		t.Fatalf("dedup: %s %v", again, err)
	}
	st2, _ := os.Stat(filepath.Join(dir, BlobsDir, sha))
	if !st1.ModTime().Equal(st2.ModTime()) {
		t.Fatal("dedup must not rewrite the blob")
	}
	sha2, n, err := w.BlobFrom(bytes.NewReader(content))
	if err != nil || sha2 != sha || n != int64(len(content)) {
		t.Fatalf("BlobFrom: %s %d %v", sha2, n, err)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, BlobsDir))
	if len(entries) != 1 {
		t.Fatalf("temp files left behind: %d entries", len(entries))
	}
	if _, err := w.blobs.Get("../events.jsonl"); !errors.Is(err, ErrBadSHA) {
		t.Fatalf("path escape: %v", err)
	}
	if ok, err := w.blobs.Has(strings.Repeat("0", 64)); ok || err != nil {
		t.Fatalf("Has(missing) = %v %v", ok, err)
	}
	if _, _, err := w.BlobFrom(failingReader{}); err == nil {
		t.Fatal("reader error must surface")
	}
	entries, _ = os.ReadDir(filepath.Join(dir, BlobsDir))
	if len(entries) != 1 {
		t.Fatalf("failed stream must discard its temp file: %d entries", len(entries))
	}
	// A directory squatting on the target makes rename fail; the existing target is accepted as is.
	other := bytes.Repeat([]byte("x"), 10)
	osha := sha256.Sum256(other)
	target := filepath.Join(dir, BlobsDir, hex.EncodeToString(osha[:]))
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.BlobFrom(bytes.NewReader(other)); err != nil {
		t.Fatalf("EEXIST-style race must be benign: %v", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatalf("Close syncs blobs: %v", err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

// Also pins record-ledger.md E11: a large body streams into a blob.
func TestBlobFromStreamsLargeBody(t *testing.T) {
	if testing.Short() {
		t.Skip("32 MiB stream")
	}
	w, _, _ := openTestWriter(t)
	defer w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	const size = 32 << 20
	sha, n, err := w.BlobFrom(io.LimitReader(zeroReader{}, size))
	if err != nil || n != size {
		t.Fatalf("BlobFrom: %d %v", n, err)
	}
	h := sha256.New()
	_, _ = io.Copy(h, io.LimitReader(zeroReader{}, size))
	if sha != hex.EncodeToString(h.Sum(nil)) {
		t.Fatal("sha mismatch")
	}
}

type zeroReader struct{}

func (zeroReader) Read(b []byte) (int, error) {
	for i := range b {
		b[i] = 0
	}
	return len(b), nil
}

func BenchmarkBlob(b *testing.B) {
	dir := filepath.Join(b.TempDir(), testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		b.Fatal(err)
	}
	defer w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	content := make([]byte, 64<<10)
	b.SetBytes(int64(len(content)))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		content[0] = byte(i)
		content[1] = byte(i >> 8)
		if _, err := w.Blob(content); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkRedactStage is the redaction stage on an ssl_request with credentials in its headers and a key in
// its query string: every captured request goes through it.
func BenchmarkRedactStage(b *testing.B) {
	headers := map[string]string{"x-api-key": "sk-ant-api03-SECRET", "Authorization": "Bearer sk-ant-api03-SECRET",
		"anthropic-version": "2023-06-01", "Content-Type": "application/json", "User-Agent": "anthropic-sdk-python",
		"cookie": "s=1", "x-custom": "z"}
	payload := sslRequest(headers, map[string]any{"path": "/v1/messages?beta=true&key=abcdefghijklmnopqrstuvwxyz0123"}).Payload
	sink := RedactStage(func(*record.Event) error { return nil })
	b.ReportAllocs()
	for b.Loop() {
		e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceForwarder, PID: 3, TID: 3, Payload: payload}
		if err := sink(e); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSplitBlobsStage is the blob-splitting stage on the two captured shapes that carry bodies over
// BlobThreshold: a response whose 16 KiB body is stored whole, and a request whose 20-message conversation is
// stored as a splice with one new message per op, the rest deduplicated (R11). Each op's body is new content.
func BenchmarkSplitBlobsStage(b *testing.B) {
	msgs := make([]map[string]any, 20)
	for i := range msgs {
		msgs[i] = map[string]any{"role": []string{"user", "assistant"}[i%2], "content": strings.Repeat("m", 600) + strconv.Itoa(i)}
	}
	shapes := []struct {
		name string
		kind record.Kind
		body func(i int) string
	}{
		{"response", record.KindSSLResponse, func(i int) string { return fmt.Sprintf("%08d", i) + strings.Repeat("r", 16<<10) }},
		{"request", record.KindSSLRequest, func(i int) string {
			msgs[len(msgs)-1]["content"] = fmt.Sprintf("new %08d", i) + strings.Repeat("u", 600)
			body, _ := json.Marshal(map[string]any{"model": "claude", "max_tokens": 1024, "messages": msgs})
			return string(body)
		}},
	}
	for _, s := range shapes {
		b.Run(s.name, func(b *testing.B) {
			dir := filepath.Join(b.TempDir(), testRef.ID)
			w, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
			if err != nil {
				b.Fatal(err)
			}
			sink := w.SplitBlobsStage(func(*record.Event) error { return nil })
			b.ReportAllocs()
			i := 0
			for b.Loop() {
				e := &record.Event{Kind: s.kind, Source: record.SourceForwarder}
				_ = e.SetPayload(map[string]any{"status": 200, "body": s.body(i)})
				i++
				if err := sink(e); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		})
	}
}
