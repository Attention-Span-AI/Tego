// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestBodyReadsAWholeBodyBlobOnlyToTheRecordedSize is R11's bound on a body stored whole, against the blobs
// directory a same-uid tamperer can rewrite (E16): Body reads the file the event's blob names to the size the
// event recorded and one byte more, and refuses a longer file with ErrCorruptBlob rather than allocating all
// of it. An ssl_response records no size, so its blob is held to R11's 1 GiB instead and a real response body
// comes back whole. FuzzBody's blob mode asserts the same budget over arbitrary files.
func TestBodyReadsAWholeBodyBlobOnlyToTheRecordedSize(t *testing.T) {
	w, dir := startedWriter(t)
	pipeline := w.SplitBlobsStage(w.Append)
	// Not JSON, so R11 stores it whole under blob rather than as a splice.
	body := strings.Repeat("not json ", BlobThreshold/8)
	if err := pipeline(sslRequest(nil, map[string]any{"body": body, "size": len(body)})); err != nil {
		t.Fatal(err)
	}
	resp := &record.Event{Kind: record.KindSSLResponse, Source: record.SourceForwarder, PID: 3, TID: 3}
	answer := strings.Repeat("an answer ", BlobThreshold/8)
	if err := resp.SetPayload(map[string]any{"request_seq": 1, "status": 200, "latency_ms": 5,
		"parser_version": "anthropic/1", "body": answer}); err != nil {
		t.Fatal(err)
	}
	if err := pipeline(resp); err != nil {
		t.Fatal(err)
	}
	events := readAll(t, dir)[1:]
	var req record.SSLRequestPayload
	var res record.SSLResponsePayload
	if err := events[0].DecodePayload(&req); err != nil {
		t.Fatal(err)
	}
	if err := events[1].DecodePayload(&res); err != nil {
		t.Fatal(err)
	}
	if req.Blob == "" || res.Blob == "" {
		t.Fatalf("the bodies were not stored whole under blob: request %q, response %q", req.Blob, res.Blob)
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	replace := func(t *testing.T, sha, content string) {
		t.Helper()
		path := filepath.Join(dir, BlobsDir, sha)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	if got, err := r.Body(events[0]); err != nil || string(got) != body {
		t.Fatalf("the request as written: %d bytes, %v; want the %d-byte body", len(got), err, len(body))
	}
	if got, err := r.Body(events[1]); err != nil || string(got) != answer {
		t.Fatalf("the response, which records no size: %d bytes, %v; want the %d-byte body", len(got), err, len(answer))
	}

	// Exactly the recorded size passes the length bound, but bytes that are not what the blob's name hashes
	// to are refused all the same (TestBodyRefusesAWholeBlobEditedToTheSameLength); one byte more fails the bound.
	replace(t, req.Blob, strings.Repeat("y", req.Size+1))
	if got, err := r.Body(events[0]); !errors.Is(err, ErrCorruptBlob) {
		t.Errorf("a blob one byte over size %d: %d bytes, %v; want ErrCorruptBlob", req.Size, len(got), err)
	}
	replace(t, req.Blob, strings.Repeat("y", 64*req.Size))
	if got, err := r.Body(events[0]); !errors.Is(err, ErrCorruptBlob) || got != nil {
		t.Errorf("a blob 64 times its size: %d bytes, %v; want nothing and ErrCorruptBlob", len(got), err)
	}
}

// TestBodyHoldsARecordedSizeToTheCeiling is R11's ceiling on a recorded size. The forwarder records the length
// the client declared when it exceeds the bytes it read, and net/http takes any Content-Length up to 2^63-1,
// so an honest event can carry a size the agent chose. Taken as the bound it is, a size of 2^63-1 wrapped the
// blob read's size+1 and returned an empty body with no error. Each body here is stored by the real Writer and
// its blob stage, whole and as a splice, and must come back whole whatever the size says.
func TestBodyHoldsARecordedSizeToTheCeiling(t *testing.T) {
	w, dir := startedWriter(t)
	pipeline := w.SplitBlobsStage(w.Append)
	whole := strings.Repeat("not json ", BlobThreshold/8)
	spliced := string(conversation(t, 6, "")[5])
	sizes := []int64{math.MaxInt64, math.MaxInt64 - 1, 1 << 40, maxSpliceBody + 1}
	type stored struct {
		body string
		size int64
	}
	var want []stored
	for _, size := range sizes {
		for _, body := range []string{whole, spliced} {
			if err := pipeline(sslRequest(nil, map[string]any{"body": body, "size": size})); err != nil {
				t.Fatal(err)
			}
			want = append(want, stored{body, size})
		}
	}
	events := readAll(t, dir)[1:]
	if len(events) != len(want) {
		t.Fatalf("%d events for %d requests", len(events), len(want))
	}
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i, e := range events {
		var p record.SSLRequestPayload
		if err := e.DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if int64(p.Size) != want[i].size {
			t.Fatalf("request %d recorded size %d, want %d", i, p.Size, want[i].size)
		}
		stored := "blob " + p.Blob
		if p.Frame != "" {
			stored = "frame " + p.Frame
		}
		if p.Blob == "" && p.Frame == "" {
			t.Fatalf("request %d was stored inline, so the case does not reach the bound", i)
		}
		got, err := r.Body(e)
		if err != nil || string(got) != want[i].body {
			t.Errorf("size %d, %s: Body = %d bytes, %v; want the %d-byte body", want[i].size, stored, len(got), err,
				len(want[i].body))
		}
	}
}

// TestBodyLimit is the ceiling itself, since a file over 1 GiB is too large to write in a test: a recorded
// size bounds the read only where it is below maxSpliceBody, and every other size, none included, is held to
// maxSpliceBody. With the whole-body tests above, which show a file one byte over the bound refused, this is
// ErrCorruptBlob for a file over 1 GiB whatever size the event records.
func TestBodyLimit(t *testing.T) {
	for _, tc := range []struct{ size, want int64 }{
		{math.MinInt64, maxSpliceBody}, {-1, maxSpliceBody}, {0, maxSpliceBody}, {1, 1},
		{maxSpliceBody - 1, maxSpliceBody - 1}, {maxSpliceBody, maxSpliceBody}, {maxSpliceBody + 1, maxSpliceBody},
		{1 << 40, maxSpliceBody}, {math.MaxInt64, maxSpliceBody},
	} {
		if got := bodyLimit(tc.size); got != tc.want {
			t.Errorf("bodyLimit(%d) = %d, want %d", tc.size, got, tc.want)
		}
	}
}
