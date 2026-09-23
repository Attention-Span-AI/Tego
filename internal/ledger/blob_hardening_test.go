// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSplitBlobsRefusesToOverwrite covers the one way the split can destroy a recorded value: it moves a
// field's content to a different key, and that key may already be occupied. Refusing is a visible loss, which
// the pipeline turns into a gap; overwriting would be an invisible one.
func TestSplitBlobsRefusesToOverwrite(t *testing.T) {
	w, _ := startedWriter(t)
	big := strings.Repeat("x", BlobThreshold+1)
	cases := []struct {
		name    string
		payload map[string]any
	}{
		{"body beside an existing blob", map[string]any{"body": big, "blob": "already here"}},
		{"a field beside its own _blob", map[string]any{"detail": big, "detail_blob": "already here"}},
		// Both over the threshold: splitting detail_blob first freed the name detail's split then took, so
		// the outcome depended on map order. Refused every time now.
		{"a field beside its own _blob, both large", map[string]any{"detail": big, "detail_blob": big}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceSSL}
			if err := e.SetPayload(tc.payload); err != nil {
				t.Fatal(err)
			}
			before := string(e.Payload)
			for range 30 { // map order varies between runs of the same split
				probe := *e
				if err := w.splitBlobs(&probe); err == nil {
					t.Fatalf("split accepted the collision and produced %s", probe.Payload)
				}
			}
			err := w.splitBlobs(e)
			if err == nil {
				t.Fatalf("split accepted the collision and produced %s", e.Payload)
			}
			if !strings.Contains(err.Error(), "overwrite") {
				t.Errorf("error %v, want it to name the overwrite", err)
			}
			if string(e.Payload) != before {
				t.Errorf("the payload was modified on the refused path: %s", e.Payload)
			}
		})
	}
}

// TestSplitBlobsStillSplitsWithoutCollision guards the refusal from becoming over-broad: the ordinary case
// must still move a large field to a blob.
func TestSplitBlobsStillSplitsWithoutCollision(t *testing.T) {
	w, _ := startedWriter(t)
	e := &record.Event{Kind: record.KindSSLRequest, Source: record.SourceSSL}
	body := strings.Repeat("y", BlobThreshold+1)
	if err := e.SetPayload(map[string]any{"body": body, "method": "POST"}); err != nil {
		t.Fatal(err)
	}
	if err := w.splitBlobs(e); err != nil {
		t.Fatal(err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(e.Payload, &m); err != nil {
		t.Fatal(err)
	}
	if _, gone := m["body"]; gone {
		t.Errorf("body stayed inline: %s", e.Payload)
	}
	var sha string
	if err := json.Unmarshal(m["blob"], &sha); err != nil {
		t.Fatal(err)
	}
	rc, err := w.blobs.Get(sha)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rc.Close() }()
	got, err := os.ReadFile(filepath.Join(w.dir, BlobsDir, sha))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("blob holds %d bytes, want the %d-byte body", len(got), len(body))
	}
}

// TestOpenSweepsPartialBlobs covers the disk a writer leaks when it dies inside store. Open holds the run's
// exclusive lock, so anything still named .tmp- was abandoned by a process that is gone.
func TestOpenSweepsPartialBlobs(t *testing.T) {
	w, dir := startedWriter(t)
	real, err := w.Blob([]byte("a blob that must survive the sweep"))
	if err != nil {
		t.Fatal(err)
	}
	_ = w.events.Close()
	_ = w.lock.Close()

	blobs := filepath.Join(dir, BlobsDir)
	partial := filepath.Join(blobs, tmpPrefix+"1234567890")
	if err := os.WriteFile(partial, []byte("half a body"), 0o600); err != nil {
		t.Fatal(err)
	}

	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = w2.Close(record.RunEndPayload{Reason: record.RunEndStopped}) }()
	if _, err := os.Stat(partial); !os.IsNotExist(err) {
		t.Errorf("the partial blob survived Open: %v", err)
	}
	if ok, err := w2.blobs.Has(real); err != nil || !ok {
		t.Errorf("the sweep removed a real blob: has=%v err=%v", ok, err)
	}
}

// TestBlobsAreIsolatedPerRun pins R11: "message dedup is per-run, not global... no host-wide CAS, so gc
// deleting one run can never orphan another's blobs." Two runs that happen to store byte-identical content
// must each keep their own on-disk copy under their own run directory.
func TestBlobsAreIsolatedPerRun(t *testing.T) {
	root := t.TempDir()
	refA := record.RunRef{ID: runID(fixedStart, "aaaaaa"), Agent: "retriever"}
	refB := record.RunRef{ID: runID(fixedStart.Add(time.Second), "bbbbbb"), Agent: "retriever"}
	dirA, dirB := filepath.Join(root, refA.ID), filepath.Join(root, refB.ID)
	wA, err := Open(dirA, refA, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	wB, err := Open(dirB, refB, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	content := []byte("identical body two unrelated runs happen to share")
	shaA, err := wA.Blob(content)
	if err != nil {
		t.Fatal(err)
	}
	shaB, err := wB.Blob(content)
	if err != nil {
		t.Fatal(err)
	}
	if shaA != shaB {
		t.Fatalf("content-addressing must agree across runs: %s vs %s", shaA, shaB)
	}
	if _, err := os.Stat(filepath.Join(dirA, BlobsDir, shaA)); err != nil {
		t.Fatalf("run A must hold its own copy under its own run directory: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dirB, BlobsDir, shaB)); err != nil {
		t.Fatalf("run B must hold its own copy under its own run directory: %v", err)
	}
	if err := wA.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(dirA); err != nil { // what gc does to a whole run directory past retention
		t.Fatal(err)
	}
	rc, err := wB.blobs.Get(shaB)
	if err != nil {
		t.Fatalf("run B's blob must survive run A's removal: %v", err)
	}
	got, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(got) != string(content) {
		t.Fatal("run B's blob content changed")
	}
	_ = wB.Close(record.RunEndPayload{Reason: record.RunEndExit})
}

// startedWriter is openTestWriter with run_start already on disk, which splitBlobs and Blob both need.
func startedWriter(t *testing.T) (*Writer, string) {
	t.Helper()
	w, dir, _ := openTestWriter(t)
	if err := w.WriteRunStart(startPayload()); err != nil {
		t.Fatal(err)
	}
	return w, dir
}

// TestBlobPendingListIsBounded: every blob written since Open kept its
// name for one fsync at Close, without end. Past maxPendingBlobs the names are dropped and Close's Sync
// flushes the filesystem once instead.
//
// Also pins record-ledger.md R15: past the pending-name bound Close makes the blobs durable with one syncfs.
func TestBlobPendingListIsBounded(t *testing.T) {
	w, _ := startedWriter(t)
	for i := range maxPendingBlobs + 1 {
		if _, err := w.Blob([]byte(strconv.Itoa(i))); err != nil {
			t.Fatal(err)
		}
	}
	w.blobs.mu.Lock()
	n, over := len(w.blobs.pending), w.blobs.overflow
	w.blobs.mu.Unlock()
	if n != 0 || !over {
		t.Fatalf("pending %d overflow %v, want the names dropped for one syncfs", n, over)
	}
	if err := w.blobs.Sync(); err != nil {
		t.Fatalf("Sync: %v", err)
	}
	if w.blobs.overflow {
		t.Error("Sync left the overflow set")
	}
}
