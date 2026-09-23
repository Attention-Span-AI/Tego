// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// pendingBlobs is how many blobs are still waiting for their fsync.
func pendingBlobs(w *Writer) int {
	w.blobs.mu.Lock()
	defer w.blobs.mu.Unlock()
	return len(w.blobs.pending)
}

// TestCloseSyncsBlobsBeforeEvents pins the direction of Close's one durability barrier (R6). An events.jsonl
// line carries blob:"<sha>" — a pointer — and store never fsyncs the blob it renames into place, so the whole
// run's blob content is page cache until Close. Making the references durable first means a crash inside
// Close leaves a ledger that verifies, reads as ended and points at bodies that were never written; the other
// direction only ever leaves an orphan blob, which gc removes with the run directory.
//
// The events fsync is made to fail here so the two steps become distinguishable: the blobs must already be
// durable by the time that failure is possible.
func TestCloseSyncsBlobsBeforeEvents(t *testing.T) {
	w, _, _ := openTestWriter(t)
	startRun(t, w, 1)
	if _, err := w.Blob(bytes.Repeat([]byte("b"), 8192)); err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if pendingBlobs(w) != 1 {
		t.Fatalf("pending = %d before Close, want 1", pendingBlobs(w))
	}
	// The run_end line still has to be written, so send it to a sink that accepts it while the real
	// descriptor is closed and its Sync therefore fails.
	w.out = io.Discard
	if err := w.events.Close(); err != nil {
		t.Fatal(err)
	}
	err := w.Close(record.RunEndPayload{Reason: record.RunEndExit})
	if err == nil || !strings.Contains(err.Error(), "fsync events") {
		t.Fatalf("Close = %v, want the events fsync to fail", err)
	}
	if n := pendingBlobs(w); n != 0 {
		t.Fatalf("%d blob(s) still unsynced when the events fsync ran: the reference to a blob would have "+
			"been made durable before the bytes it names", n)
	}
}

// TestCloseReportsABlobSyncFailure: a blob that cannot be fsynced (E16 — blobs/ is not tamper-proof) is
// reported as the blob failure it is, run_end is still on disk, so the run reads as ended rather than lost,
// and the run is anchored, since its chain is durable.
func TestCloseReportsABlobSyncFailure(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	startRun(t, w, 1)
	sha, err := w.Blob(bytes.Repeat([]byte("c"), 8192))
	if err != nil {
		t.Fatalf("Blob: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, BlobsDir, sha)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err == nil ||
		!strings.Contains(err.Error(), "fsync blobs") {
		t.Fatalf("Close = %v, want the blob fsync failure", err)
	}
	if s := stateOf(t, dir); s != StateEnded {
		t.Fatalf("state = %s, want ended: run_end is written before the barrier", s)
	}
	// The chain itself is durable (events.jsonl's fsync succeeded), and the anchor vouches for the chain,
	// not for the blobs: Verify never reads them, and a lost blob is ErrCorruptBlob at read time. Withholding
	// the anchor made this run read as unanchored (ErrAnchorMissing) for good over one blob's EIO.
	if _, ok, _ := anchor.Head(testRef.ID); !ok {
		t.Fatal("a run whose events fsync succeeded was left unanchored by a blob's fsync failure")
	}
}
