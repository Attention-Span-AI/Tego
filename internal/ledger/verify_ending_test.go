// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// endingAnchor ends the run inside Head, the way a launcher's Close lands between Verify's scan and its anchor read.
type endingAnchor struct {
	*memAnchor
	w    *Writer
	once bool
}

func (a *endingAnchor) Head(run string) (string, bool, error) {
	if !a.once {
		a.once = true
		if err := a.w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
			return "", false, err
		}
	}
	return a.memAnchor.Head(run)
}

// TestVerifyRunEndingBetweenScanAndAnchorRead: a run that ends after the scan but before the anchor read is an
// intact ledger, not ErrCorruptChain, and the report's Lines and Head are the rescan's, the anchored ones: the
// first scan's deferred Lines/Head overwrote them, so `events --verify` printed the stale line count and head.
func TestVerifyRunEndingBetweenScanAndAnchorRead(t *testing.T) {
	mem := &memAnchor{}
	dir := filepath.Join(t.TempDir(), "runs", testRef.ID)
	w, err := Open(dir, testRef, WithAnchor(mem))
	if err != nil {
		t.Fatal(err)
	}
	startRun(t, w, 1)
	rep, err := verifyErr(t, dir, &endingAnchor{memAnchor: mem, w: w})
	if err != nil || !rep.Anchored || !rep.Ended {
		t.Fatalf("Verify across run end = %+v, %v, want anchored and ended", rep, err)
	}
	head, _, err := mem.Head(testRef.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Lines != 3 || rep.Head != head {
		t.Errorf("Verify across run end: Lines %d, Head %q; want 3 (run_start, event, run_end), anchored %q",
			rep.Lines, rep.Head, head)
	}
}
