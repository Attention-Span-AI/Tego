// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAbandonWritesNothing: a launcher whose run failed before run_start closed its
// Writer with Close, which appended run_end as line 0 of a ledger that never started. A launcher that died
// before removing the directory left a run that reads as ended with no run_start; Abandon releases the lock
// and the descriptors and leaves the empty ledger that says the run never started.
func TestAbandonWritesNothing(t *testing.T) {
	w, dir, anchor := openTestWriter(t)
	if err := w.Abandon(); err != nil {
		t.Fatalf("Abandon: %v", err)
	}
	if st, err := os.Stat(filepath.Join(dir, EventsFile)); err != nil || st.Size() != 0 {
		t.Fatalf("an abandoned run's ledger must hold no line: %v", err)
	}
	if _, ok, _ := anchor.Head(testRef.ID); ok {
		t.Fatal("an abandoned run must not be anchored")
	}
	if state, err := NewRunRepository(filepath.Dir(dir)).State(context.Background(), testRef.ID); err != nil || state != StateEmpty {
		t.Fatalf("state %q (%v), want empty", state, err)
	}
	if err := w.Abandon(); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("a second Abandon: %v, want ErrAlreadyClosed", err)
	}
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndError}); !errors.Is(err, ErrAlreadyClosed) {
		t.Fatalf("Close after Abandon: %v, want ErrAlreadyClosed", err)
	}
	w2, err := Open(dir, testRef, WithAnchor(&memAnchor{}))
	if err != nil {
		t.Fatalf("the lock must be free after Abandon: %v", err)
	}
	_ = w2.Abandon()
}
