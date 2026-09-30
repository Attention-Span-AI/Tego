// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestLastLineFindsTheLineBeforeALongTornTail: a crash mid-write leaves a torn tail after the last complete
// line. With a long line before it, the window that held the last line alone held no boundary before the
// torn bytes, and State called a legitimate ledger corrupt.
func TestLastLineFindsTheLineBeforeALongTornTail(t *testing.T) {
	first := `{"pad":"` + strings.Repeat("a", 1_200_000) + `"}`
	torn := strings.Repeat("b", 1_200_000)
	body := "x\n" + first + "\n" + torn
	f := bytes.NewReader([]byte(body))
	line, present, err := lastLine(f, int64(len(body)))
	if err != nil || !present || string(line) != first {
		t.Fatalf("lastLine: len %d present %v err %v", len(line), present, err)
	}
}

// TestVerifyWrapsAnOverLongLineInErrUnverified: a line past MaxLineBytes is the ledger's content, so verify
// reports a finding (exit 1), not a read failure (exit 125).
func TestVerifyWrapsAnOverLongLineInErrUnverified(t *testing.T) {
	dir, anchor := closedRun(t, 1)
	f, err := os.OpenFile(filepath.Join(dir, EventsFile), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, werr := f.Write(append(bytes.Repeat([]byte("x"), MaxLineBytes+10), '\n'))
	_ = f.Close()
	if werr != nil {
		t.Fatal(werr)
	}
	_, err = verifyErr(t, dir, anchor)
	if !errors.Is(err, ErrUnverified) || !errors.Is(err, ErrCorruptLedger) {
		t.Fatalf("Verify = %v, want ErrUnverified wrapping ErrCorruptLedger", err)
	}
}

// TestGCCountsARunAConcurrentGCRemovedAsDeleted: the run is gone between List and this pass's removal lock,
// which is retention's outcome, not an error.
func TestGCCountsARunAConcurrentGCRemovedAsDeleted(t *testing.T) {
	root := filepath.Join(t.TempDir(), "runs")
	w, ref := openLive(t, root, fixedStart, "gone11")
	startRun(t, w, 1)
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	remove := WithForeignRun(func(id string) bool {
		if err := os.RemoveAll(filepath.Join(root, id)); err != nil {
			t.Error(err)
		}
		return false
	})
	now := WithNow(func() time.Time { return fixedStart.Add(365 * 24 * time.Hour) })
	rep, err := GC(context.Background(), root, 24*time.Hour, false, remove, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Errors) != 0 || !slices.Contains(rep.Deleted, ref.ID) {
		t.Fatalf("a run removed under gc: %+v", rep)
	}
}
