// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unreadableLedger makes a run directory's events.jsonl unopenable the way a shared ledger_root does: the
// directory is listable and run-shaped, the ledger itself is not ours to read. Root ignores the mode, so the
// test says so rather than asserting something false.
func unreadableLedger(t *testing.T, dir string) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root reads a 0000 file; this case needs an unprivileged uid")
	}
	if err := os.Chmod(filepath.Join(dir, EventsFile), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, EventsFile), 0o600) })
	if _, err := OpenReader(dir); err == nil {
		t.Skip("events.jsonl is still readable; this case needs a uid that the mode excludes")
	}
}

// An unreadable state gives no evidence that an orphan's descendants were cleaned up. Keep its only retry
// record even past retention, so restoring access allows a later sweep to check and clean up the run.
func TestGCKeepsARunWhoseStateCannotBeRead(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	ref := makeRun(t, root, fixedStart, "u00001", StateEnded)
	dir := filepath.Join(root, ref.ID)
	unreadableLedger(t, dir)

	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(rep.Deleted) != 0 || !sameSet(rep.Kept, []string{ref.ID}) {
		t.Fatalf("deleted = %v, kept = %v; want retained unknown state", rep.Deleted, rep.Kept)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("run directory lost its cleanup retry record: %v", err)
	}
	if rep.Errors[ref.ID] == nil {
		t.Fatal("the unreadable ledger must still be reported")
	}
}

// TestGCKeepsAnUnreadableRunWhoseLockIsHeld is the other half of the rule: when the ledger cannot be read,
// the lock is the only remaining evidence of liveness, and a live run's directory is never removed whatever
// its age (§7 row 1, I7).
func TestGCKeepsAnUnreadableRunWhoseLockIsHeld(t *testing.T) {
	root := t.TempDir()
	now := fixedStart.Add(40 * 24 * time.Hour)
	ref := makeRun(t, root, fixedStart, "u00002", StateRunning) // the Writer stays open until cleanup
	dir := filepath.Join(root, ref.ID)
	unreadableLedger(t, dir)

	rep, err := GC(context.Background(), root, 30*24*time.Hour, false, WithNow(func() time.Time { return now }))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if !sameSet(rep.Kept, []string{ref.ID}) || len(rep.Deleted) != 0 {
		t.Fatalf("kept = %v deleted = %v, want the live run kept", rep.Kept, rep.Deleted)
	}
	if _, err := os.Stat(filepath.Join(dir, EventsFile)); err != nil {
		t.Fatalf("live run's ledger removed: %v", err)
	}
	if rep.Errors[ref.ID] == nil {
		t.Fatal("the unreadable ledger must still be reported")
	}
}

// TestGCDoesNotSweepARunWhoseStateCannotBeRead: sweeping means appending run_end to a ledger, and a ledger
// nothing can read is not one to write to. The run stays for retry, unswept.
func TestGCDoesNotSweepARunWhoseStateCannotBeRead(t *testing.T) {
	root := t.TempDir()
	ref := makeRun(t, root, fixedStart, "u00003", StateLost)
	unreadableLedger(t, filepath.Join(root, ref.ID))

	var hooked []string
	rep, err := GC(context.Background(), root, 30*24*time.Hour, false,
		WithNow(func() time.Time { return fixedStart.Add(time.Hour) }), // well inside keep: nothing is removed
		WithSweepHook(func(_ context.Context, _ sys.Lender, run record.RunRef) error {
			hooked = append(hooked, run.ID)
			return nil
		}))
	if err != nil {
		t.Fatalf("GC: %v", err)
	}
	if len(rep.Swept) != 0 || len(hooked) != 0 {
		t.Fatalf("swept = %v hook = %v, want neither on an unreadable ledger", rep.Swept, hooked)
	}
	if !sameSet(rep.Kept, []string{ref.ID}) {
		t.Fatalf("kept = %v, want %v", rep.Kept, []string{ref.ID})
	}
}
