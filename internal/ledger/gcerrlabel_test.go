// SPDX-License-Identifier: Apache-2.0

package ledger

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// TestGCErrorsNameTheLedgerRoot: GC and SweepLive looked runs up through the descriptor-bound root
// /proc/self/fd/<n>, and their Report.Errors carried that spelling ("open /proc/self/fd/6/r-.../events.jsonl"),
// which names nothing once tego has exited; `tego gc` printed it. They now look runs up under the root they hold
// and name the configured ledger root in their errors.
// The events file is a FIFO, which openRegular refuses for root too.
func TestGCErrorsNameTheLedgerRoot(t *testing.T) {
	root := t.TempDir()
	ref := sealedRun(t, root, fixedStart, "fifo01")
	events := filepath.Join(root, ref.ID, EventsFile)
	if err := os.Remove(events); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(events, 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(pass string, rep Report, err error) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s: %v", pass, err)
		}
		if rep.Errors[ref.ID] == nil {
			t.Fatalf("%s: no error for the unreadable run: %v", pass, rep.Errors)
		}
		for id, e := range rep.Errors {
			if msg := e.Error(); strings.Contains(msg, "/proc/self/fd/") || (id == ref.ID && !strings.Contains(msg, events)) {
				t.Errorf("%s: Errors[%s] = %q, want the path under %s", pass, id, msg, root)
			}
		}
	}
	rep, err := GC(context.Background(), root, keepAll, true)
	check("gc", rep, err)
	if err := MarkLive(root, ref.ID); err != nil {
		t.Fatal(err)
	}
	rep, err = SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	check("sweep", rep, err)
	if err := os.RemoveAll(filepath.Join(root, LiveDir)); err != nil {
		t.Fatal(err)
	}
	rep, err = SweepLive(context.Background(), root, WithWriterOptions(WithAnchor(&memAnchor{})))
	check("sweep without an index", rep, err)
}
