// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestGCLeavesARunThatHoldsItsLock is limits-check-doctor-cli.md E21: gc takes the same flock probe as run
// and stop before it touches a directory, so a run whose launcher is alive is neither ended as an orphan nor
// deleted, however old its id says it is, and it is corrupted by neither pass: once it finishes, the next
// pass treats it as any ended run past the window.
func TestGCLeavesARunThatHoldsItsLock(t *testing.T) {
	root := gcRoot(t)
	at := time.Now().Add(-90 * 24 * time.Hour) // far past retention, so only the lock can save it
	id, err := identity.NewRunID(localHost(), at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, string(id))
	w, err := ledger.Open(dir, record.RunRef{ID: string(id), Agent: "tester"})
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = w.Close(record.RunEndPayload{Reason: record.RunEndExit})
		}
	})
	if err := w.WriteRunStart(record.RunStartPayload{
		Command: []string{"true"}, Cwd: "/", Tier: "landlock", TegoVersion: "test", Kernel: "test",
		ContractHash: strings.Repeat("a", 64), LauncherPID: 1, LauncherStartNS: 1,
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatal(err)
	}

	code, out, errs := gcOut(t)
	if code != identity.ExitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	if strings.Contains(out, "orphaned") && !strings.Contains(out, "ended 0 orphaned") {
		t.Errorf("output %q: gc ended a run whose launcher holds the lock", out)
	}
	after, err := os.ReadFile(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		t.Fatalf("gc removed a live run's ledger: %v", err)
	}
	if string(after) != string(before) {
		t.Errorf("gc wrote to a live run's ledger:\n before %q\n after  %q", before, after)
	}

	closed = true
	if err := w.Close(record.RunEndPayload{Reason: record.RunEndExit}); err != nil {
		t.Fatal(err)
	}
	if code, _, errs := gcOut(t); code != identity.ExitOK {
		t.Fatalf("second pass exit %d: %s", code, errs)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("the finished run past retention survived the next pass: %v", err)
	}
}
