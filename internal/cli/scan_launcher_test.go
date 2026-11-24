// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
	tegoruntime "github.com/attention-span-ai/tego/internal/runtime"
	"github.com/attention-span-ai/tego/internal/scan/result"
)

// TestScanNamesTheLauncherOfARun: an unreadable program that is the proved lock holder of a live run is named with its
// run, so the person reads why the count is not zero; a pid that is not, a lock line that names a process that does not
// hold the lock, and a run whose lock is free are not. The scan's exit and counts do not change (the unreadable pid
// stays in the list the scan prints).
func TestScanNamesTheLauncherOfARun(t *testing.T) {
	dir, id, info := liveRun(t)
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(info.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(dir)
	got := launcherRuns(t.Context(), root, []int{info.PID, os.Getpid(), 1})
	if len(got) != 1 || got[info.PID] != id {
		t.Fatalf("launcherRuns = %v, want pid %d of run %s only", got, info.PID, id)
	}
	// A planted line: this process is alive and is named by the line, but it does not hold the lock.
	self := os.Getpid()
	start, err := tegoruntime.StartBootNS(self)
	if err != nil {
		t.Fatal(err)
	}
	planted := tegoruntime.LockInfo{PID: self, StartBootNS: start}
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(planted.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := launcherRuns(t.Context(), root, []int{self}); len(got) != 0 {
		t.Fatalf("a planted lock line named a launcher: %v", got)
	}
	if got := launcherRuns(t.Context(), filepath.Join(root, "missing"), []int{self}); len(got) != 0 {
		t.Fatalf("no ledger root: %v", got)
	}
	if got := launcherRuns(t.Context(), root, nil); got != nil {
		t.Fatalf("no pids: %v", got)
	}
}

// TestScanSaysWhichUnreadableProgramIsALauncher: the line `tego scan` prints beside the unreadable count. It names the
// proved launcher and no other pid, prints nothing for a failed scan or when nothing is unreadable, and goes to stderr
// only, so the JSON result and the count keep their shape.
func TestScanSaysWhichUnreadableProgramIsALauncher(t *testing.T) {
	dir, id, info := liveRun(t)
	if err := os.WriteFile(filepath.Join(dir, ledger.LockFile), []byte(info.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	old := scanLedgerRoot
	scanLedgerRoot = func(string, uint32) (string, error) { return filepath.Dir(dir), nil }
	t.Cleanup(func() { scanLedgerRoot = old })
	s := result.New(time.Now(), uint32(os.Getuid()), "dev")
	s.Status, s.UnreadableProgramPIDs = "partial", []int{os.Getpid(), info.PID}
	var errs bytes.Buffer
	nameLaunchers(t.Context(), &errs, t.TempDir(), s)
	want := fmt.Sprintf("tego scan: pid %d is the launcher of run %s;", info.PID, id)
	if !strings.Contains(errs.String(), want) || strings.Contains(errs.String(), fmt.Sprintf("pid %d ", os.Getpid())) {
		t.Fatalf("stderr %q, want a line starting %q and none for pid %d", errs.String(), want, os.Getpid())
	}
	if strings.Count(errs.String(), "\n") != 1 {
		t.Fatalf("stderr %q: want one line", errs.String())
	}
	errs.Reset()
	s.UnreadableProgramPIDs = nil
	nameLaunchers(t.Context(), &errs, t.TempDir(), s)
	failed := result.New(time.Now(), uint32(os.Getuid()), "dev")
	failed.Status, failed.UnreadableProgramPIDs = "failed", []int{info.PID}
	nameLaunchers(t.Context(), &errs, t.TempDir(), failed)
	if errs.Len() != 0 {
		t.Fatalf("stderr %q for nothing unreadable and for a failed scan", errs.String())
	}
}
