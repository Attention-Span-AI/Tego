// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/pkg/spec/config"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// retainRoot is gcRoot with extra machine-config lines.
func retainRoot(t *testing.T, extra string) string {
	t.Helper()
	root := gcRoot(t)
	cfg := os.Getenv("TEGO_CONFIG")
	if err := os.WriteFile(cfg, []byte("ledger_root: "+root+"\n"+extra), 0o600); err != nil {
		t.Fatal(err)
	}
	return root
}

// heldRun is a run started at `at` whose writer this test holds open: its lock is held, so it reads running
// however old its id is.
func heldRun(t *testing.T, root string, at time.Time) string {
	t.Helper()
	id, err := identity.NewRunID([32]byte{}, at, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	w, err := ledger.Open(filepath.Join(root, string(id)), record.RunRef{ID: string(id), Agent: "tester"},
		ledger.WithAnchor(nopAnchor{}))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.WriteRunStart(record.RunStartPayload{Command: []string{"sleep"}, Cwd: "/", Tier: "landlock"}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Abandon() })
	return string(id)
}

// retainNow runs the start's retention pass under the machine config the test wrote.
func retainNow(t *testing.T) string {
	t.Helper()
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	retainBeforeRun(context.Background(), m, &stderr)
	return stderr.String()
}

func exists(t *testing.T, root, id string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(root, id))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		t.Fatal(err)
	}
	return err == nil
}

// TestRunStartAppliesRetention: with gc_interval set, a tego run start removes the ended
// runs older than retention and keeps a fresh run and a live one however old; the chain of every run left still
// verifies against chain.log, which keeps the removed run's line (its verify then reports the ledger missing, not
// a run that never existed). A second start inside the interval removes nothing; one after it does.
func TestRunStartAppliesRetention(t *testing.T) {
	root := retainRoot(t, "retention: 30d\ngc_interval: 1h\n")
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	fresh := endedRun(t, root, time.Now().Add(-time.Hour))
	live := heldRun(t, root, time.Now().Add(-90*24*time.Hour))

	if out := retainNow(t); !strings.Contains(out, "removed 1 ended run(s) older than 30d") {
		t.Errorf("stderr %q", out)
	}
	if exists(t, root, old) || !exists(t, root, fresh) || !exists(t, root, live) {
		t.Fatalf("after the pass: old %v, fresh %v, live %v; want false, true, true",
			exists(t, root, old), exists(t, root, fresh), exists(t, root, live))
	}
	anchor := ledger.NewFileChainAnchor(ledger.DefaultAnchorPath(filepath.Join(root, fresh)))
	if _, err := ledger.VerifyRunDir(context.Background(), filepath.Join(root, fresh), anchor); err != nil {
		t.Fatalf("the run retention kept does not verify: %v", err)
	}
	if _, err := ledger.VerifyRunDir(context.Background(), filepath.Join(root, old), anchor); !errors.Is(err, ledger.ErrLedgerMissing) {
		t.Fatalf("the removed run verifies as %v, want its anchored ledger missing", err)
	}

	older := endedRun(t, root, time.Now().Add(-45*24*time.Hour))
	if out := retainNow(t); out != "" || !exists(t, root, older) {
		t.Fatalf("a start inside gc_interval ran a pass: stderr %q, run kept %v", out, exists(t, root, older))
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(root, retentionStamp), past, past); err != nil {
		t.Fatal(err)
	}
	retainNow(t)
	if exists(t, root, older) || !exists(t, root, live) {
		t.Fatalf("after the interval: expired run kept %v, live run kept %v", exists(t, root, older), exists(t, root, live))
	}
}

// TestRunStartRetentionStopsAtItsBudget: a pass whose budget is spent stops before the next run, removing nothing
// more, and the run that is starting goes on; the stamp is taken, so the next pass is the next interval's.
func TestRunStartRetentionStopsAtItsBudget(t *testing.T) {
	root := retainRoot(t, "gc_interval: 1h\n")
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	prev := retentionBudget
	retentionBudget = time.Nanosecond
	t.Cleanup(func() { retentionBudget = prev })
	if out := retainNow(t); out != "" || !exists(t, root, old) {
		t.Fatalf("a spent budget still removed: stderr %q, run kept %v", out, exists(t, root, old))
	}
	if _, err := os.Lstat(filepath.Join(root, retentionStamp)); err != nil {
		t.Fatalf("no stamp: %v", err)
	}
}

// TestRetentionStampNotOursIsReplaced: a stamp this process cannot open, the shape a root pass leaves in a user's
// ledger root when its hand-over fails or it dies before one, does not cost that user every later pass: a due
// one is replaced and the pass runs; one inside the interval stays, and no pass is due. Mode 000 stands in for
// another owner, since a test cannot make one without root. As root the stamp simply opens, and the outcomes are the
// same, so this needs no skip.
func TestRetentionStampNotOursIsReplaced(t *testing.T) {
	root := retainRoot(t, "gc_interval: 1h\n")
	stamp := filepath.Join(root, retentionStamp)
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	if err := os.WriteFile(stamp, []byte("2026-10-01T00:00:00Z\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stamp, 0); err != nil {
		t.Fatal(err)
	}
	if out := retainNow(t); out != "" || !exists(t, root, old) {
		t.Fatalf("a start inside gc_interval ran a pass: stderr %q, run kept %v", out, exists(t, root, old))
	}
	if st, err := os.Lstat(stamp); err != nil || st.Mode().Perm() != 0 {
		t.Fatalf("a stamp inside gc_interval was touched: %v, %v", st, err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stamp, past, past); err != nil {
		t.Fatal(err)
	}
	retainNow(t)
	if exists(t, root, old) {
		t.Fatal("a stamp the user cannot open cost that user the pass")
	}
	if b, err := os.ReadFile(stamp); err != nil || len(b) == 0 {
		t.Fatalf("the replaced stamp: %q, %v", b, err)
	}
}

// TestRetentionStampOnlyReplacesAFile: what sits at the stamp's name and cannot be opened is removed only when it is a
// regular file. A FIFO there stays, and is no claim.
func TestRetentionStampOnlyReplacesAFile(t *testing.T) {
	root := retainRoot(t, "gc_interval: 1h\n")
	stamp := filepath.Join(root, retentionStamp)
	if err := unix.Mkfifo(stamp, 0); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(stamp, past, past); err != nil {
		t.Fatal(err)
	}
	if release, ok := claimRetention(root, time.Hour, time.Now()); ok {
		release()
		t.Fatal("a FIFO at the stamp's name was claimed")
	}
	if st, err := os.Lstat(stamp); err != nil || st.Mode()&os.ModeNamedPipe == 0 {
		t.Fatalf("the FIFO at the stamp's name: %v, %v", st, err)
	}
}

// TestRunStartRetentionIsOffByDefault: without gc_interval no start removes anything, and nothing is written.
func TestRunStartRetentionIsOffByDefault(t *testing.T) {
	root := retainRoot(t, "")
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	if out := retainNow(t); out != "" || !exists(t, root, old) {
		t.Fatalf("stderr %q, old run kept %v", out, exists(t, root, old))
	}
	if _, err := os.Lstat(filepath.Join(root, retentionStamp)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stamp without gc_interval: %v", err)
	}
}

// TestGCWithNoFlagsStampsRetention: `tego gc` with no flags is the same pass, so the next start inside gc_interval
// skips it; gc --keep or --dry-run leaves the stamp alone.
func TestGCWithNoFlagsStampsRetention(t *testing.T) {
	root := retainRoot(t, "gc_interval: 1h\n")
	stamp := filepath.Join(root, retentionStamp)
	if code, _, errs := gcOut(t, "--dry-run"); code != identity.ExitOK {
		t.Fatal(errs)
	}
	if code, _, errs := gcOut(t, "--keep", "90d"); code != identity.ExitOK {
		t.Fatal(errs)
	}
	if _, err := os.Lstat(stamp); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("gc --dry-run or --keep stamped: %v", err)
	}
	if code, _, errs := gcOut(t); code != identity.ExitOK {
		t.Fatal(errs)
	}
	if _, err := os.Lstat(stamp); err != nil {
		t.Fatalf("gc stamped nothing: %v", err)
	}
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	if out := retainNow(t); out != "" || !exists(t, root, old) {
		t.Fatalf("a start right after gc ran a pass: stderr %q", out)
	}
}
