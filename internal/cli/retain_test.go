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
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/rulefile"
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
	m, ds, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	retainBeforeRun(context.Background(), m, "tego run", ds, &stderr)
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

// TestRunStartPrunesTheRuleChangeJournal: a start's retention pass prunes the ledger root's rule-change journal with
// the machine's retention, and says how many lines went.
func TestRunStartPrunesTheRuleChangeJournal(t *testing.T) {
	root := retainRoot(t, "retention: 0s\ngc_interval: 1h\n")
	journaled(t, root)
	if out := retainNow(t); !strings.Contains(out, "retention pruned 2 rule-change journal line(s) older than 0s") {
		t.Errorf("stderr %q", out)
	}
	if n := journalLines(t, root); n != 0 {
		t.Errorf("the journal holds %d lines after the pass", n)
	}
}

// TestRunStartJournalNotPrunedWithoutTheUserLayer: the one layer a run start's load (TrustAbort) leaves out without
// refusing the run is the per-user layer of a uid the passwd database does not name (E9). That layer may set the
// retention, so the pass prunes nothing of the rule-change journal; the runs are swept as before.
func TestRunStartJournalNotPrunedWithoutTheUserLayer(t *testing.T) {
	root := retainRoot(t, "retention: 0s\ngc_interval: 1h\n")
	journaled(t, root)
	uid := 1 << 30
	for ; ; uid++ {
		if _, err := config.LookupPasswd(uid); err != nil {
			break
		}
	}
	_, _, ds := config.Resolve(uid, false)
	if _, ok := skippedLayer(ds); !ok {
		t.Fatalf("Resolve for uid %d, which has no passwd entry, says no layer was left out: %v", uid, ds)
	}
	m, _, err := loadMachine(config.TrustWarn)
	if err != nil {
		t.Fatal(err)
	}
	var stderr bytes.Buffer
	retainBeforeRun(context.Background(), m, "tego run", ds, &stderr)
	if n := journalLines(t, root); n != 2 || strings.Contains(stderr.String(), "rule-change") {
		t.Errorf("the journal holds %d lines after the pass, want both; stderr %q", n, stderr.String())
	}
}

// asRoot makes the rule-change journal's prune (journalOwner) read this process as root, invoked by uid through sudo
// when viaSudo, with a runAs that records the credentials it was asked to take and runs the prune as this process:
// the test's user, whose journal it is. It returns what runAs was asked.
func asRoot(t *testing.T, uid int, viaSudo bool) *[]sys.TaskCreds {
	t.Helper()
	asked := &[]sys.TaskCreds{}
	prevEUID, prevInvoking, prevAs := procEUID, invokingUID, runAs
	procEUID = func() int { return 0 }
	invokingUID = func() (int, bool) { return uid, viaSudo }
	runAs = func(c sys.TaskCreds, fn func()) error {
		*asked = append(*asked, c)
		fn()
		return nil
	}
	t.Cleanup(func() { procEUID, invokingUID, runAs = prevEUID, prevInvoking, prevAs })
	return asked
}

// journalOwnerCreds are the credentials a root pass prunes root's journal with: its owner's uid and gid, no capability.
func journalOwnerCreds(t *testing.T, root string) sys.TaskCreds {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(root, rulefile.JournalDirName), &st); err != nil {
		t.Fatal(err)
	}
	return sys.TaskCreds{EUID: st.Uid, EGID: st.Gid, FSUID: st.Uid, FSGID: st.Gid, Groups: []uint32{st.Gid}}
}

// TestRootRunStartPrunesTheJournalAsTheInvokingUser: `sudo tego run` (tiers 2 and 3 need root) works in the invoking
// user's ledger root, whose rule-change journal root may not write (the user's own writes would refuse a file root
// made). Its start's pass prunes that journal as the user, once, and says so as a user's start does; so does `sudo
// tego gc`.
func TestRootRunStartPrunesTheJournalAsTheInvokingUser(t *testing.T) {
	root := retainRoot(t, "retention: 0s\ngc_interval: 1h\n")
	journaled(t, root)
	want := journalOwnerCreds(t, root)
	asked := asRoot(t, int(want.EUID), true)
	if out := retainNow(t); !strings.Contains(out, "retention pruned 2 rule-change journal line(s)") {
		t.Errorf("stderr %q", out)
	}
	if n := journalLines(t, root); n != 0 || len(*asked) != 1 || !(*asked)[0].Equal(want) {
		t.Errorf("%d lines left, pruned as %+v; want none left, pruned once as %+v", n, *asked, want)
	}

	journaled(t, root)
	code, out, errs := gcOut(t, "--keep", "0s")
	if code != identity.ExitOK || !strings.Contains(out, "rule-change journal: pruned 2 line(s)") ||
		len(*asked) != 2 || !(*asked)[1].Equal(want) {
		t.Errorf("sudo tego gc: exit %d, stdout %q, stderr %q, pruned as %+v", code, out, errs, *asked)
	}
}

// TestRootPassLeavesAnotherUsersJournal: a root pass meeting the rule-change journal of a user who did not invoke it
// (another uid through sudo, or no sudo at all) takes on no one's credentials and prunes nothing, and says why: gc on
// stderr, its exit 0.
func TestRootPassLeavesAnotherUsersJournal(t *testing.T) {
	root := gcRoot(t)
	journaled(t, root)
	owner := int(journalOwnerCreds(t, root).EUID)
	for _, who := range []struct {
		uid  int
		sudo bool
	}{{owner + 1, true}, {owner, false}} {
		asked := asRoot(t, who.uid, who.sudo)
		code, out, errs := gcOut(t, "--keep", "0s")
		if code != identity.ExitOK || strings.Contains(out, "rule-change journal") ||
			!strings.Contains(errs, "rule-change journal: rulefile: the rule-change journal is another user's") {
			t.Errorf("invoked by %d (sudo %v): exit %d, stdout %q, stderr %q", who.uid, who.sudo, code, out, errs)
		}
		if n := journalLines(t, root); n != 2 || len(*asked) != 0 {
			t.Errorf("invoked by %d (sudo %v): %d lines left, pruned as %+v; want both, as no one", who.uid, who.sudo, n,
				*asked)
		}
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
