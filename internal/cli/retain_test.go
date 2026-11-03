// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
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
// more, and the run that is starting goes on; the stamp is taken, so the next pass is the next interval's. The
// rule-change journal it left unpruned is in tego's own log: a budget spent on every pass left it unpruned for good
// with no word of it.
func TestRunStartRetentionStopsAtItsBudget(t *testing.T) {
	root := retainRoot(t, "gc_interval: 1h\n")
	old := endedRun(t, root, time.Now().Add(-60*24*time.Hour))
	journaled(t, root)
	prev := retentionBudget
	retentionBudget = time.Nanosecond
	t.Cleanup(func() { retentionBudget = prev })
	if out := retainNow(t); out != "" || !exists(t, root, old) {
		t.Fatalf("a spent budget still removed: stderr %q, run kept %v", out, exists(t, root, old))
	}
	if _, err := os.Lstat(filepath.Join(root, retentionStamp)); err != nil {
		t.Fatalf("no stamp: %v", err)
	}
	const said = "retention: rule-change journal: not pruned, the pass's 1ns budget ran out"
	if b, err := os.ReadFile(logPath(testHome, "")); err != nil || !strings.Contains(string(b), said) {
		t.Errorf("tego's own log (%v) does not say %q", err, said)
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

// passUser is the user a test of a root pass's journal prune has invoke the pass: its uid, and the group it gives.
type passUser struct{ uid, gid int }

// As root (the root suites, CI's root-suites job), a test of a root pass's journal prune hands the journal to a user of
// its own, passUID with group passGID, as the own log's root tests use, and the journal's folders carry foldersGID, a
// group that is not the user's: the one a setgid ledger root gives what is made in it, say.
const (
	passUID    = 4242
	passGID    = 4343
	foldersGID = 4344
)

// journalFor hands root, with its rule-change journal, to the user a test of a root pass prunes it for, and returns
// that user. As root the prune really runs as that user (asRoot, sys.RunAs): root and everything in it become passUID's
// in group foldersGID, as the user's own tego rule and runs would have left them in a setgid ledger root, and every
// directory the test made on the way down to root is made searchable, never writable, by others. Otherwise root is
// played through the seams, and the user is this process's, the journal's owner, with a group the journal's folder
// does not carry, so that the prune's group cannot be taken for the folder's.
func journalFor(t *testing.T, root string) passUser {
	t.Helper()
	if os.Geteuid() != 0 {
		var st unix.Stat_t
		if err := unix.Lstat(filepath.Join(root, rulefile.JournalDirName), &st); err != nil {
			t.Fatal(err)
		}
		return passUser{uid: int(st.Uid), gid: int(st.Gid) + 1}
	}
	err := filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return os.Lchown(p, passUID, foldersGID)
	})
	if err != nil {
		t.Fatal(err)
	}
	openWay(t, filepath.Dir(root))
	return passUser{uid: passUID, gid: passGID}
}

// openWay makes dir and every directory above it up to the test's own temporary directory searchable by every user,
// adding no write bit, and fails the test when a directory above that is not: the user a root pass acts as reaches
// its ledger root, and the folders of its rules files, through them.
func openWay(t *testing.T, dir string) {
	t.Helper()
	top := filepath.Dir(t.TempDir()) // the test's own temporary directory, which holds every one t.TempDir makes
	for d := dir; ; d = filepath.Dir(d) {
		st, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		switch {
		case st.Mode().Perm()&0o001 != 0:
		case d == top || strings.HasPrefix(d, top+string(filepath.Separator)):
			if err := os.Chmod(d, st.Mode().Perm()|0o011); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("%s is not searchable by other users, so no user but root reaches %s; set TMPDIR to a directory "+
				"they can search", d, dir)
		}
		if d == filepath.Dir(d) {
			return
		}
	}
}

// asRoot makes the rule-change journal's prune (journalOwner) read this process as root, invoked by u's uid, through
// sudo when viaSudo, whose group is u's, and records the credentials runAs is asked to take, which it returns. As root
// runAs takes them (sys.RunAs), and the prune runs as u; otherwise it runs the prune as this process, the user whose
// journal it is.
func asRoot(t *testing.T, u passUser, viaSudo bool) *[]sys.TaskCreds {
	t.Helper()
	asked := &[]sys.TaskCreds{}
	prevEUID, prevUID, prevGID, prevAs := procEUID, invokingUID, invokingGID, runAs
	t.Cleanup(func() { procEUID, invokingUID, invokingGID, runAs = prevEUID, prevUID, prevGID, prevAs })
	root := os.Geteuid() == 0
	if !root {
		procEUID = func() int { return 0 }
	}
	if was, err := sys.Dumpable(); root && err == nil && was {
		// A thread that takes another uid makes the process undumpable (sys.RunAs); the tests after this one find it
		// as they would have.
		t.Cleanup(func() { _ = sys.SetDumpable(true) })
	}
	invokingUID = func() (int, bool) { return u.uid, viaSudo }
	invokingGID = func(int) (int, bool) { return u.gid, true }
	runAs = func(c sys.TaskCreds, fn func()) error {
		*asked = append(*asked, c)
		if root {
			return sys.RunAs(c, fn)
		}
		fn()
		return nil
	}
	return asked
}

// journalContracts is the contract of each line of root's rule-change journal, read from the file as it lies: a root
// test reads a journal it handed to another user, which ReadJournal, run as root, refuses as not root's.
func journalContracts(t *testing.T, root string) []string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root, rulefile.JournalDirName, rulefile.JournalFile))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, l := range bytes.Split(b, []byte("\n")) {
		if len(l) == 0 {
			continue
		}
		var e rulefile.Entry
		if err := json.Unmarshal(l, &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Contract)
	}
	return out
}

// userMade fails the test when, as root, the journal file a prune rewrote is not u's, in u's group, or a file in the
// journal is root's: the prune ran as the user whose journal it is. Otherwise the test plays root, and the process is
// the user, so there is nothing to tell.
func userMade(t *testing.T, root string, u passUser) {
	t.Helper()
	if os.Geteuid() != 0 {
		return
	}
	dir := filepath.Join(root, rulefile.JournalDirName)
	var st unix.Stat_t
	if err := unix.Lstat(filepath.Join(dir, rulefile.JournalFile), &st); err != nil {
		t.Fatal(err)
	}
	if int(st.Uid) != u.uid || int(st.Gid) != u.gid {
		t.Errorf("the journal the prune wrote is %d:%d, want the user's %d:%d", st.Uid, st.Gid, u.uid, u.gid)
	}
	err := filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		var st unix.Stat_t
		if err := unix.Lstat(p, &st); err != nil {
			return err
		}
		if st.Uid == 0 {
			t.Errorf("%s is root's: the prune wrote there as root", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestRootRunStartPrunesTheJournalAsTheInvokingUser: `sudo tego run` (tiers 2 and 3 need root) works in the invoking
// user's ledger root, whose rule-change journal root may not write (the user's own writes would refuse a file root
// made). Its start's pass prunes that journal as the user, once, with the user's uid and group alone and no
// capability, and says so as a user's start does; so does `sudo tego gc`. It looks at the rules files as the user too:
// a file in a folder the user cannot search may be there for all the user can tell, so its lines stay. As root (the
// root suites) the prune really runs as another user, and the journal it rewrote is that user's, in that user's group.
// Its looks ran on threads of root's, with every capability, which saw that file gone and pruned its lines, and it took
// the journal folder's group (here not the user's) for the user's.
func TestRootRunStartPrunesTheJournalAsTheInvokingUser(t *testing.T) {
	root := retainRoot(t, "retention: 0s\ngc_interval: 1h\n")
	open := func() string {
		d := t.TempDir()
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
		return d
	}
	journaledIn(t, root, open(), "gone-", false)
	later := journaledIn(t, root, open(), "later-", true)
	shut := t.TempDir()
	closed := journaledIn(t, root, shut, "closed-", false)
	if err := os.Chmod(shut, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(shut, 0o700) }) // so that the temporary directory can be removed
	u := journalFor(t, root)
	want := sys.TaskCreds{EUID: uint32(u.uid), EGID: uint32(u.gid), FSUID: uint32(u.uid), FSGID: uint32(u.gid),
		Groups: []uint32{uint32(u.gid)}}
	asked := asRoot(t, u, true)

	if out := retainNow(t); !strings.Contains(out, "retention pruned 2 rule-change journal line(s)") {
		t.Errorf("stderr %q", out)
	}
	if left := journalContracts(t, root); !slices.Equal(left, []string{later, later, closed, closed}) ||
		len(*asked) != 1 || !(*asked)[0].Equal(want) {
		t.Errorf("lines of %v left, pruned as %+v; want the lines of the file gone pruned and the rest kept, once as %+v",
			left, *asked, want)
	}
	userMade(t, root, u)

	if err := os.Remove(later); err != nil {
		t.Fatal(err)
	}
	code, out, errs := gcOut(t, "--keep", "0s")
	if code != identity.ExitOK || !strings.Contains(out, "rule-change journal: pruned 2 line(s), 3 blob(s), 1 lock file(s)") ||
		len(*asked) != 2 || !(*asked)[1].Equal(want) {
		t.Errorf("sudo tego gc: exit %d, stdout %q, stderr %q, pruned as %+v", code, out, errs, *asked)
	}
	if left := journalContracts(t, root); !slices.Equal(left, []string{closed, closed}) {
		t.Errorf("after sudo tego gc, lines of %v left; want those of the file the user cannot look at alone", left)
	}
	userMade(t, root, u)
}

// TestRootPassLeavesAnotherUsersJournal: a root pass meeting the rule-change journal of a user who did not invoke it
// (another uid through sudo, or no sudo at all) takes on no one's credentials and prunes nothing, and says why: gc on
// stderr, its exit 0. As root the journal is a user's of the test's own; it was root's, which a root pass prunes as
// root, so the root suites saw it pruned.
func TestRootPassLeavesAnotherUsersJournal(t *testing.T) {
	root := gcRoot(t)
	journaled(t, root)
	owner := journalFor(t, root)
	for _, who := range []struct {
		uid  int
		sudo bool
	}{{owner.uid + 1, true}, {owner.uid, false}} {
		asked := asRoot(t, passUser{uid: who.uid, gid: owner.gid}, who.sudo)
		code, out, errs := gcOut(t, "--keep", "0s")
		if code != identity.ExitOK || strings.Contains(out, "rule-change journal") ||
			!strings.Contains(errs, "rule-change journal: rulefile: the rule-change journal is another user's") {
			t.Errorf("invoked by %d (sudo %v): exit %d, stdout %q, stderr %q", who.uid, who.sudo, code, out, errs)
		}
		if n := len(journalContracts(t, root)); n != 2 || len(*asked) != 0 {
			t.Errorf("invoked by %d (sudo %v): %d lines left, pruned as %+v; want both, as no one", who.uid, who.sudo, n,
				*asked)
		}
	}
}

// TestRootPassLeavesTheJournalOfAUserWithNoGroup: a root pass prunes the invoking user's journal with that user's
// group, SUDO_GID's or the passwd database's (sudoGID). With neither naming one it takes on no credentials, prunes
// nothing and says why, the exit 0, as a root run of that user is refused for the same lack; it never falls back to
// the group the journal's folder carries.
func TestRootPassLeavesTheJournalOfAUserWithNoGroup(t *testing.T) {
	root := gcRoot(t)
	journaled(t, root)
	u := journalFor(t, root)
	asked := asRoot(t, u, true)
	invokingGID = func(int) (int, bool) { return 0, false }
	code, out, errs := gcOut(t, "--keep", "0s")
	if code != identity.ExitOK || strings.Contains(out, "rule-change journal") ||
		!strings.Contains(errs, "rule-change journal: "+errGroupUnknown.Error()) {
		t.Errorf("exit %d, stdout %q, stderr %q", code, out, errs)
	}
	if n := len(journalContracts(t, root)); n != 2 || len(*asked) != 0 {
		t.Errorf("%d lines left, pruned as %+v; want both, as no one", n, *asked)
	}
}

// TestSudoGIDIsSudosElseThePasswdGroup: the group a root tego gives the invoking user's files, and prunes their journal
// with, is SUDO_GID when it is a gid, else the uid's group in the passwd database, and none for a uid that database
// does not name.
func TestSudoGIDIsSudosElseThePasswdGroup(t *testing.T) {
	uid := os.Getuid()
	pw, err := config.LookupPasswd(uid)
	wantOK := err == nil
	want := -1
	if wantOK {
		if want, err = strconv.Atoi(pw.Gid); err != nil {
			t.Fatal(err)
		}
	}
	for _, env := range []string{"", "x", "4294967295", "-1"} { // unset, or no gid: (gid_t)-1 is "no group"
		t.Setenv("SUDO_GID", env)
		if gid, ok := sudoGID(uid); ok != wantOK || ok && gid != want {
			t.Errorf("SUDO_GID %q: %d, %v; want the passwd group %d, %v", env, gid, ok, want, wantOK)
		}
	}
	t.Setenv("SUDO_GID", "4343")
	if gid, ok := sudoGID(uid); !ok || gid != 4343 {
		t.Errorf("SUDO_GID 4343: %d, %v", gid, ok)
	}
	t.Setenv("SUDO_GID", "")
	none := 1 << 30
	for ; ; none++ {
		if _, err := config.LookupPasswd(none); err != nil {
			break
		}
	}
	if gid, ok := sudoGID(none); ok {
		t.Errorf("uid %d, which the passwd database does not name: group %d", none, gid)
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
