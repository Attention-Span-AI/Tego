// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const day = 24 * time.Hour

// clock sets the journal's clock to when, until the test ends or now is set again.
func clock(t *testing.T, when time.Time) {
	t.Helper()
	now = func() time.Time { return when }
	t.Cleanup(func() { now = time.Now })
}

// ageBlobs dates every file in root's blobs/ d ago, as an old change's blobs are.
func ageBlobs(t *testing.T, root string, d time.Duration) {
	t.Helper()
	dir := filepath.Join(root, JournalDirName, BlobsDir)
	old := time.Now().Add(-d)
	for _, n := range names(t, root, BlobsDir) {
		if err := os.Chtimes(filepath.Join(dir, n), old, old); err != nil {
			t.Fatal(err)
		}
	}
}

// write replaces the contract at path, which holds from, with to.
func write(t *testing.T, g Guard, path, from, to string) *Entry {
	t.Helper()
	e, err := Replace(context.Background(), g, path, Sum([]byte(from)), []byte(to), Change{Via: "cli"})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// names is what the directory dir (BlobsDir, LocksDir) of root's journal holds, sorted.
func names(t *testing.T, root, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(filepath.Join(root, JournalDirName, dir))
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range ents {
		out = append(out, e.Name())
	}
	return out
}

// tree is every file under root's journal directory, by path: its sha256 and modification time.
func tree(t *testing.T, root string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(filepath.Join(root, JournalDirName), func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		out[p] = fmt.Sprintf("%s %d", Sum(b), info.ModTime().UnixNano())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// numbered is textA with a numbered comment line: a contract text of its own for each i.
func numbered(i int) string { return fmt.Sprintf("%s# %d\n", textA, i) }

// TestPruneAgesOutWhatNoLineNeeds: the lines older than the retention of a contract whose file is gone go, with the
// blobs no line left names and the lock files of contracts with no line left; a blob a line left names stays, the
// lock file of the contract that line writes stays, and the change it records still undoes.
func TestPruneAgesOutWhatNoLineNeeds(t *testing.T) {
	g, path := fixture(t)
	gone := filepath.Join(filepath.Dir(path), "gone.yaml")
	if err := os.WriteFile(gone, []byte(textA), 0o600); err != nil {
		t.Fatal(err)
	}
	clock(t, time.Now().Add(-60*day))
	write(t, g, gone, textA, textB)
	write(t, g, gone, textB, textC)
	write(t, g, path, textA, textB) // names textA's and textB's blobs too
	now = time.Now
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	ageBlobs(t, g.LedgerRoot, 60*day)

	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil {
		t.Fatal(err)
	}
	if want := (Pruned{Lines: 2, Blobs: 1, Locks: 1}); p != want {
		t.Errorf("pruned %+v, want %+v", p, want)
	}
	es, err := ReadJournal(g.LedgerRoot)
	if err != nil || len(es) != 1 || es[0].Contract != path {
		t.Fatalf("the journal holds %+v, %v; want the one line of %s", es, err, path)
	}
	if _, err := Blob(g.LedgerRoot, Sum([]byte(textC))); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the blob no line names: %v, want it gone", err)
	}
	want := []string{Sum([]byte(path)) + ".lock", "journal.lock", "prune.lock"}
	slices.Sort(want)
	if got := names(t, g.LedgerRoot, LocksDir); !slices.Equal(got, want) {
		t.Errorf("locks/ holds %v, want %v", got, want)
	}
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
		t.Fatalf("undo of the change a line left: %v", err)
	}
	if got := mustRead(t, path); got != textA {
		t.Errorf("undo left %q", got)
	}
}

// TestPruneKeepsEachContractsNewestChanges: of a contract whose file is there, the newest KeepChanges changes that
// stand stay however old, with the texts they name, so Undo still goes that many changes back, and no further.
func TestPruneKeepsEachContractsNewestChanges(t *testing.T) {
	g, path := fixture(t)
	if err := os.WriteFile(path, []byte(numbered(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	const n = KeepChanges + 5
	clock(t, time.Now().Add(-60*day))
	for i := 1; i <= n; i++ {
		write(t, g, path, numbered(i-1), numbered(i))
	}
	now = time.Now
	ageBlobs(t, g.LedgerRoot, 60*day)
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil || p.Lines != 5 || p.Blobs != 5 {
		t.Fatalf("pruned %+v, %v; want the 5 oldest changes and the 5 texts only they named", p, err)
	}
	for i := n - 1; i >= n-KeepChanges; i-- {
		if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
			t.Fatalf("undo to text %d: %v", i, err)
		}
		if got := mustRead(t, path); got != numbered(i) {
			t.Fatalf("undo left %q, want text %d", got, i)
		}
	}
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("an undo past the lines left: %v, want ErrNoChange", err)
	}
}

// TestPruneKeepsARevertWithWhatItUndid: a contract's lines from the first one inside the retention on all stay, in
// the journal's order, so a revert a clock set back dated older is not pruned while the change it undid stays, which
// would show that change standing again.
func TestPruneKeepsARevertWithWhatItUndid(t *testing.T) {
	g, path := fixture(t)
	clock(t, time.Now().Add(-10*day))
	e := write(t, g, path, textA, textB)
	clock(t, time.Now().Add(-60*day)) // the clock was set back
	if _, err := Undo(context.Background(), g, path, RevertOptions{}); err != nil {
		t.Fatal(err)
	}
	now = time.Now
	if err := os.Remove(path); err != nil { // a file that is gone keeps no newest lines
		t.Fatal(err)
	}
	if p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil || p != (Pruned{}) {
		t.Fatalf("pruned %+v, %v; want nothing", p, err)
	}
	hist, err := History(g.LedgerRoot, path)
	if err != nil || len(hist) != 2 || hist[1].ID != e.ID || hist[1].UndoneBy != hist[0].ID {
		t.Errorf("history %+v, %v; want the change, undone by the revert", hist, err)
	}
}

// TestPruneKeepsACreationWhileItsFileIsThere: the line that created a contract stays while its file is there, however
// many changes followed it, so the Rules page still offers a contract made here that no run ran yet.
func TestPruneKeepsACreationWhileItsFileIsThere(t *testing.T) {
	g, existing := fixture(t)
	path := filepath.Join(filepath.Dir(existing), "new.yaml")
	clock(t, time.Now().Add(-60*day))
	c, err := Create(context.Background(), g, path, []byte(numbered(0)), Change{})
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= KeepChanges+2; i++ {
		write(t, g, path, numbered(i-1), numbered(i))
	}
	now = time.Now
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil || p.Lines != 2 {
		t.Fatalf("pruned %+v, %v; want the two oldest changes", p, err)
	}
	hist, err := History(g.LedgerRoot, path)
	if err != nil || len(hist) != KeepChanges+1 || hist[len(hist)-1].ID != c.ID {
		t.Errorf("history of %d lines, %v; want the newest %d changes and the creation", len(hist), err, KeepChanges)
	}
}

// TestPruneLiveLinesGoWithTheirChange: a live line stays or goes with the change it records outcomes of, however late
// it was appended; one whose change is in no line goes once older than the retention.
func TestPruneLiveLinesGoWithTheirChange(t *testing.T) {
	g, path := fixture(t)
	ctx := context.Background()
	gone := filepath.Join(filepath.Dir(path), "gone.yaml")
	if err := os.WriteFile(gone, []byte(textA), 0o600); err != nil {
		t.Fatal(err)
	}
	live := []Live{{Run: "r-x", Block: "exec:git", OK: true}}
	clock(t, time.Now().Add(-60*day))
	old := write(t, g, gone, textA, textB)
	kept := write(t, g, path, textA, textB)
	if err := AppendLive(ctx, g.LedgerRoot, "rc-of-no-line", live); err != nil {
		t.Fatal(err)
	}
	now = time.Now
	for _, of := range []string{old.ID, kept.ID, "rc-of-no-line-yet"} {
		if err := AppendLive(ctx, g.LedgerRoot, of, live); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(gone); err != nil {
		t.Fatal(err)
	}
	p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil || p.Lines != 3 {
		t.Fatalf("pruned %+v, %v; want the gone contract's change, its live line and the old live line of no change", p, err)
	}
	es, err := ReadJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range es {
		got = append(got, e.Op+" "+e.Of)
	}
	if want := []string{"change ", "live " + kept.ID, "live rc-of-no-line-yet"}; !slices.Equal(got, want) || es[0].ID != kept.ID {
		t.Errorf("the journal holds %q, want %q", got, want)
	}
}

// TestPruneLeavesALockAWriteHolds: a contract's lock file is removed only while Prune holds its flock, so one a write
// holds stays, and so does the lock of a contract with a line left; journal.lock and prune.lock are no contract's and
// stay.
func TestPruneLeavesALockAWriteHolds(t *testing.T) {
	g, path := fixture(t)
	write(t, g, path, textA, textB)
	j, err := openJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	held, free := Sum([]byte("/held.yaml"))+".lock", Sum([]byte("/free.yaml"))+".lock"
	unlock, err := j.lock(context.Background(), held)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	release, err := j.lock(context.Background(), free)
	if err != nil {
		t.Fatal(err)
	}
	release()
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil || p != (Pruned{Locks: 1}) {
		t.Fatalf("pruned %+v, %v; want the free lock file only", p, err)
	}
	want := []string{held, "journal.lock", Sum([]byte(path)) + ".lock", "prune.lock"}
	slices.Sort(want)
	if got := names(t, g.LedgerRoot, LocksDir); !slices.Equal(got, want) {
		t.Errorf("locks/ holds %v, want %v", got, want)
	}
}

// TestPruneWaitsForAWriteBetweenItsBlobsAndItsLine: a write's blobs are named by no line until it appends its own,
// and it holds prune.lock shared from its first blob to that line, so a Prune meanwhile waits rather than take them
// for blobs no line names, and the change can still be undone.
func TestPruneWaitsForAWriteBetweenItsBlobsAndItsLine(t *testing.T) {
	g, path := fixture(t)
	var p Pruned
	perr := errors.New("no Prune ran")
	setHook(t, func(s string) error {
		if s != "journal" {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		// An edge an hour ahead: every blob is older than the retention, and only the lock keeps the write's.
		p, perr = Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(time.Hour)})
		return nil
	})
	e, err := Replace(context.Background(), g, path, Sum([]byte(textA)), []byte(textB), Change{})
	if err != nil {
		t.Fatal(err)
	}
	hook = nil
	if perr == nil || !strings.Contains(perr.Error(), "being written") || p != (Pruned{}) {
		t.Fatalf("a Prune during the write: %+v, %v; want it to wait for the write, removing nothing", p, perr)
	}
	if _, err := Revert(context.Background(), g, e.ID, RevertOptions{}); err != nil {
		t.Fatalf("revert of the change written during the Prune: %v", err)
	}
	if got := mustRead(t, path); got != textA {
		t.Errorf("revert left %q", got)
	}
}

// TestLockAfterItsFileWasRemoved: Prune removes a contract's lock file under its flock. A writer that opened the file
// before it went and locks it after would hold a lock on a file no later writer opens, so it locks the name again:
// the lock it ends with is the file at the name, which another writer cannot take meanwhile.
func TestLockAfterItsFileWasRemoved(t *testing.T) {
	g, _ := fixture(t)
	j, err := openJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer j.close()
	name := Sum([]byte("/a.yaml")) + ".lock"
	file := filepath.Join(g.LedgerRoot, JournalDirName, LocksDir, name)
	removed := false
	setHook(t, func(s string) error {
		if s == "lock" && !removed {
			removed = true
			return os.Remove(file) // Prune, between this writer's open and its flock
		}
		return nil
	})
	unlock, err := j.lock(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	f, err := os.Open(file)
	if err != nil {
		t.Fatalf("no lock file at the name: %v", err)
	}
	defer func() { _ = f.Close() }()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Errorf("another writer's flock of the lock file: %v, want EWOULDBLOCK", err)
	}
}

// TestPruneDryRunChangesNothing: a dry run counts what a Prune removes and leaves every file as it was, making none.
func TestPruneDryRunChangesNothing(t *testing.T) {
	g, path := fixture(t)
	clock(t, time.Now().Add(-60*day))
	write(t, g, path, textA, textB)
	write(t, g, path, textB, textC)
	now = time.Now
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ageBlobs(t, g.LedgerRoot, 60*day)
	before := tree(t, g.LedgerRoot)
	o := PruneOptions{Before: time.Now().Add(-30 * day), DryRun: true}
	dry, err := Prune(context.Background(), g.LedgerRoot, o)
	if err != nil {
		t.Fatal(err)
	}
	if after := tree(t, g.LedgerRoot); !maps.Equal(after, before) {
		t.Errorf("a dry run changed the journal: %v, was %v", after, before)
	}
	o.DryRun = false
	done, err := Prune(context.Background(), g.LedgerRoot, o)
	if want := (Pruned{Lines: 2, Blobs: 3, Locks: 1}); err != nil || dry != want || done != want {
		t.Errorf("a dry run %+v, then a Prune %+v, %v; want both %+v", dry, done, err, want)
	}
}

// TestPruneTornAndForeignLines: a torn line (a crash mid-append) goes; a line of another journal version leaves the
// whole journal as it is, since it may name blobs and lines in ways this version cannot see.
func TestPruneTornAndForeignLines(t *testing.T) {
	g, path := fixture(t)
	ctx := context.Background()
	jf := filepath.Join(g.LedgerRoot, JournalDirName, JournalFile)
	appendLine := func(s string) {
		t.Helper()
		f, err := os.OpenFile(jf, os.O_WRONLY|os.O_APPEND, 0)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString(s); err != nil {
			t.Fatal(err)
		}
		if err := f.Close(); err != nil {
			t.Fatal(err)
		}
	}
	write(t, g, path, textA, textB)
	appendLine(`{"v":1,"id":"rc-torn","op":"chan`)
	write(t, g, path, textB, textC) // starts on a line of its own
	if p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil || p != (Pruned{Lines: 1}) {
		t.Fatalf("pruned %+v, %v; want the torn line", p, err)
	}
	if strings.Contains(mustRead(t, jf), "rc-torn") {
		t.Error("the torn line is still there")
	}
	if es, err := ReadJournal(g.LedgerRoot); err != nil || len(es) != 2 {
		t.Fatalf("the journal holds %d lines, %v; want both changes", len(es), err)
	}

	appendLine(`{"v":2,"id":"rc-newer","op":"change","at":"2020-01-01T00:00:00Z"}` + "\n")
	if err := os.Remove(path); err != nil { // every line would go, but for the newer one
		t.Fatal(err)
	}
	before := tree(t, g.LedgerRoot)
	_, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(time.Hour)})
	if err == nil || !strings.Contains(err.Error(), "left whole") {
		t.Errorf("a Prune of a journal holding a newer line: %v, want it refused", err)
	}
	if after := tree(t, g.LedgerRoot); !maps.Equal(after, before) {
		t.Errorf("the refused Prune changed the journal: %v, was %v", after, before)
	}
}

// TestPruneOtherOwnersJournal: a journal another user owns (a root tego gc over the invoking user's ledger root) is
// ErrOtherOwner and left as it is.
func TestPruneOtherOwnersJournal(t *testing.T) {
	g, path := fixture(t)
	write(t, g, path, textA, textB)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := tree(t, g.LedgerRoot)
	uid := os.Geteuid()
	geteuid = func() int { return uid + 4242 }
	t.Cleanup(func() { geteuid = os.Geteuid })
	if _, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(time.Hour)}); !errors.Is(err, ErrOtherOwner) {
		t.Errorf("Prune: %v, want ErrOtherOwner", err)
	}
	if after := tree(t, g.LedgerRoot); !maps.Equal(after, before) {
		t.Errorf("Prune changed another user's journal: %v, was %v", after, before)
	}
}

// TestPruneNoJournal: a ledger root where nothing was ever changed is nothing to do, and Prune makes no journal.
func TestPruneNoJournal(t *testing.T) {
	g, _ := fixture(t)
	if p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now()}); err != nil || p != (Pruned{}) {
		t.Fatalf("Prune: %+v, %v", p, err)
	}
	if _, err := os.Lstat(filepath.Join(g.LedgerRoot, JournalDirName)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Prune made the journal: %v", err)
	}
}
