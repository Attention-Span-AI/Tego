// SPDX-License-Identifier: Apache-2.0

package rulefile

import (
	"context"
	crand "crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/testutil/ledgertest"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// mintRun is the id of a run minted at `at`, as a launcher mints one.
func mintRun(t *testing.T, at time.Time) string {
	t.Helper()
	id, err := identity.NewRunID([32]byte{}, at, crand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return string(id)
}

// runAt makes in root the directory of a run minted at `at` and returns its id: its name says when it started.
func runAt(t *testing.T, root string, at time.Time) string {
	t.Helper()
	id := mintRun(t, at)
	if err := os.Mkdir(filepath.Join(root, id), 0o700); err != nil {
		t.Fatal(err)
	}
	return id
}

// namedRunAt makes in root the directory of the run name whose run_start line says it started at `at`, as the
// dashboard's tests name runs: a name that is no minted run id, so only that line says when it started.
func namedRunAt(t *testing.T, root, name string, at time.Time) {
	t.Helper()
	e := ledgertest.Event(t, record.KindRunStart, record.RunStartPayload{Tier: "landlock", Capture: "off",
		ContractHash: strings.Repeat("0", 64), Command: []string{"sh"}, Cwd: "/", Kernel: "6", StopGrace: "1s",
		RecordMinor: record.Minor}, func(e *record.Event) { e.Run, e.TS = name, at.UTC() })
	l, err := e.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ledger.EventsFile), append(l, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
}

// writeIDs is the ids of root's journal lines that wrote a contract, oldest first.
func writeIDs(t *testing.T, root string) []string {
	t.Helper()
	es, err := ReadJournal(root)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range es {
		if isWrite(e.Op) {
			out = append(out, e.ID)
		}
	}
	return out
}

// appendRaw appends s to root's journal as a writer of another tego, or a hand, would.
func appendRaw(t *testing.T, root, s string) {
	t.Helper()
	f, err := os.OpenFile(filepath.Join(root, JournalDirName, JournalFile), os.O_WRONLY|os.O_APPEND, 0)
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

// TestPruneKeepsWhatARunStillHereReads: a run still in the ledger root lists the changes of its rules file made since
// it started (pending for its next run) and Apply now places them, so no line written after the oldest such run
// started goes, however old; once the run is gone, or counts as gone (Gone, a dry run's sweep), they age out as any
// line does. A run starts at its run_start line's time, as the readers read it, or at its id's mint time when that is
// earlier or no line reads.
func TestPruneKeepsWhatARunStillHereReads(t *testing.T) {
	for _, c := range []struct {
		name string
		make func(t *testing.T, root string, started time.Time) string
	}{
		{"a minted id", func(t *testing.T, root string, started time.Time) string { return runAt(t, root, started) }},
		{"a name that is no minted id", func(t *testing.T, root string, started time.Time) string {
			namedRunAt(t, root, "r-aaaa-0001-rules", started)
			return "r-aaaa-0001-rules"
		}},
		{"an id minted after its run_start line's time", func(t *testing.T, root string, started time.Time) string {
			id := mintRun(t, started.Add(10*day)) // the clock went back between the mint and run_start
			namedRunAt(t, root, id, started)
			return id
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			g, path := fixture(t)
			clock(t, time.Now().Add(-60*day))
			write(t, g, path, textA, textB)
			run := c.make(t, g.LedgerRoot, time.Now().Add(-45*day))
			clock(t, time.Now().Add(-40*day))
			since := write(t, g, path, textB, textC)
			now = time.Now
			if err := os.Remove(path); err != nil { // a file that is gone keeps no newest changes
				t.Fatal(err)
			}
			o := PruneOptions{Before: time.Now().Add(-30 * day)}
			if p, err := Prune(ctx, g.LedgerRoot, o); err != nil || p.Lines != 1 {
				t.Fatalf("pruned %+v, %v; want the change made before the run started", p, err)
			}
			if got := writeIDs(t, g.LedgerRoot); !slices.Equal(got, []string{since.ID}) {
				t.Fatalf("the journal holds %v, want the change made since the run started", got)
			}
			o.Gone, o.DryRun = []string{run}, true
			if p, err := Prune(ctx, g.LedgerRoot, o); err != nil || p.Lines != 1 {
				t.Errorf("a dry run with the run gone: %+v, %v; want the change since it started counted", p, err)
			}
			if err := os.RemoveAll(filepath.Join(g.LedgerRoot, run)); err != nil {
				t.Fatal(err)
			}
			o.Gone, o.DryRun = nil, false
			if p, err := Prune(ctx, g.LedgerRoot, o); err != nil || p.Lines != 1 || len(writeIDs(t, g.LedgerRoot)) != 0 {
				t.Errorf("the run gone: pruned %+v, %v; want the change since it started too", p, err)
			}
		})
	}
}

// TestPruneKeepsALineThatNamesARunStillHere: a change that placed a live block on a run still in the ledger root is
// one an Undo of another change reads (it holds the block: internal/control/rules heldByOther), so it stays, with
// every line after it, however old its date: here a clock set back dated it before the run started. So does a change a
// live line of which names the run, and one made from the run's line. A run no longer there keeps nothing.
func TestPruneKeepsALineThatNamesARunStillHere(t *testing.T) {
	for _, how := range []string{"live outcome", "live line", "made from", "run gone"} {
		t.Run(how, func(t *testing.T) {
			ctx := context.Background()
			g, path := fixture(t)
			run := runAt(t, g.LedgerRoot, time.Now().Add(-10*day))
			named := run
			if how == "run gone" {
				named = mintRun(t, time.Now().Add(-10*day)) // a run whose directory went
			}
			placed := []Live{{Run: named, Block: "exec:git", OK: true}}
			c := Change{Via: "dashboard"}
			switch how {
			case "live outcome", "run gone":
				c.Live = placed
			case "made from":
				c.Run, c.Line = named, 7
			}
			clock(t, time.Now().Add(-60*day)) // set back: the change reads older than the run
			e, err := Replace(ctx, g, path, Sum([]byte(textA)), []byte(textB), c)
			if err != nil {
				t.Fatal(err)
			}
			if how == "live line" {
				if err := AppendLive(ctx, g.LedgerRoot, e.ID, placed); err != nil {
					t.Fatal(err)
				}
			}
			clock(t, time.Now().Add(-59*day))
			later := write(t, g, path, textB, textC)
			now = time.Now
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
			want, ids := 0, []string{e.ID, later.ID}
			if how == "run gone" {
				want, ids = 2, nil
			}
			if err != nil || p.Lines != want {
				t.Fatalf("pruned %+v, %v; want %d lines", p, err, want)
			}
			if got := writeIDs(t, g.LedgerRoot); !slices.Equal(got, ids) {
				t.Errorf("the journal holds %v, want %v", got, ids)
			}
			if hist, err := History(g.LedgerRoot, path); how != "run gone" && (err != nil || len(hist) != 2 ||
				hist[1].ID != e.ID || hist[1].UndoneBy != "" || (how != "made from") != slices.Equal(hist[1].Live, placed)) {
				t.Errorf("history %+v, %v; want the change standing with what it placed", hist, err)
			}
		})
	}
}

// TestPruneKeepsWhatARevertLeftUndid: a revert that stays keeps the change it undid however old, and a revert of a
// revert (a redo) the change that one undid too: a revert's words say what it undid ("Undid: …", "Redid: …",
// rulesview.UndoWords), and a run's pending changes leave out a revert of a change made since the run started.
func TestPruneKeepsWhatARevertLeftUndid(t *testing.T) {
	ctx := context.Background()
	g, path := fixture(t)
	clock(t, time.Now().Add(-60*day))
	c := write(t, g, path, textA, textB)
	clock(t, time.Now().Add(-59*day))
	u, err := Undo(ctx, g, path, RevertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	clock(t, time.Now().Add(-5*day))
	r, err := Revert(ctx, g, u.ID, RevertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	now = time.Now
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil || p.Lines != 0 {
		t.Fatalf("pruned %+v, %v; want the redo inside the retention to keep the undo and the change", p, err)
	}
	hist, err := History(g.LedgerRoot, path)
	if err != nil || len(hist) != 3 || hist[0].ID != r.ID || hist[1].ID != u.ID || hist[1].UndoneBy != r.ID ||
		hist[2].ID != c.ID || hist[2].UndoneBy != "" {
		t.Errorf("history %+v, %v; want the redo, the undo it undid and the change standing again", hist, err)
	}
}

// TestPruneKeepsTheChangesUndoReaches: KeepChanges counts changes that stand, not lines. After 45 changes and 10
// Undos, all older than the retention, of a file that is there, the 20 newest changes that stand stay with every line
// after them, and Undo goes 20 changes back, no further.
func TestPruneKeepsTheChangesUndoReaches(t *testing.T) {
	ctx := context.Background()
	g, path := fixture(t)
	if err := os.WriteFile(path, []byte(numbered(0)), 0o600); err != nil {
		t.Fatal(err)
	}
	clock(t, time.Now().Add(-60*day))
	const n, undone = 45, 10
	for i := 1; i <= n; i++ {
		write(t, g, path, numbered(i-1), numbered(i))
	}
	for range undone {
		if _, err := Undo(ctx, g, path, RevertOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	now = time.Now
	if p, err := Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil ||
		p.Lines != n-undone-KeepChanges {
		t.Fatalf("pruned %+v, %v; want the %d oldest changes", p, err, n-undone-KeepChanges)
	}
	for i := n - undone - 1; i >= n-undone-KeepChanges; i-- {
		if _, err := Undo(ctx, g, path, RevertOptions{}); err != nil {
			t.Fatalf("undo to text %d: %v", i, err)
		}
		if got := mustRead(t, path); got != numbered(i) {
			t.Fatalf("undo left %q, want text %d", got, i)
		}
	}
	if _, err := Undo(ctx, g, path, RevertOptions{}); !errors.Is(err, ErrNoChange) {
		t.Errorf("an undo past the changes left: %v, want ErrNoChange", err)
	}
}

// TestPruneLooksAtTheFilesBeforeItLocks: whether a contract's file is there is looked at before Prune takes a lock,
// and waited for at most lookWait. A file on a stale mount, whose lstat never returns, counts as there, so its newest
// changes stay, and neither a write meanwhile nor the run start that prunes waits on it.
func TestPruneLooksAtTheFilesBeforeItLocks(t *testing.T) {
	g, path := fixture(t)
	clock(t, time.Now().Add(-60*day))
	write(t, g, path, textA, textB)
	write(t, g, path, textB, textC)
	now = time.Now
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	pl := filepath.Join(g.LedgerRoot, JournalDirName, LocksDir, pruneLock)
	release, returned := make(chan struct{}), make(chan struct{})
	free := make(chan bool, 1) // whether a write could take prune.lock while the file was looked at
	lstat = func(name string) (os.FileInfo, error) {
		if name != path {
			return os.Lstat(name)
		}
		defer close(returned)
		f, err := os.Open(pl)
		free <- err == nil && unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB) == nil
		if err == nil {
			_ = f.Close() // drops the flock
		}
		<-release // the stale mount answers once the test is over
		return os.Lstat(name)
	}
	prevWait := lookWait
	lookWait = 100 * time.Millisecond
	t.Cleanup(func() {
		close(release)
		<-returned
		lstat, lookWait = os.Lstat, prevWait
	})
	start := time.Now()
	p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)})
	if err != nil || p.Lines != 0 {
		t.Errorf("pruned %+v, %v; want a file that never answered to count as there, keeping its changes", p, err)
	}
	if took := time.Since(start); took > 2*time.Second {
		t.Errorf("Prune took %s waiting on a file that never answers", took)
	}
	select {
	case ok := <-free:
		if !ok {
			t.Error("prune.lock was held while the file was looked at; want it looked at before Prune locks")
		}
	case <-time.After(time.Second):
		t.Error("the file was never looked at")
	}
}

// TestPruneWaitsForACreationBetweenItsBlobAndItsLine: Create, as Replace does, holds prune.lock shared from its blob
// to its line, so a Prune meanwhile waits rather than take the new text for a blob no line names.
func TestPruneWaitsForACreationBetweenItsBlobAndItsLine(t *testing.T) {
	g, existing := fixture(t)
	path := filepath.Join(filepath.Dir(existing), "new.yaml")
	var p Pruned
	perr := errors.New("no Prune ran")
	setHook(t, func(s string) error {
		if s != "journal" {
			return nil
		}
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		// An edge an hour ahead: the new text is older than the retention, and only the lock keeps it.
		p, perr = Prune(ctx, g.LedgerRoot, PruneOptions{Before: time.Now().Add(time.Hour)})
		return nil
	})
	if _, err := Create(context.Background(), g, path, []byte(textB), Change{}); err != nil {
		t.Fatal(err)
	}
	hook = nil
	if perr == nil || !strings.Contains(perr.Error(), "being written") || p != (Pruned{}) {
		t.Fatalf("a Prune during the creation: %+v, %v; want it to wait for the creation, removing nothing", p, perr)
	}
	if _, err := Blob(g.LedgerRoot, Sum([]byte(textB))); err != nil {
		t.Errorf("the new contract's text: %v", err)
	}
}

// TestPruneRemovesWhatACrashedPruneLeft: a Prune that crashed between writing the new journal and renaming it over
// the old one left the new file, a copy of the journal; the next Prune removes it under prune.lock, and a dry run
// leaves it. A name no Prune writes stays.
func TestPruneRemovesWhatACrashedPruneLeft(t *testing.T) {
	g, path := fixture(t)
	write(t, g, path, textA, textB)
	dir := filepath.Join(g.LedgerRoot, JournalDirName)
	left, other := filepath.Join(dir, journalTemp+"0123456789abcdef"), filepath.Join(dir, journalTemp+"notaprunes")
	for _, f := range []string{left, other} {
		if err := os.WriteFile(f, []byte("a whole journal\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	o := PruneOptions{Before: time.Now().Add(-30 * day), DryRun: true}
	if _, err := Prune(context.Background(), g.LedgerRoot, o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(left); err != nil {
		t.Fatalf("a dry run removed what a crashed Prune left: %v", err)
	}
	o.DryRun = false
	if _, err := Prune(context.Background(), g.LedgerRoot, o); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(left); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("what a crashed Prune left: %v, want it gone", err)
	}
	if _, err := os.Lstat(other); err != nil {
		t.Errorf("a name no Prune writes: %v, want it left", err)
	}
}

// rawLine is e as a journal line of this version, dated `at`.
func rawLine(t *testing.T, e Entry, at time.Time) string {
	t.Helper()
	e.V, e.At = JournalVersion, at.UTC()
	b, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	return string(b) + "\n"
}

// TestPruneLeavesWholeAJournalWithTwoLinesOfOneID: no write of this tego makes two lines of one id, and a revert
// naming it would fold in ways a Prune could not keep as they read, so such a journal is left whole.
func TestPruneLeavesWholeAJournalWithTwoLinesOfOneID(t *testing.T) {
	g, path := fixture(t)
	e := write(t, g, path, textA, textB)
	appendRaw(t, g.LedgerRoot, rawLine(t, *e, time.Now().Add(-60*day)))
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	before := tree(t, g.LedgerRoot)
	_, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(time.Hour)})
	if err == nil || !strings.Contains(err.Error(), "left whole") {
		t.Errorf("Prune: %v, want the journal left whole", err)
	}
	if after := tree(t, g.LedgerRoot); !reflect.DeepEqual(after, before) {
		t.Errorf("the refused Prune changed the journal: %v, was %v", after, before)
	}
}

// TestPruneFollowsARevertAcrossContracts: a revert resolves its rules file's folder again, so a folder moved behind a
// symlink between a change and its Undo journals the revert under another path than the change. A revert left still
// keeps the change it undid, and a change left the revert that undid it, so the feed reads both as before: what the
// revert undid, and that the change is undone.
func TestPruneFollowsARevertAcrossContracts(t *testing.T) {
	for _, keeps := range []string{"the revert", "the change"} {
		t.Run(keeps+" stays", func(t *testing.T) {
			g, path := fixture(t)
			write(t, g, path, textA, textB) // a journal to append to, of a file that is there
			run := runAt(t, g.LedgerRoot, time.Now().Add(time.Hour))
			c := Entry{ID: "rc-c", Op: OpChange, Contract: "/gone/old/agent.yaml", OldSHA256: Sum([]byte(textA)),
				NewSHA256: Sum([]byte(textB))}
			r := Entry{ID: "rc-r", Op: OpRevert, Contract: "/gone/new/agent.yaml", Reverts: c.ID,
				OldSHA256: Sum([]byte(textB)), NewSHA256: Sum([]byte(textA))}
			rAt := time.Now().Add(-5 * day) // the revert inside the retention keeps the change
			if keeps == "the change" {
				c.Live = []Live{{Run: run, Block: "exec:git", OK: true}} // a run still here keeps the change
				rAt = time.Now().Add(-59 * day)
			}
			appendRaw(t, g.LedgerRoot, rawLine(t, c, time.Now().Add(-60*day))+rawLine(t, r, rAt))
			es0, err := ReadJournal(g.LedgerRoot)
			if err != nil {
				t.Fatal(err)
			}
			if p, err := Prune(context.Background(), g.LedgerRoot, PruneOptions{Before: time.Now().Add(-30 * day)}); err != nil ||
				p.Lines != 0 {
				t.Fatalf("pruned %+v, %v; want the change and its revert kept", p, err)
			}
			es1, err := ReadJournal(g.LedgerRoot)
			if err != nil {
				t.Fatal(err)
			}
			if f0, f1 := Fold(es0, nil), Fold(es1, nil); !reflect.DeepEqual(f1, f0) || f1[1].ID != c.ID || f1[1].UndoneBy != r.ID {
				t.Errorf("the feed reads %+v after the Prune, %+v before; want the change undone by the revert", f1, f0)
			}
		})
	}
}

// TestPruneLeavesEveryReaderAsItWas: over journals of random changes, Undos, redos, creations and live outcomes written
// at random times (the clock set back now and then), with runs in the ledger root started at random times, some files
// removed and a random retention edge, a Prune keeps every line the journal's readers read as they read it before:
//   - every line left folds as before: whether it is undone, its live outcomes and every field (Fold, History);
//   - a revert left keeps what it undid, and a redo what that undid (rulesview.UndoWords);
//   - every line written after a run still here started, and every line that names such a run, stays (a run's
//     pending changes and Apply now, the feed of its timeline, an Undo's lift: internal/control/rules heldByOther);
//   - every line written at or after the edge stays;
//   - the texts every line left names are there (Blob), and so is the lock file of every contract with a line left;
//   - of a contract whose file is there, the newest KeepChanges changes that stand and the newest creation stay.
func TestPruneLeavesEveryReaderAsItWas(t *testing.T) {
	seeds := uint64(10)
	if testing.Short() {
		seeds = 3
	}
	pruned := 0
	for seed := range seeds {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			pruned += pruneRandom(t, rand.New(rand.NewPCG(seed, 0x7e90))) // reproducible: a failure names its seed
		})
	}
	if pruned == 0 {
		t.Error("no draw pruned a line: the property was never put to the test")
	}
}

// pruneRandom writes one random journal, prunes it and checks what TestPruneLeavesEveryReaderAsItWas says; it returns
// how many lines went.
func pruneRandom(t *testing.T, rng *rand.Rand) int {
	t.Helper()
	ctx := context.Background()
	g, first := fixture(t)
	dir := filepath.Dir(first)
	paths := []string{first, filepath.Join(dir, "b.yaml"), filepath.Join(dir, "c.yaml")}
	for _, p := range paths[1:] {
		if err := os.WriteFile(p, []byte(textA), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := time.Now().Add(-90 * day)
	starts := map[string]time.Time{}
	var runs []string
	for range rng.IntN(4) {
		at := base.Add(time.Duration(rng.Int64N(int64(90 * day))))
		id := runAt(t, g.LedgerRoot, at)
		runs, starts[id] = append(runs, id), at
	}
	named := append(slices.Clone(runs), mintRun(t, base)) // and a run whose directory went
	at := base
	now = func() time.Time { return at }
	t.Cleanup(func() { now = time.Now })
	n := 0
	text := func(c int) string { n++; return fmt.Sprintf("%s# %d %d\n", textA, c, n) }
	live := func() []Live {
		var ls []Live
		for range rng.IntN(3) {
			ls = append(ls, Live{Run: named[rng.IntN(len(named))], Block: fmt.Sprintf("exec:p%d", rng.IntN(3)),
				OK: rng.IntN(4) > 0, Lift: rng.IntN(5) == 0})
		}
		return ls
	}
	created := 0
	for range 30 + rng.IntN(30) {
		switch rng.IntN(10) {
		case 0:
			at = at.Add(-time.Duration(rng.Int64N(int64(20 * day)))) // the clock set back
		case 1:
			at = at.Add(10*day + time.Duration(rng.Int64N(int64(20*day)))) // weeks with no change
		default:
			at = at.Add(time.Duration(rng.Int64N(int64(3 * day))))
		}
		c := 0
		if rng.IntN(2) == 0 {
			c = rng.IntN(len(paths))
		}
		cur, err := Read(paths[c], g)
		if err != nil {
			t.Fatal(err)
		}
		switch op := rng.IntN(10); {
		case op < 5:
			ch := Change{Via: "dashboard", Live: live()}
			if rng.IntN(4) == 0 {
				ch.Run = named[rng.IntN(len(named))]
			}
			if _, err := Replace(ctx, g, paths[c], cur.SHA256, []byte(text(c)), ch); err != nil {
				t.Fatal(err)
			}
		case op < 7:
			if _, err := Undo(ctx, g, paths[c], RevertOptions{}); err != nil && !errors.Is(err, ErrNoChange) {
				t.Fatal(err)
			}
		case op < 8: // the dashboard's Undo of an entry it shows as current: a change, or a revert (a redo)
			hist, err := History(g.LedgerRoot, cur.Path)
			if err != nil {
				t.Fatal(err)
			}
			var cs []string
			for _, h := range hist {
				if (h.Op == OpChange || h.Op == OpRevert) && h.NewSHA256 == cur.SHA256 {
					cs = append(cs, h.ID)
				}
			}
			if len(cs) > 0 {
				if _, err := Revert(ctx, g, cs[rng.IntN(len(cs))], RevertOptions{}); err != nil {
					t.Fatal(err)
				}
			}
		case op < 9:
			if ws := writeIDs(t, g.LedgerRoot); len(ws) > 0 {
				if err := AppendLive(ctx, g.LedgerRoot, ws[rng.IntN(len(ws))], live()); err != nil {
					t.Fatal(err)
				}
			}
		case created < 2:
			created++
			p := filepath.Join(dir, fmt.Sprintf("new%d.yaml", created))
			if _, err := Create(ctx, g, p, []byte(text(len(paths))), Change{Via: "dashboard"}); err != nil {
				t.Fatal(err)
			}
			paths = append(paths, p)
		}
	}
	now = time.Now
	there := map[string]bool{}
	for _, p := range paths {
		if rng.IntN(3) == 0 {
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
		} else {
			there[p] = true
		}
	}
	ageBlobs(t, g.LedgerRoot, 100*day)
	o := PruneOptions{Before: time.Now().Add(-time.Duration(rng.Int64N(int64(60 * day))))}
	if len(runs) > 0 && rng.IntN(3) == 0 {
		o.Gone = runs[:1]
	}
	es0, err := ReadJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	p, err := Prune(ctx, g.LedgerRoot, o)
	if err != nil {
		t.Fatal(err)
	}
	es1, err := ReadJournal(g.LedgerRoot)
	if err != nil {
		t.Fatal(err)
	}
	if p.Lines != len(es0)-len(es1) {
		t.Errorf("Prune says %d lines went, the journal lost %d", p.Lines, len(es0)-len(es1))
	}
	f0, f1 := Fold(es0, nil), Fold(es1, nil)
	by0, by1 := map[string]Entry{}, map[string]Entry{}
	for _, e := range f0 {
		by0[e.ID] = e
	}
	for _, e := range f1 {
		by1[e.ID] = e
	}
	need := func(id, why string) {
		if _, ok := by1[id]; !ok {
			t.Errorf("%s went, which %s", id, why)
		}
	}
	for _, e := range f1 {
		if !reflect.DeepEqual(e, by0[e.ID]) {
			t.Errorf("%s folds as %+v after the Prune, %+v before", e.ID, e, by0[e.ID])
		}
		if u, ok := by0[e.Reverts]; ok && e.Op == OpRevert {
			need(u.ID, "the revert "+e.ID+" left undid")
			if _, ok := by0[u.Reverts]; ok && u.Op == OpRevert {
				need(u.Reverts, "the redo "+e.ID+" left names")
			}
		}
		for _, s := range []string{e.OldSHA256, e.NewSHA256} {
			if _, err := Blob(g.LedgerRoot, s); s != "" && err != nil {
				t.Errorf("the text %s of %s, a line left: %v", s, e.ID, err)
			}
		}
		if _, err := os.Lstat(filepath.Join(g.LedgerRoot, JournalDirName, LocksDir, Sum([]byte(e.Contract))+".lock")); err != nil {
			t.Errorf("the lock file of %s, which has a line left: %v", e.Contract, err)
		}
	}
	for _, e := range f0 {
		if !e.At.Before(o.Before) {
			need(e.ID, "was written inside the retention")
		}
		for _, r := range runs {
			if slices.Contains(o.Gone, r) {
				continue
			}
			if e.At.After(starts[r]) {
				need(e.ID, "was written after "+r+", still here, started")
			}
			if e.Run == r || slices.ContainsFunc(e.Live, func(l Live) bool { return l.Run == r }) {
				need(e.ID, "names "+r+", still here")
			}
		}
	}
	for c := range there {
		kept, created := 0, false
		for _, e := range f0 { // newest first
			switch {
			case e.Contract != c:
			case e.Op == OpChange && e.UndoneBy == "" && kept < KeepChanges:
				kept++
				need(e.ID, "is one of the newest changes that stand of "+c+", whose file is there")
			case e.Op == OpCreate && !created:
				created = true
				need(e.ID, "is the newest creation of "+c+", whose file is there")
			}
		}
	}
	return p.Lines
}
