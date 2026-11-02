// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// TestVerifyRunBounds: a run over the dashboard's line bound, a bad run id and an unknown or missing anchor are
// "not checked", each saying why, before any ledger is read; none is ever "verified".
func TestVerifyRunBounds(t *testing.T) {
	root := t.TempDir()
	const id = "r-3f9c2a1b-0dllq06ts7400-b0undx"
	if err := os.MkdirAll(filepath.Join(root, id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, id, "events.jsonl"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	anchor := filepath.Join(root, "chain.log")
	if err := os.WriteFile(anchor, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name, id, anchor string
		run              *Run
		want             string
	}{
		{"too long", id, anchor, &Run{ID: id, Ended: true, Cut: true}, "too long for the dashboard"},
		{"live", id, anchor, &Run{ID: id, Live: true}, "still being written"},
		{"bad id", "../etc", anchor, nil, "not a run id"},
		{"no anchor", id, "", &Run{ID: id, Ended: true}, "not known"},
		{"missing anchor", id, filepath.Join(root, "nope", "chain.log"), &Run{ID: id, Ended: true}, "not readable here"},
	} {
		got := VerifyRun(context.Background(), root, c.id, c.anchor, c.run)
		if got.State != ChainUnchecked || !strings.Contains(got.Reason, c.want) {
			t.Errorf("%s: %+v, want unchecked with %q", c.name, got, c.want)
		}
	}
}

// loadedRun is LoadRun's summary of run id, failing the test when there is none.
func loadedRun(t *testing.T, root, id string) *Run {
	t.Helper()
	r, err := LoadRun(root, id)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// rewriteAnchorLine applies edit to run id's line of the chain.log at anchor (without its "\n") and writes the result
// over it in place: the same file, the same size, with stamps (mtime, ctime) other than the file had. On a kernel
// without multigrain timestamps (before 6.13) they come from a coarse clock, and a write within the tick of the change
// before it, which the dashboard's view may have read, would keep them: the line is written again until they move.
// TestChainSeesAnUnstampedEditOnceTheViewIsOld and TestChainStaleVerdictRecheckedInBackground hold what the dashboard
// does with an edit that keeps them.
func rewriteAnchorLine(t *testing.T, anchor, id string, edit func(line []byte)) {
	t.Helper()
	b, err := os.ReadFile(anchor)
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(b), id+" ")
	if i < 0 {
		t.Fatalf("no line for %s in %s", id, b)
	}
	line := b[i : i+strings.IndexByte(string(b[i:]), '\n')]
	edit(line)
	before, err := os.Stat(anchor)
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(anchor, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }() // closed below; this covers a t.Fatal
	for try := 0; ; try++ {
		if _, err := f.WriteAt(line, int64(i)); err != nil {
			t.Fatal(err)
		}
		after, err := os.Stat(anchor)
		if err != nil || !os.SameFile(before, after) || after.Size() != before.Size() {
			t.Fatalf("test setup: chain.log is not the same file at the same size after the edit (%v)", err)
		}
		if idOf(after) != idOf(before) {
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
			return
		}
		if try == 100 {
			t.Fatal("test setup: chain.log's stamps never moved")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// flipLastHexDigit changes the last character of an anchor line's head.
func flipLastHexDigit(line []byte) {
	if line[len(line)-1] == '0' {
		line[len(line)-1] = '1'
	} else {
		line[len(line)-1] = '0'
	}
}

// TestChainSeesTheRunsAnchorLineEditedInPlace: the run's line in chain.log rewritten in place at the same length (the
// same file, the same size, so no key the cache held moved) is seen on the next look, broken, as `tego events <run>
// --verify` says at once; the kept verdict used to stand for its ten minutes. The other run's verdict, whose line is
// as it was, stands without a check. The look that finds the new verdict moves the store's revision, so pages open on
// "verified" redraw: an edit of chain.log moves none of its own.
func TestChainSeesTheRunsAnchorLineEditedInPlace(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id, other := "r-3f9c2a1b-0dllq06ts7410-c4chex", "r-3f9c2a1b-0dllq06ts7411-c4chex"
	chainRun(t, root, anchor, id)
	chainRun(t, root, anchor, other)
	r, o := loadedRun(t, root, id), loadedRun(t, root, other)
	for _, run := range []*Run{r, o} {
		if c := VerifyRun(context.Background(), root, run.ID, anchor, run); !c.Verified() {
			t.Fatalf("%s before the edit: %+v", run.ID, c)
		}
	}
	rewriteAnchorLine(t, anchor, id, flipLastHexDigit)
	n, rev := chainVerifies.Load(), Open(root).Rev()
	if c := VerifyRun(context.Background(), root, other, anchor, o); !c.Verified() {
		t.Fatalf("the run whose line is as it was: %+v", c)
	}
	if d := chainVerifies.Load() - n; d != 0 {
		t.Fatalf("the run whose line is as it was was checked again (%d checks)", d)
	}
	if Open(root).Rev() != rev {
		t.Fatal("the revision moved for a run whose verdict stands")
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() || c.AtLine || !strings.Contains(c.Reason, "anchored head") {
		t.Fatalf("after its anchor line was rewritten in place: %+v, want broken after the last line on the anchored head", c)
	}
	if Open(root).Rev() == rev {
		t.Fatal("the look found another verdict but the revision did not move, so open pages keep showing verified")
	}
	if lc := VerifySnapshot(context.Background(), mustSnapshot(t, root), anchor); lc.Broken == nil || lc.Broken.Run != id {
		t.Fatalf("the overview after the edit: %+v, want %s broken", lc, id)
	}
}

// TestChainKeepsItsVerdictThroughOtherRunsEnds: another run's end appends its line to chain.log, which changes the
// file; the kept verdict stands without a check, and the file is read once for the change, not once per look.
func TestChainKeepsItsVerdictThroughOtherRunsEnds(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7412-c4chex"
	chainRun(t, root, anchor, id)
	r := loadedRun(t, root, id)
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain: %+v", c)
	}
	chainRun(t, root, anchor, "r-3f9c2a1b-0dllq06ts7413-c4chex")
	n, reads, rev := chainVerifies.Load(), anchorReads.Load(), Open(root).Rev()
	for range 3 {
		if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
			t.Fatalf("after another run's end: %+v", c)
		}
	}
	if d := chainVerifies.Load() - n; d != 0 {
		t.Fatalf("another run's end made %d checks of this one", d)
	}
	if Open(root).Rev() != rev {
		t.Fatal("another run's end moved the revision through this run's verdict, which stands")
	}
	if d := anchorReads.Load() - reads; d != 1 {
		t.Fatalf("chain.log was read %d times for one change, want 1", d)
	}
}

// TestChainSeesAnAnchorChangeThatChangesTheRunsAnswer: whatever changes what chain.log answers for the run, not only
// its own line, is seen on the next look, as the CLI sees it: a second head appended for it, another run's line made
// malformed in place (Head then fails for every run), the run's line renamed in place to another run (its line gone).
func TestChainSeesAnAnchorChangeThatChangesTheRunsAnswer(t *testing.T) {
	id, other := "r-3f9c2a1b-0dllq06ts7414-c4chex", "r-3f9c2a1b-0dllq06ts7415-c4chex"
	for _, tc := range []struct {
		name   string
		change func(t *testing.T, anchor string)
		reason string
	}{
		{"a second head appended", func(t *testing.T, anchor string) {
			f, err := os.OpenFile(anchor, os.O_WRONLY|os.O_APPEND, 0)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteString(id + " " + strings.Repeat("9", 64) + "\n"); err != nil {
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}, "two heads"},
		{"another run's line made malformed in place", func(t *testing.T, anchor string) {
			rewriteAnchorLine(t, anchor, other, func(line []byte) { line[len(other)] = 'x' })
		}, "anchor line"},
		{"the run's line renamed in place", func(t *testing.T, anchor string) {
			rewriteAnchorLine(t, anchor, id, func(line []byte) { line[len(id)-1] = 'y' })
		}, "no chain anchor"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
			chainRun(t, root, anchor, id)
			chainRun(t, root, anchor, other)
			r := loadedRun(t, root, id)
			if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
				t.Fatalf("chain before the change: %+v", c)
			}
			tc.change(t, anchor)
			if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() || !strings.Contains(c.Reason, tc.reason) {
				t.Fatalf("after the change: %+v, want broken on %q", c, tc.reason)
			}
		})
	}
}

// unstampedEdit leaves the dashboard's view of the chain.log at anchor as a write the file's stamps do not show leaves
// it (a write within one tick of a coarse clock, or through a shared mapping whose page is already dirty): the answers
// it read before the write, under the stamps the file has after it.
func unstampedEdit(t *testing.T, anchor string) {
	t.Helper()
	stamp, known := anchorStamp(anchor)
	anchorMu.Lock()
	defer anchorMu.Unlock()
	v := anchorViews[anchor]
	if v == nil || !v.known || !known {
		t.Fatalf("test setup: no view of %s, or no file there", anchor)
	}
	v.stamp = stamp
}

// ageAnchorView makes the dashboard's view of the chain.log at anchor older than chainTTL.
func ageAnchorView(t *testing.T, anchor string) {
	t.Helper()
	anchorMu.Lock()
	defer anchorMu.Unlock()
	v := anchorViews[anchor]
	if v == nil {
		t.Fatalf("test setup: no view of %s", anchor)
	}
	v.read = time.Now().Add(-2 * chainTTL)
}

// expireChain makes the kept chain verdicts of the run directory dir older than chainTTL.
func expireChain(dir string) {
	chainMu.Lock()
	defer chainMu.Unlock()
	for k, e := range chainVerdicts {
		if k.dir == dir {
			e.at = time.Now().Add(-2 * chainTTL)
			chainVerdicts[k] = e
		}
	}
}

// TestChainSeesAnUnstampedEditOnceTheViewIsOld: an edit of chain.log its stamps do not show is not seen while the
// dashboard's view of the file is young, but once the view is chainTTL old the next look reads the file again, finds
// the run's answer changed, and checks the run before the page answers, though the kept verdict's own time has not
// run out. The view used to stand for as long as the stamps did, which for such an edit is for good.
func TestChainSeesAnUnstampedEditOnceTheViewIsOld(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id := "r-3f9c2a1b-0dllq06ts7416-c4chex"
	chainRun(t, root, anchor, id)
	r := loadedRun(t, root, id)
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain: %+v", c)
	}
	rewriteAnchorLine(t, anchor, id, flipLastHexDigit)
	unstampedEdit(t, anchor)
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Verified() {
		t.Fatalf("test setup: a look saw the edit its view was made not to show: %+v", c)
	}
	ageAnchorView(t, anchor)
	n := chainVerifies.Load()
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() || c.AtLine || !strings.Contains(c.Reason, "anchored head") {
		t.Fatalf("once the view is %v old: %+v, want broken after the last line on the anchored head", chainTTL, c)
	}
	if d := chainVerifies.Load() - n; d != 1 {
		t.Fatalf("%d checks, want the one made before the page answered", d)
	}
}

// TestChainBrokenAfterTheLastLineNamesIt: a chain that held through every line and broke after the last (here a
// second head for the run in chain.log) names that last line, #1 of a two-line run, not the count of its lines: #2 is
// a line the run does not have, and the pages said "after #2". A broken chain with no line to walk (an anchored run
// whose ledger is gone) names none.
func TestChainBrokenAfterTheLastLineNamesIt(t *testing.T) {
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id, gone := "r-3f9c2a1b-0dllq06ts7418-c4chex", "r-3f9c2a1b-0dllq06ts7419-c4chex"
	chainRun(t, root, anchor, id)
	chainRun(t, root, anchor, gone)
	r, g := loadedRun(t, root, id), loadedRun(t, root, gone)
	f, err := os.OpenFile(anchor, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(id + " " + strings.Repeat("9", 64) + "\n"); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if c := VerifyRun(context.Background(), root, id, anchor, r); !c.Broken() || c.AtLine || c.Lines != 2 || c.Line != 1 ||
		!strings.Contains(c.Reason, "two heads") {
		t.Fatalf("a second head for a two-line run: %+v, want broken after #1, its last line", c)
	}
	if err := os.Remove(filepath.Join(root, gone, "events.jsonl")); err != nil {
		t.Fatal(err)
	}
	if c := VerifyRun(context.Background(), root, gone, anchor, g); !c.Broken() || c.AtLine || c.Lines != 0 || c.Line != 0 {
		t.Fatalf("an anchored run whose ledger is gone: %+v, want broken with no line read", c)
	}
}

// TestChainExpiredVerdictsShareOneRead: the overview's verdicts, which PrewarmChain lands together, run out together
// ten minutes on, and so does the reading of chain.log they rest on. The overview's look then reads chain.log once,
// for every run; the checks it starts in the background, one per expired verdict, and the run pages opened while they
// run read it no more. Each check used to read the whole file for itself, one after another under the views' lock:
// with this 9.7 MB chain.log (100,000 other runs, as a long-used ~/.tego holds) the overview's checks read it 20
// times, and a run page opened meanwhile waited over a second for them.
func TestChainExpiredVerdictsShareOneRead(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	others := 100_000
	if testing.Short() {
		others = 1_000 // the same reads, from a smaller file
	}
	var b strings.Builder
	for i := range others {
		fmt.Fprintf(&b, "r-3f9c2a1b-0dllq%08d-c4chex %064x\n", i, i)
	}
	if err := os.WriteFile(anchor, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	ids := make([]string, MaxChainRuns)
	for i := range ids {
		ids[i] = fmt.Sprintf("r-3f9c2a1b-0dllq06ts75%02d-c4chex", i)
		chainRun(t, root, anchor, ids[i])
	}
	snap := mustSnapshot(t, root)
	reads := anchorReads.Load()
	<-PrewarmChain(ctx, snap, anchor)
	if d := anchorReads.Load() - reads; d != 1 {
		t.Fatalf("the start-up check of %d runs read chain.log %d times, want once", len(ids), d)
	}
	for _, id := range ids {
		expireChain(filepath.Join(root, id))
	}
	ageAnchorView(t, anchor)
	reads, n := anchorReads.Load(), chainVerifies.Load()
	start := time.Now()
	if lc := VerifySnapshot(ctx, snap, anchor); lc.Checked != len(ids) || lc.Verifying != 0 || lc.Broken != nil {
		t.Fatalf("the overview: %+v, want the %d kept verdicts shown while they are checked again", lc, len(ids))
	}
	over := time.Since(start)
	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		worst time.Duration
	)
	for _, id := range ids[:5] {
		wg.Add(1)
		go func() {
			defer wg.Done()
			start := time.Now()
			c := VerifyRun(ctx, root, id, anchor, snap.Find(id))
			mu.Lock()
			worst = max(worst, time.Since(start))
			mu.Unlock()
			if !c.Verified() {
				t.Errorf("%s, its page opened while the checks run: %+v", id, c)
			}
		}()
	}
	wg.Wait()
	for _, id := range ids {
		waitNoFlight(t, filepath.Join(root, id))
	}
	t.Logf("chain.log of %d lines: the overview took %v, the slowest run page opened meanwhile %v", others+len(ids),
		over, worst)
	if d := chainVerifies.Load() - n; d != int64(len(ids)) {
		t.Fatalf("%d checks, want one for each of the %d expired verdicts", d, len(ids))
	}
	if d := anchorReads.Load() - reads; d != 1 {
		t.Fatalf("the overview, its %d checks and 5 run pages read chain.log %d times, want once", len(ids), d)
	}
}

// holdAnchorReads makes every read of the chain.log at anchor wait until the returned release is called, counting
// them in n; started is closed once the first has begun.
func holdAnchorReads(t *testing.T, anchor string) (started <-chan struct{}, release func(), n *atomic.Int64) {
	t.Helper()
	begun, free := make(chan struct{}), make(chan struct{})
	var once, freed sync.Once
	n = new(atomic.Int64)
	anchorMu.Lock()
	anchorHeadsOf = func(path string, runs []string) (map[string]ledger.AnchorHead, os.FileInfo) {
		if path == anchor {
			n.Add(1)
			once.Do(func() { close(begun) })
			<-free
		}
		return ledger.AnchorHeads(path, runs)
	}
	anchorMu.Unlock()
	release = func() { freed.Do(func() { close(free) }) }
	t.Cleanup(func() {
		release()
		anchorMu.Lock()
		anchorHeadsOf = ledger.AnchorHeads
		anchorMu.Unlock()
	})
	return begun, release, n
}

// TestChainAnchorReadHoldsNoLock: chain.log is read without the views' lock. While one run page has it read (its run
// is one the view did not answer for, on a chain.log that may be megabytes), a look the view already answers for gets
// its answer at once, and a look that needs the same read waits for it and reads nothing itself. The read used to
// hold the lock, and every look, the overview's included, waited for it.
func TestChainAnchorReadHoldsNoLock(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	root, anchor := filepath.Join(dir, "runs"), filepath.Join(dir, "chain.log")
	id, other := "r-3f9c2a1b-0dllq06ts7420-c4chex", "r-3f9c2a1b-0dllq06ts7421-c4chex"
	chainRun(t, root, anchor, id)
	chainRun(t, root, anchor, other)
	r, o := loadedRun(t, root, id), loadedRun(t, root, other)
	if c := VerifyRun(ctx, root, id, anchor, r); !c.Verified() {
		t.Fatalf("chain: %+v", c)
	}
	started, release, n := holdAnchorReads(t, anchor)
	page := make(chan Chain, 1)
	go func() { page <- VerifyRun(ctx, root, other, anchor, o) }()
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("test setup: the run page for a run the view does not answer for never read chain.log")
	}
	look := make(chan Chain, 1)
	go func() { look <- VerifyRun(ctx, root, id, anchor, r) }()
	select {
	case c := <-look:
		if !c.Verified() {
			t.Fatalf("the look the view answers for: %+v", c)
		}
	case <-time.After(10 * time.Second):
		release()
		t.Fatal("a look the view answers for waited for another page's read of chain.log")
	}
	shared := make(chan ledger.AnchorHead, 1)
	go func() { shared <- anchorHeadsNow(anchor, other)[0] }()
	select {
	case h := <-shared:
		t.Fatalf("a look that needs the read in flight answered before it ended: %+v", h)
	case <-time.After(50 * time.Millisecond):
	}
	release()
	if c := <-page; !c.Verified() {
		t.Fatalf("the run page that had chain.log read: %+v", c)
	}
	if h := <-shared; !h.OK || h.Err != nil {
		t.Fatalf("the look that waited for the read: %+v", h)
	}
	if got := n.Load(); got != 1 {
		t.Fatalf("chain.log was read %d times, want once, shared", got)
	}
}

// mustSnapshot is Load of root, failing the test on an error.
func mustSnapshot(t *testing.T, root string) *Snapshot {
	t.Helper()
	s, err := Load(root)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
