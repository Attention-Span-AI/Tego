// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// The chain check's bounds: a run with more lines than MaxLines (the run page's own bound), or an events file
// larger than maxVerifyBytes, is not checked here; the CLI checks it.
const (
	maxVerifyBytes = 64 << 20
	verifyTimeout  = 5 * time.Second
	// MaxChainRuns is how many of the newest ended runs the overview checks.
	MaxChainRuns = 20
)

// The states of a chain check.
const (
	ChainVerified  = "verified"
	ChainBroken    = "broken"
	ChainUnchecked = "unchecked"
)

// Chain is one run's chain check, as the dashboard shows it.
type Chain struct {
	Run   string
	State string // ChainVerified, ChainBroken or ChainUnchecked
	// Lines is how many lines the chain held through: all of them when verified, those before the break when broken.
	Lines uint64
	// Line is where a broken chain broke, as a seq (the timeline's #N, the CLI's "line N"). With AtLine it is the line
	// the walk stopped on, whose own bytes, link or schema fail. Without it the chain held through every line and broke
	// after the last (an anchor that disagrees or is missing, bytes after run_end), and Line is that last line, #Lines-1;
	// with Lines 0 no line was read (the ledger gone, replaced or empty), and there is no line to name.
	Line   uint64
	AtLine bool
	// Anchored is true when the head was checked against the chain anchor (chain.log).
	Anchored bool
	Ended    bool
	// Live is an unchecked run that is still being written: its chain is checked once it ends, so the page says when,
	// not that something was left unchecked.
	Live bool
	// Reason is what failed (broken) or why nothing was checked (unchecked).
	Reason string
}

// Verified reports whether the chain verified, for templates.
func (c Chain) Verified() bool { return c.State == ChainVerified }

// Broken reports whether the chain does not verify, for templates.
func (c Chain) Broken() bool { return c.State == ChainBroken }

// Unchecked reports whether the chain was not checked, for templates.
func (c Chain) Unchecked() bool { return c.State == ChainUnchecked }

func unchecked(run, why string) Chain { return Chain{Run: run, State: ChainUnchecked, Reason: why} }

// VerifyRun checks run id's hash chain under root against the chain anchor at anchor, with the code `tego events
// <run> --verify` runs: ledger.VerifyRunDir, over the anchor's answers as ledger.NewFileChainAnchor gives them, read
// through the dashboard's view of chain.log (viewAnchor, anchorview.go: read again after any change to the file, and
// at least once every chainTTL). Its result is read as internal/cli's runVerify reads it, through ledger.VerdictOf
// (this package may not import internal/cli, TestControlLinksNoEngine):
// ErrUnverified is a ledger that does not verify (broken); any other error (the ledger or the anchor not readable, a
// run still closing) and a ledger with no run_start is no verdict (unchecked), as the CLI exits 125 there; nil is
// verified. The dashboard is stricter than the CLI only in refusing to judge: it skips a live run (still being
// written), a run over its line bound, and an anchor path it was not given or that does not exist, each said as
// unchecked, never as verified.
// anchor is the path the CLI would use (internal/control/cli resolves it by ledger.AnchorPath, as tego does); "" is
// unknown.
// When the same run is already being verified (PrewarmChain, another request), it waits for that verdict.
func VerifyRun(ctx context.Context, root, id, anchor string, run *Run) Chain {
	c, _ := verifyRun(ctx, root, id, anchor, run, true)
	return c
}

// verifyRun is VerifyRun; with wait false, a run already being verified elsewhere is not waited for and verifying
// reports it (the overview says "verifying" for it).
func verifyRun(ctx context.Context, root, id, anchor string, run *Run, wait bool) (c Chain, verifying bool) {
	k, why := chainKeyOf(root, id, anchor, run)
	if why != nil {
		return *why, false
	}
	if k.dir == "" { // not cacheable: a run not ended, or an events file that could not be stat'ed
		c, _ := verifyNow(ctx, filepath.Join(root, id), id, anchor)
		return c, false
	}
	return chainFor(ctx, root, k, wait)
}

// chainKeyOf is the cache key of run id's chain check, or the unchecked verdict that makes the check unneeded. A key
// with an empty dir is a check that cannot be cached (the run did not end, or its events file was not there).
func chainKeyOf(root, id, anchor string, run *Run) (chainKey, *Chain) {
	no := func(why string) (chainKey, *Chain) { c := unchecked(id, why); return chainKey{}, &c }
	if !validRunID(id) {
		return no("not a run id")
	}
	if run != nil && run.Live {
		c := unchecked(id, "the run is still being written; check it once it ends")
		c.Live = true
		return chainKey{}, &c
	}
	if run != nil && run.Cut {
		return no(fmt.Sprintf("too long for the dashboard (over %d lines), run tego events %s --verify", MaxLines, id))
	}
	dir := filepath.Join(root, id)
	efi, err := os.Lstat(filepath.Join(dir, ledger.EventsFile))
	if err == nil && efi.Size() > maxVerifyBytes {
		return no(fmt.Sprintf("too long for the dashboard (over %d MiB), run tego events %s --verify", maxVerifyBytes>>20, id))
	}
	if anchor == "" {
		return no("the chain anchor (chain.log) is not known to this dashboard")
	}
	if _, aerr := os.Stat(anchor); aerr != nil {
		// The CLI reads a missing chain.log as "no anchor line" and fails an ended run for it (E29). Here it is
		// more likely a dashboard pointed at another user's ledger root: say so instead of crying "broken".
		return no("the chain anchor " + anchor + " is not readable here: " + errText(aerr))
	}
	if err != nil || run == nil || !run.Ended {
		return chainKey{}, nil
	}
	return chainKey{dir: dir, id: id, events: idOf(efi), lastID: Open(root).lastLineID(id), anchor: anchor}, nil
}

// verifyNow runs the check itself, bounded by verifyTimeout, and returns with its verdict the anchor's answer for the
// run that verdict rests on (nil when the check never asked the anchor: a chain that broke at a line, a ledger that
// could not be read). It reads the events file from disk and the anchor through its view (viewAnchor), as the kept
// verdicts do, so a check reads chain.log only when the view must read it anyway.
func verifyNow(ctx context.Context, dir, id, anchor string) (Chain, *ledger.AnchorHead) {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	a := &viewAnchor{path: anchor}
	rep, verr := ledger.VerifyRunDir(ctx, dir, a)
	c := Chain{Run: id, Lines: rep.Lines, Anchored: rep.Anchored, Ended: rep.Ended}
	// The CLI's reading of the same result (ledger.VerdictOf): `tego events <run> --verify` exits 0, 1 or 125 where
	// this says verified, broken or not checked.
	switch ledger.VerdictOf(rep, verr) {
	case ledger.Unverified:
		c.State, c.Reason = ChainBroken, brokenReason(verr)
		switch {
		case rep.AtLine:
			// A line of its own broke the walk: the chain holds through the lines before it.
			c.AtLine, c.Line, c.Lines = true, rep.BrokenLine, rep.BrokenLine
		case rep.Lines > 0:
			// It held through every line and broke after the last, which rep.Lines counts and #Lines-1 names (an
			// anchor that disagrees or is missing, bytes after run_end).
			c.Line = rep.Lines - 1
		}
		// Neither: there was no line to walk (the ledger gone, replaced or empty), and no line to name.
	case ledger.Verified:
		c.State = ChainVerified
	default:
		if verr != nil {
			return unchecked(id, "the ledger could not be read: "+errText(verr)), a.last
		}
		return unchecked(id, "no run record: "+ledger.EventsFile+" holds no run_start"), a.last
	}
	return c, a.last
}

// An ended run's chain verdict is kept, so the overview does not hash its newest 20 runs again on every load. A
// verdict is what VerifyRunDir makes of two things, the run's events file and the anchor's answer for the run (its
// Head), so it is kept by both. The key is the events file as it was verified (device, inode, size, mtime, ctime and
// its last line's id: fileID, whose ctime no utimes can put back, so an in-place rewrite that keeps the size and mtime
// is a new key, r10 BR-2) and the anchor's path; the entry holds the anchor's answer the verdict rests on, and a look
// asks the anchor again (anchorHeadsNow: one lstat of chain.log while it is unchanged, one read of it after any change,
// shared by every run, and one at least every chainTTL). The verdict stands while the answer is the same, so another
// run's end appending its line costs no check, while any edit the file's stamps show that changes what `tego events
// <run> --verify` would read for this run (its line rewritten in place, a second head for it, a malformed line
// anywhere, its line gone) is checked before the page answers, as is a changed events file. Some writes keep the
// stamps (one within a tick of a coarse clock, one through a shared mapping whose page is already dirty). In chain.log
// such an edit is seen within chainTTL: the first look once the view is chainTTL old reads the file again, for every
// run and check at once, and a changed answer is checked before the page answers. In the events file it is seen once
// the verdict is chainTTL old: the run is then checked again, its events file read from disk and chain.log through the
// view, in the background, while the kept verdict is still shown. A check that finds another verdict than the one
// kept, at a look or in the background, moves the store's revision, so open pages redraw with it. One check per key
// runs at a time (chainFlights): a second asker waits for it, or, on the overview, counts the run as being verified.
// `tego events <run> --verify` stays the authority.
type chainKey struct {
	dir    string
	id     string
	events fileID
	lastID string
	anchor string
}

type chainEntry struct {
	c Chain
	// head is the anchor's answer for the run the verdict rests on; nil when the check never asked the anchor (a chain
	// that broke at a line), and the verdict then stands whatever the anchor says.
	head *ledger.AnchorHead
	at   time.Time
}

// chainFlight is one check of a key in progress; done is closed once c is set.
type chainFlight struct {
	done chan struct{}
	c    Chain
}

const (
	chainTTL         = 10 * time.Minute
	maxChainVerdicts = 4096
)

var (
	chainMu       sync.Mutex
	chainVerdicts = map[chainKey]chainEntry{}
	chainFlights  = map[chainKey]*chainFlight{}
	chainVerifies atomic.Int64 // the number of VerifyRunDir calls the cache let through, for tests
)

// chainFor is k's verdict: the kept one while the anchor answers for the run as it did (checking it again in the
// background once chainTTL ran out), the one a check already running gives (waited for when wait is set; verifying
// otherwise), or a check run now. A check that finds another verdict than the one kept for k moves the store's
// revision, so pages open on the kept one redraw: an edit of chain.log moves no revision of its own.
func chainFor(ctx context.Context, root string, k chainKey, wait bool) (Chain, bool) {
	// The anchor's answer for the run now, asked outside chainMu: one lstat of chain.log while it is unchanged and its
	// view younger than chainTTL. A run the view does not answer for yet is read now, and the check below then finds
	// it there.
	now := anchorHeadsNow(k.anchor, k.id)[0]
	chainMu.Lock()
	e, kept := chainVerdicts[k]
	if kept && (e.head == nil || sameHead(*e.head, now)) {
		if time.Since(e.at) > chainTTL && chainFlights[k] == nil {
			// Only the time ran out: the events file and the anchor's answer are the ones this verdict is for, as far
			// as their stamps tell. Show it, and check again without making the page wait (an overview load used to
			// hash 20 runs here every 10 min), for an edit of the events file its stamps did not show. The check asks
			// chain.log through the view, as `now` did, not from disk: the view is never more than chainTTL old, and
			// the overview's 20 verdicts run out together, so 20 checks each reading the file read it 20 times.
			f := startFlight(k)
			go func() {
				// Bounded by verifyTimeout; not tied to the request, which ends first.
				c, head := verifyNow(context.Background(), k.dir, k.id, k.anchor)
				land(k, head, f, c)
				if otherVerdict(e.c, c) {
					Open(root).bump()
				}
			}()
		}
		chainMu.Unlock()
		return e.c, false
	}
	if f := chainFlights[k]; f != nil {
		chainMu.Unlock()
		if !wait {
			return unchecked(k.id, "being verified"), true
		}
		select {
		case <-f.done:
			return f.c, false
		case <-ctx.Done():
			return unchecked(k.id, "the check was cut short: "+ctx.Err().Error()), false
		}
	}
	f := startFlight(k)
	chainMu.Unlock()
	c, head := verifyNow(ctx, k.dir, k.id, k.anchor)
	land(k, head, f, c)
	if kept && otherVerdict(e.c, c) {
		// The anchor's answer for the run changed since e was reached (chain.log changed under it) and so did the
		// verdict.
		Open(root).bump()
	}
	return c, false
}

// otherVerdict reports whether c is a verdict (verified or broken) that is not was: another state, or a break at
// another line.
func otherVerdict(was, c Chain) bool {
	return (c.Broken() || c.Verified()) && (c.State != was.State || c.Line != was.Line || c.Lines != was.Lines)
}

// startFlight registers a check of ck. chainMu must be held and no check of ck running.
func startFlight(ck chainKey) *chainFlight {
	f := &chainFlight{done: make(chan struct{})}
	chainFlights[ck] = f
	chainVerifies.Add(1)
	return f
}

// land ends f with verdict c, keeping c with the anchor's answer it rests on when it is a verdict (verified or broken).
func land(ck chainKey, head *ledger.AnchorHead, f *chainFlight, c Chain) {
	chainMu.Lock()
	defer chainMu.Unlock()
	if c.Verified() || c.Broken() {
		if len(chainVerdicts) >= maxChainVerdicts {
			clear(chainVerdicts)
		}
		chainVerdicts[ck] = chainEntry{c: c, head: head, at: time.Now()}
	}
	delete(chainFlights, ck)
	f.c = c
	close(f.done)
}

// lastLineID is the id (hash) of the newest line the store published of run, "" when it has not read it.
func (s *Store) lastLineID(run string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st := s.runs[run]; st != nil && st.pub != nil {
		return st.pub.lastID
	}
	return ""
}

// brokenReason is the CLI's error text without the package prefixes it repeats.
func brokenReason(err error) string {
	s := err.Error()
	for {
		t := strings.TrimPrefix(strings.TrimPrefix(s, ledger.ErrUnverified.Error()+": "), "ledger: ")
		if t == s {
			return s
		}
		s = t
	}
}

func errText(err error) string {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err.Error()
	}
	return err.Error()
}

// LedgerChain is the overview's chain check over a snapshot: the newest MaxChainRuns ended runs, verified one by one
// until the first that breaks.
type LedgerChain struct {
	Checked int    // runs verified
	Broken  *Chain // the first run that does not verify, newest first
	// Verifying counts the runs whose first check is still running (PrewarmChain as the dashboard starts, or another
	// request): the overview says so rather than wait, and the store's revision moves when the verdicts are in.
	Verifying int
	Skipped   int    // ended runs past the bound, and runs not checked (live, lost, too long, unreadable)
	Reason    string // set when nothing could be checked
}

// VerifySnapshot checks the newest MaxChainRuns ended runs of s, newest first, stopping at the first broken one. A run
// already being verified elsewhere is counted in Verifying, not waited for.
func VerifySnapshot(ctx context.Context, s *Snapshot, anchor string) LedgerChain {
	var out LedgerChain
	for _, r := range s.Runs {
		if !r.Ended || r.Live {
			out.Skipped++
			continue
		}
		if out.Checked+out.Verifying >= MaxChainRuns {
			out.Skipped++
			continue
		}
		c, verifying := verifyRun(ctx, s.Root, r.ID, anchor, r, false)
		switch {
		case verifying:
			out.Verifying++
		case c.State == ChainVerified:
			out.Checked++
		case c.State == ChainBroken:
			out.Broken = &c
			return out
		default:
			out.Skipped++
			if out.Reason == "" {
				out.Reason = c.Reason
			}
		}
	}
	return out
}

// PrewarmChain starts checking the runs VerifySnapshot would check that have no verdict yet, newest first, on up to
// four goroutines, and returns a channel closed once all are done. Every such run is marked as being verified before
// it returns, so an overview opened meanwhile says "verifying" for them instead of hashing them again or waiting; once
// all are in, the store's revision moves and open pages redraw. internal/control/web's Server.Prewarm runs it as
// tego-control serve starts, after the first Load, and waits for the channel. ctx ending (the server stopping) cuts
// the checks short, each then unchecked and not kept.
func PrewarmChain(ctx context.Context, s *Snapshot, anchor string) <-chan struct{} {
	type todo struct {
		k chainKey
		f *chainFlight
	}
	var (
		list []todo
		ids  []string
	)
	for _, r := range s.Runs {
		if !r.Ended || r.Live || len(ids) >= MaxChainRuns {
			continue
		}
		k, why := chainKeyOf(s.Root, r.ID, anchor, r)
		if why != nil || k.dir == "" {
			continue
		}
		ids = append(ids, r.ID)
		chainMu.Lock()
		if _, kept := chainVerdicts[k]; !kept && chainFlights[k] == nil {
			list = append(list, todo{k, startFlight(k)})
		}
		chainMu.Unlock()
	}
	done := make(chan struct{})
	if len(list) == 0 {
		close(done)
		return done
	}
	// One read of chain.log answers for every run the overview checks, so the checks below each find their run's
	// line in the view instead of reading the file again.
	anchorHeadsNow(anchor, ids...)
	// On readWorkers goroutines, as the cold read: one after another, the 20 checks of the r7 perf ledger took 2.4 s.
	next := make(chan todo, len(list))
	for _, t := range list {
		next <- t
	}
	close(next)
	var wg sync.WaitGroup
	for range readWorkers(len(list)) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for t := range next {
				c, head := verifyNow(ctx, t.k.dir, t.k.id, t.k.anchor)
				land(t.k, head, t.f, c)
			}
		}()
	}
	go func() {
		wg.Wait()
		Open(s.Root).bump()
		close(done)
	}()
	return done
}
