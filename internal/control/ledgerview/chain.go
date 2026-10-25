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
	// Line is the seq (the timeline's #N, the CLI's "line N") of the line the chain broke at, when Broken and
	// the walk stopped on a line; AtLine says it did (an anchor mismatch breaks after the last line instead).
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
// <run> --verify` runs: ledger.VerifyRunDir over ledger.NewFileChainAnchor. The verdict mirrors internal/cli's
// runVerify (verify.go), which this package may not import (TestControlLinksNoEngine): ErrUnverified is a ledger
// that does not verify (broken); any other error (the ledger or the anchor not readable, a run still closing) and a
// ledger with no run_start is no verdict (unchecked), as the CLI exits 125 there; nil is verified. The dashboard is
// stricter than the CLI only in refusing to judge: it skips a live run (still being written), a run over its line
// bound, and an anchor path it was not given or that does not exist, each said as unchecked, never as verified.
// anchor is the path the CLI would use (internal/control/cli resolves it as runtime.AnchorPath does); "" is unknown.
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
		return verifyNow(ctx, filepath.Join(root, id), id, anchor), false
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
	afi, aerr := os.Stat(anchor)
	if aerr != nil {
		// The CLI reads a missing chain.log as "no anchor line" and fails an ended run for it (E29). Here it is
		// more likely a dashboard pointed at another user's ledger root: say so instead of crying "broken".
		return no("the chain anchor " + anchor + " is not readable here: " + errText(aerr))
	}
	if err != nil || run == nil || !run.Ended {
		return chainKey{}, nil
	}
	k := chainKey{dir: dir, id: id, events: idOf(efi), lastID: Open(root).lastLineID(id), anchor: anchor, anchorSize: afi.Size()}
	k.anchorDev, k.anchorIno = idOf(afi).dev, idOf(afi).ino
	return k, nil
}

// verifyNow runs the check itself, bounded by verifyTimeout.
func verifyNow(ctx context.Context, dir, id, anchor string) Chain {
	ctx, cancel := context.WithTimeout(ctx, verifyTimeout)
	defer cancel()
	rep, verr := ledger.VerifyRunDir(ctx, dir, ledger.NewFileChainAnchor(anchor))
	c := Chain{Run: id, Lines: rep.Lines, Anchored: rep.Anchored, Ended: rep.Ended}
	switch {
	case verr != nil && errors.Is(verr, ledger.ErrUnverified):
		c.State, c.Reason = ChainBroken, brokenReason(verr)
		// Lines is the count before the line that broke the walk, which is that line's seq; an anchor that
		// disagrees with the whole chain (or is missing for an ended run) breaks after the last line.
		c.Line = rep.Lines
		c.AtLine = !errors.Is(verr, ledger.ErrAnchorMissing) && !errors.Is(verr, ledger.ErrLedgerMissing) &&
			!strings.Contains(verr.Error(), "anchored head")
	case verr != nil:
		return unchecked(id, "the ledger could not be read: "+errText(verr))
	case !rep.Started:
		return unchecked(id, "no run record: "+ledger.EventsFile+" holds no run_start")
	default:
		c.State = ChainVerified
	}
	return c
}

// An ended run's chain verdict is kept, so the overview does not hash its newest 20 runs again on every load. The key
// is the events file as it was verified (device, inode, size, mtime, ctime and its last line's id: fileID, whose ctime
// no utimes can put back, so an in-place rewrite that keeps the size and mtime is a new key, r10 BR-2) and the anchor
// file's identity; a verdict is dropped when the anchor got shorter than it was. The anchor's ctime is not in the key:
// every run's end appends to chain.log, and each append would check every kept verdict again. After chainTTL the same
// key is checked again, so an edit of chain.log in place is seen: in the background, while the verdict for that same
// file and anchor
// is still shown, and the store's revision moves if the new verdict differs, so open pages redraw with it. A changed
// events file or anchor is a new key and is checked before the page answers. One check per key runs at a time
// (chainFlights): a second asker waits for it, or, on the overview, counts the run as being verified.
// `tego events <run> --verify` stays the authority.
type chainKey struct {
	dir                  string
	id                   string
	events               fileID
	lastID               string
	anchor               string
	anchorDev, anchorIno uint64
	anchorSize           int64 // as seen when asked; not compared by the cache, which keeps the size it verified
}

type chainEntry struct {
	c          Chain
	anchorSize int64
	at         time.Time
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

// cacheKey is k without the anchor size it was asked with, as the maps hold it.
func (k chainKey) cacheKey() chainKey { k.anchorSize = 0; return k }

// chainFor is k's verdict: the kept one (checking it again in the background once chainTTL ran out), the one a check
// already running gives (waited for when wait is set; verifying otherwise), or a check run now.
func chainFor(ctx context.Context, root string, k chainKey, wait bool) (Chain, bool) {
	ck := k.cacheKey()
	chainMu.Lock()
	if e, ok := chainVerdicts[ck]; ok && k.anchorSize >= e.anchorSize {
		if time.Since(e.at) > chainTTL && chainFlights[ck] == nil {
			// Only the time ran out: the events file and the anchor are the ones this verdict is for. Show it, and
			// check again without making the page wait (an overview load used to hash 20 runs here every 10 min).
			f := startFlight(ck)
			go func() {
				// Bounded by verifyTimeout; not tied to the request, which ends first.
				c := verifyNow(context.Background(), k.dir, k.id, k.anchor)
				land(ck, k.anchorSize, f, c)
				if (c.Broken() || c.Verified()) && (c.State != e.c.State || c.Line != e.c.Line || c.Lines != e.c.Lines) {
					Open(root).bump()
				}
			}()
		}
		chainMu.Unlock()
		return e.c, false
	}
	if f := chainFlights[ck]; f != nil {
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
	f := startFlight(ck)
	chainMu.Unlock()
	c := verifyNow(ctx, k.dir, k.id, k.anchor)
	land(ck, k.anchorSize, f, c)
	return c, false
}

// startFlight registers a check of ck. chainMu must be held and no check of ck running.
func startFlight(ck chainKey) *chainFlight {
	f := &chainFlight{done: make(chan struct{})}
	chainFlights[ck] = f
	chainVerifies.Add(1)
	return f
}

// land ends f with verdict c, keeping c when it is a verdict (verified or broken).
func land(ck chainKey, anchorSize int64, f *chainFlight, c Chain) {
	chainMu.Lock()
	defer chainMu.Unlock()
	if c.Verified() || c.Broken() {
		if len(chainVerdicts) >= maxChainVerdicts {
			clear(chainVerdicts)
		}
		chainVerdicts[ck] = chainEntry{c: c, anchorSize: anchorSize, at: time.Now()}
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
	var list []todo
	n := 0
	for _, r := range s.Runs {
		if !r.Ended || r.Live || n >= MaxChainRuns {
			continue
		}
		k, why := chainKeyOf(s.Root, r.ID, anchor, r)
		if why != nil || k.dir == "" {
			continue
		}
		n++
		ck := k.cacheKey()
		chainMu.Lock()
		if _, kept := chainVerdicts[ck]; !kept && chainFlights[ck] == nil {
			list = append(list, todo{k, startFlight(ck)})
		}
		chainMu.Unlock()
	}
	done := make(chan struct{})
	if len(list) == 0 {
		close(done)
		return done
	}
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
				land(t.k.cacheKey(), t.k.anchorSize, t.f, verifyNow(ctx, t.k.dir, t.k.id, t.k.anchor))
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
