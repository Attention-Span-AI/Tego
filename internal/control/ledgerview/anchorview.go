// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// anchorView is a chain anchor (chain.log) as the dashboard last read it: what ledger.AnchorHeads answered for each
// run asked about so far, which is what `tego events <run> --verify` reads there, and the file as it was opened. A
// look that finds the same file at the path (device, inode, size, mtime and ctime: fileID) costs one lstat; any change
// to it, a run's end appending its line or an edit in place, is read again once, for every run the view answers for.
// The chain checks ask the anchor through it (viewAnchor), and a kept verdict stands only while it answers for the run
// as it did when the verdict was reached (chain.go).
//
// The stamps miss some changes: a write within one tick of a coarse clock (a kernel without multigrain timestamps,
// before 6.13) keeps mtime and ctime, and so does a write through a shared mapping whose page is already dirty, which
// takes no fault. So a view is trusted for chainTTL at most: past it the next look reads the file again whatever the
// stamps say, and a change they did not show is seen within chainTTL of being made. That one read serves every run
// and every check, the background re-checks of kept verdicts included: no check reads chain.log for itself.
//
// The file is read outside anchorMu, one read of a path at a time (anchorFlight): a look that needs it read again
// waits for the read in flight, or makes it, and shares it; a look the view already answers for waits for no read.
type anchorView struct {
	stamp fileID    // the file as read
	known bool      // a regular file was opened and stat'ed; false for none, or one that could not be opened
	read  time.Time // when the read began; a view older than chainTTL is read again
	// seq is the read's number in anchorSeq: a view whose read began after a look's lstat answers for that look,
	// whatever its stamps.
	seq   uint64
	heads map[string]ledger.AnchorHead
}

// anchorFlight is a read of a chain.log in progress; done is closed once it is over, its view (if it made one) in
// anchorViews.
type anchorFlight struct{ done chan struct{} }

// maxAnchorRuns bounds the runs one view answers for: a read past it answers for the runs it was asked about only.
const maxAnchorRuns = maxChainVerdicts

// headsReader reads a chain anchor for runs, as ledger.AnchorHeads does.
type headsReader func(path string, runs []string) (map[string]ledger.AnchorHead, os.FileInfo)

var (
	// anchorMu guards anchorViews, anchorFlights, anchorSeq and anchorHeadsOf; it is never held while a file is read.
	anchorMu      sync.Mutex
	anchorViews   = map[string]*anchorView{}
	anchorFlights = map[string]*anchorFlight{}
	anchorSeq     uint64       // the reads begun
	anchorReads   atomic.Int64 // the reads of a chain.log the views made, for tests
	// anchorHeadsOf is the read, ledger.AnchorHeads; a variable so a test can hold one in flight.
	anchorHeadsOf headsReader = ledger.AnchorHeads
)

// anchorHeadsNow is, for each of runs, what ledger.NewFileChainAnchor(path).Head(run) answers now. It is the view of
// path's answer when the view answers for every run asked and is current for this look: the file at the path is the
// one it read and it was read less than chainTTL ago, or its read began after this look's lstat. Else it is one read
// of the file for those runs and every run the view answered for before, shared with every look that needs it read
// at the same time.
func anchorHeadsNow(path string, runs ...string) []ledger.AnchorHead {
	stamp, known := anchorStamp(path)
	anchorMu.Lock()
	seen := anchorSeq // a read begun after this was begun after the lstat above
	for {
		v := anchorViews[path]
		if v != nil && v.answers(runs) && (v.seq > seen || v.current(stamp, known)) {
			out := make([]ledger.AnchorHead, len(runs))
			for i, r := range runs {
				out[i] = v.heads[r]
			}
			anchorMu.Unlock()
			return out
		}
		if f := anchorFlights[path]; f != nil {
			anchorMu.Unlock()
			<-f.done
		} else {
			f = &anchorFlight{done: make(chan struct{})}
			anchorFlights[path] = f
			anchorSeq++
			seq, want, read := anchorSeq, wanted(v, runs), anchorHeadsOf
			anchorMu.Unlock()
			f.read(read, path, want, seq)
		}
		anchorMu.Lock()
	}
}

// wanted is what a read for runs asks the file about: those runs, and every run v answered for while they stay
// within maxAnchorRuns.
func wanted(v *anchorView, runs []string) []string {
	want := slices.Clone(runs)
	if v != nil && len(v.heads)+len(runs) <= maxAnchorRuns {
		for r := range v.heads {
			want = append(want, r)
		}
	}
	return want
}

// read reads the chain.log at path for want with read, without anchorMu, and makes what it read the view of path; f
// is then done, whatever happened, so no look waits on it for good.
func (f *anchorFlight) read(read headsReader, path string, want []string, seq uint64) {
	var v *anchorView
	defer func() {
		anchorMu.Lock()
		if v != nil {
			anchorViews[path] = v
		}
		delete(anchorFlights, path)
		anchorMu.Unlock()
		close(f.done)
	}()
	start := time.Now() // before the read, so a change made while it ran is read again within chainTTL
	heads, fi := read(path, want)
	anchorReads.Add(1)
	v = &anchorView{heads: heads, read: start, seq: seq}
	if fi != nil {
		v.stamp, v.known = idOf(fi), true
	}
}

// current reports whether v is the file a look found at the path (stamp, known), read less than chainTTL ago.
func (v *anchorView) current(stamp fileID, known bool) bool {
	return v.known == known && v.stamp == stamp && time.Since(v.read) <= chainTTL
}

// answers reports whether v holds an answer for each of runs.
func (v *anchorView) answers(runs []string) bool {
	for _, r := range runs {
		if _, ok := v.heads[r]; !ok {
			return false
		}
	}
	return true
}

// anchorStamp is the file at path as lstat finds it, and whether there is one. For a regular file it is what the
// view's read stat'ed through its descriptor; a link, which the read refuses, never equals that.
func anchorStamp(path string) (fileID, bool) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileID{}, false
	}
	return idOf(fi), true
}

// sameHead reports whether a and b are one answer: the same head, found or not, and the same error.
func sameHead(a, b ledger.AnchorHead) bool {
	return a.Head == b.Head && a.OK == b.OK && errMsg(a.Err) == errMsg(b.Err)
}

func errMsg(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// viewAnchor is the chain anchor at path as a dashboard check reads it: each Head is anchorHeadsNow's answer, so the
// checks and the kept verdicts share the views' reads. last is the answer it gave last, the one the check's verdict
// rests on: Verify decides on its last Head (it asks again on a rescan, and while a closing run's lock is held).
type viewAnchor struct {
	path string
	last *ledger.AnchorHead
}

// Append refuses: the dashboard never writes chain.log.
func (a *viewAnchor) Append(string, string) error {
	return errors.New("ledgerview: the dashboard does not append to chain.log")
}

// Head is the anchor's answer for run now.
func (a *viewAnchor) Head(run string) (string, bool, error) {
	h := anchorHeadsNow(a.path, run)[0]
	a.last = &h
	return h.Head, h.OK, h.Err
}
