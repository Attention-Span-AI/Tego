// SPDX-License-Identifier: Apache-2.0

package web

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/attention-span-ai/tego/internal/control/ledgerview"
	"github.com/attention-span-ai/tego/internal/control/rules"
	"github.com/attention-span-ai/tego/internal/control/runact"
	"github.com/attention-span-ai/tego/internal/liveblock"
)

// Unchanged region answers (DT-CACHE item 4). static/live.js asks for a page's changed regions each time the live
// state moves (live.go), and that state is the whole ledger root's: while one agent writes lines, the page of
// another run asked about once a second, and the run page's handler ran in full (its Highlights, verdict, timeline
// and Block now panel) only to answer that nothing changed. A run page's regions follow its own run, the enforced
// run it is read against (ledgerview.ReferenceRun), the waiting asks and whether anything runs (the layout), and a
// few files beside the run; runPageKey hashes exactly those, cheaply, before the handler would run. After a region
// answer the server keeps that key with the region hashes it answered (regionMemo); when the same address asks
// again with those very hashes and the key has not moved, it answers 204 No Content without running the handler,
// which live.js reads as "nothing to merge". Any other page, a page whose key cannot be made, or a page showing
// other hashes than the ones kept is answered by its handler as before.

// regionMemo is one address's last region answer: the key it was made at and every region hash it rendered.
type regionMemo struct {
	key    string
	hashes map[string]string
}

// regionMemos holds the region answers by address (path and query), bounded by maxRegionMemos.
type regionMemos struct {
	mu sync.Mutex
	m  map[string]regionMemo
}

// maxRegionMemos bounds the kept answers (an address each); past it the memo starts again.
const maxRegionMemos = 128

// memoTabs are the run page tabs whose regions follow only what runPageKey hashes. Least privilege and Unused also
// read the machine config and the contract source, which no ledger revision covers, so they are always rendered.
var memoTabs = map[string]bool{"timeline": true, "refusals": true, "receipt": true}

// runPageKey is the key of a run page address r asks for its regions: it moves whenever anything the page's regions
// show may have moved. It reports false for any other address, and for a run the snapshot does not hold.
func (s *Server) runPageKey(r *http.Request, snap *ledgerview.Snapshot) (string, bool) {
	rest, ok := strings.CutPrefix(r.URL.Path, "/runs/")
	if !ok || rest == "" {
		return "", false
	}
	id, tab, _ := strings.Cut(rest, "/")
	if tab == "" {
		tab = "timeline"
	}
	if !memoTabs[tab] {
		return "", false
	}
	run := snap.Find(id)
	if run == nil {
		return "", false
	}
	st := stateOf(snap)
	h := sha256.New()
	// The address, the layout (waiting asks, anything live, the snapshot's notes) and the run itself.
	fmt.Fprintf(h, "%s?%s\x00%s\x00%t\x00%t:%t:%d\x00%s:%d:%t:%t\x00", r.URL.Path, r.URL.RawQuery, st.Sig, st.Live > 0,
		snap.RunsCut, snap.LinesCut, snap.TotalRuns, run.ID, run.Rev, run.Live, run.Cut)
	if ref := ledgerview.ReferenceRun(snap.Runs, run); ref != nil {
		fmt.Fprintf(h, "ref:%s:%d\x00", ref.ID, ref.Rev)
	}
	// No clock: a running run's duration so far ticks in the browser (data-ck, regions.go), so its page's regions
	// move only with what the key hashes.
	// The files beside the run the page reads: its live blocks and pause request (one overlay, written before the
	// launcher's line confirms them), the launcher's mark that it reads a pause (made once its poll runs, which may
	// be after the lines around it: until then the page offers no Pause), its stop marker, the rule-change journal
	// its timeline's change rows come from (changefeed.go; a change that places no live block writes no line), and
	// the chain anchor it is verified against.
	fmt.Fprintf(h, "stop:%t\x00", runact.Stopping(s.cfg.Ledger, run.ID))
	statKey(h, filepath.Join(s.cfg.Ledger, run.ID, liveblock.FileName))
	statKey(h, filepath.Join(s.cfg.Ledger, run.ID, liveblock.ControlName))
	statKey(h, rules.JournalPath(s.cfg.Ledger))
	if s.cfg.Anchor != "" {
		statKey(h, s.cfg.Anchor)
	}
	return hex.EncodeToString(h.Sum(nil)), true
}

// statKey writes what a change to the file at p would move (identity, size, times), or that it is missing.
func statKey(w io.Writer, p string) {
	var st syscall.Stat_t
	if err := syscall.Lstat(p, &st); err != nil {
		_, _ = fmt.Fprintf(w, "%s:none\x00", p)
		return
	}
	_, _ = fmt.Fprintf(w, "%s:%d:%d:%d:%d.%d:%d.%d\x00", p, st.Dev, st.Ino, st.Size, st.Mtim.Sec, st.Mtim.Nsec,
		st.Ctim.Sec, st.Ctim.Nsec)
}

// regionsUnchanged reports whether a region request for r, showing have, would answer no region: the address's last
// answer was made at key and the page shows exactly the hashes it rendered.
func (s *Server) regionsUnchanged(r *http.Request, key string, have map[string]string) bool {
	s.memos.mu.Lock()
	m, ok := s.memos.m[r.URL.Path+"?"+r.URL.RawQuery]
	s.memos.mu.Unlock()
	if !ok || m.key != key {
		return false
	}
	for n, hash := range have {
		if got, ok := m.hashes[n]; !ok || got != hash {
			return false
		}
	}
	return true
}

// rememberRegions keeps a region answer's hashes under the key taken before its handler ran. Only a 200 is kept.
func (s *Server) rememberRegions(r *http.Request, key string, fw *fragWriter) {
	if fw.hashes == nil || fw.status != http.StatusOK {
		return
	}
	s.memos.mu.Lock()
	defer s.memos.mu.Unlock()
	if s.memos.m == nil || len(s.memos.m) >= maxRegionMemos {
		s.memos.m = map[string]regionMemo{}
	}
	s.memos.m[r.URL.Path+"?"+r.URL.RawQuery] = regionMemo{key: key, hashes: fw.hashes}
}

// serveRegions answers a region request: 204 when the run page it names has not moved since its last answer and the
// page shows that answer's hashes; else the same address's render at the same live state from the last second, when
// one is kept (regioncache.go); else the handler's answer (renderRegions), kept for the next ask.
func (s *Server) serveRegions(w http.ResponseWriter, r *http.Request, have map[string]string) {
	// The snapshot and the keys are taken before the handler runs: an answer is never kept under a key newer than
	// its data.
	snap, st, ok := s.liveStateOf()
	var key, ckey string
	var keyed bool
	if ok {
		key, keyed = s.runPageKey(r, snap)
		// A run page's key covers the files beside its run too (its live blocks, its stop marker).
		ckey = cacheKey(r.URL.Path, r.URL.RawQuery, have, st) + "\x00" + key
	}
	if keyed && s.regionsUnchanged(r, key, have) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	fw := &fragWriter{ResponseWriter: w, have: have}
	now := time.Now() // the wall clock, not cfg.Now: the cache bounds how old an answer is in real time
	e, gen, hit := s.regionCache.get(ckey, now)
	switch {
	case ok && hit:
		fw.answer(&e)
	default:
		s.route(fw, r)
		if ok && fw.entry != nil && fw.status == http.StatusOK {
			e := *fw.entry
			e.at, e.gen = now, gen
			s.regionCache.put(ckey, e)
		}
	}
	if keyed {
		s.rememberRegions(r, key, fw)
	}
}
