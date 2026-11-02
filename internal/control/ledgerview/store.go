// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"
)

// MaxResidentBytes bounds the decoded lines the read model keeps (an estimate, eventBytes). Past it, the lines of the
// ended runs no page asked for longest are dropped (their summaries, counts and asks stay) and read again from the
// file when a page needs them. A variable so tests can lower it.
var MaxResidentBytes int64 = 512 << 20

// Store is one ledger root's cached read model. Every request asks it for a Snapshot or a Run; it looks at each events
// file's identity, size and mtime, decodes only what was appended since the last look, and hands out immutable Runs
// that concurrent requests share. Load and LoadRun use the Store of their root (Open), so the cache lives as long as
// the process. Safe for concurrent use.
type Store struct {
	root string

	mu       sync.Mutex
	runs     map[string]*runState
	rev      uint64
	tick     uint64
	resident int64
	// bg is set while the background Snapshot a LoadNow handed a big read to runs, so at most one does.
	bg bool

	// internMu guards intern alone: runs are decoded in parallel outside mu (read), and each line takes it once.
	internMu sync.Mutex
	intern   map[string]string

	// liveMu guards probes alone: each run the live index lists, with the last probe of its lock (livelock.go).
	liveMu sync.Mutex
	probes map[string]lockProbe
}

var (
	storesMu sync.Mutex
	stores   = map[string]*Store{}
)

// Open returns the Store of root, made on first use. Two spellings of one directory share it after filepath.Clean.
func Open(root string) *Store {
	root = filepath.Clean(root)
	storesMu.Lock()
	defer storesMu.Unlock()
	s := stores[root]
	if s == nil {
		// The revision starts at the clock in microseconds, so a restarted server never repeats one an open page
		// still holds.
		s = &Store{root: root, runs: map[string]*runState{}, rev: uint64(time.Now().UnixMicro()), intern: map[string]string{},
			probes: map[string]lockProbe{}}
		stores[root] = s
	}
	return s
}

// Rev is the store's current revision, as of the last Snapshot or Run; it does not look at the ledger.
func (s *Store) Rev() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.rev
}

func (s *Store) state(id string) *runState {
	st := s.runs[id]
	if st == nil {
		st = newRunState(id, filepath.Join(s.root, id, "events.jsonl"))
		st.store = s
		s.runs[id] = st
	}
	return st
}

// A run is decoded outside s.mu, so a cold start neither blocks the requests that need nothing new nor reads one run
// after another: under s.mu a request claims the runs whose events file changed (runState.reading), drops the lock,
// decodes them on up to readWorkers goroutines, each owning its runState, and takes the lock again only to publish.
// A run another request is reading is waited for (its reading channel closes once it is published), never read
// twice at once. Measured on the r7 perf ledger (22 runs, about 200k lines, 4 cores): a cold Overview went from 5.2 s
// to under 2 s; docs/DASHBOARD.md, "Cold start", has the numbers.

// readWorkers is how many goroutines decode n claimed runs: one per run, at most GOMAXPROCS and at most 4.
func readWorkers(n int) int { return max(1, min(n, runtime.GOMAXPROCS(0), 4)) }

// nowaitBytes is the most a LoadNow decodes itself: about 1,700 lines, some 30 ms. A run with more unread is handed to
// a background Snapshot and shown as last published.
const nowaitBytes = 1 << 20

// want is one run a request needs up to date: its runState, its events file's Lstat (nil to open it regardless) and
// whether the root lists it as live.
type want struct {
	st   *runState
	seen os.FileInfo
	live bool
}

// job is a claimed run being read: what the read found, and the resident estimate it had before.
type job struct {
	want
	before      int64
	wasResident bool
	changed     bool
	err         error
}

// claim marks w's run as being read by the caller. s.mu must be held and the run not claimed.
func (s *Store) claim(w want) *job {
	w.st.reading = make(chan struct{})
	return &job{want: w, before: w.st.bytes, wasResident: w.st.resident}
}

// stale reports whether st must be read for seen: never read, or its events file is not the one it read. After
// waiting for another request's read (again), a file that read saw at least as far (the same identity, no larger,
// no newer mtime or ctime) is enough, so a request does not read twice what another just read. s.mu must be held and
// st not claimed.
func stale(st *runState, seen os.FileInfo, again bool) bool {
	if st.pub == nil {
		return true
	}
	if seen == nil {
		return !st.resident
	}
	now := idOf(seen)
	if now == st.file {
		return false
	}
	return !again || now.dev != st.file.dev || now.ino != st.file.ino || now.size > st.file.size || now.mtime > st.file.mtime ||
		now.ctime > st.file.ctime
}

// unread estimates the bytes a read of st would decode for seen. s.mu must be held and st not claimed.
func unread(st *runState, seen os.FileInfo) int64 {
	now := idOf(seen)
	if st.pub == nil || rewritten(now, st.file, st.off) || !st.resident {
		return now.size
	}
	return now.size - st.off
}

// bring brings the runs of ws up to date and publishes each that changed under a new revision. With wait false
// (LoadNow) it waits for no other request's read and decodes no run with more than nowaitBytes unread: such a run
// keeps its last published version (none when it was never read), and deferred reports that one was left for later.
// s.mu must be held; it is released while runs are read and held again on return.
func (s *Store) bring(ws []want, wait bool) (deferred bool) {
	for again := false; len(ws) > 0; again = true {
		var mine []*job
		var waits []chan struct{}
		var next []want
		for _, w := range ws {
			st := w.st
			if st.reading != nil { // another request is reading it: wait, then look again
				if wait {
					waits = append(waits, st.reading)
					next = append(next, w)
				}
				continue
			}
			if !stale(st, w.seen, again) {
				if w.live != st.live {
					st.live = w.live
					s.rev++
					st.used = s.tick
					st.publish(s.rev)
				}
				continue
			}
			if !wait && w.seen != nil && unread(st, w.seen) > nowaitBytes {
				deferred = true
				continue
			}
			mine = append(mine, s.claim(w))
		}
		if len(mine) > 0 {
			s.mu.Unlock()
			s.readAll(mine)
			s.mu.Lock()
			for _, j := range mine {
				s.finish(j)
			}
		}
		// Only now, holding no claim, wait for the others: two requests each waiting with a claim of its own would
		// wait for each other for ever.
		if len(waits) > 0 {
			s.mu.Unlock()
			for _, ch := range waits {
				<-ch
			}
			s.mu.Lock()
		}
		ws = next
	}
	return deferred
}

// readAll reads the claimed runs, on up to readWorkers goroutines that all end before it returns. s.mu must not be
// held: each read touches only its own runState (and the intern table, under internMu).
func (s *Store) readAll(jobs []*job) {
	n := readWorkers(len(jobs))
	if n <= 1 {
		for _, j := range jobs {
			j.changed, j.err = s.read(j.st, j.seen)
		}
		return
	}
	next := make(chan *job)
	var wg sync.WaitGroup
	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range next {
				j.changed, j.err = s.read(j.st, j.seen)
			}
		}()
	}
	for _, j := range jobs {
		next <- j
	}
	close(next)
	wg.Wait()
}

// finish publishes a read run, under a new revision when anything a page shows changed, and ends its claim. s.mu
// must be held.
func (s *Store) finish(j *job) {
	st := j.st
	changed := j.changed
	if j.err != nil && st.pub == nil {
		st.b.Bad++
		changed = true
	}
	if j.live != st.live {
		st.live, changed = j.live, true
	}
	if j.wasResident {
		s.resident -= j.before
	}
	if st.resident {
		s.resident += st.bytes
	}
	if changed || st.pub == nil {
		s.rev++
		st.used = s.tick
		st.publish(s.rev)
	}
	close(st.reading)
	st.reading = nil
}

// touch marks st as used by a page now, for the LRU. s.mu must be held.
func (s *Store) touch(st *runState) {
	s.tick++
	st.used = s.tick
}

// evict drops the lines of the least recently used ended runs until the resident estimate is under
// MaxResidentBytes, never those of keep, of a run not ended or of a run being read. s.mu must be held.
func (s *Store) evict(keep *runState) {
	if s.resident <= MaxResidentBytes {
		return
	}
	var cands []*runState
	for _, st := range s.runs {
		if st.reading == nil && st.resident && st != keep && st.b.Ended && !st.live && st.bytes > 0 {
			cands = append(cands, st)
		}
	}
	sort.Slice(cands, func(i, j int) bool { return cands[i].used < cands[j].used })
	for _, st := range cands {
		if s.resident <= MaxResidentBytes {
			return
		}
		s.resident -= st.bytes
		st.bytes, st.resident = 0, false
		st.b.Events = nil
		st.publish(st.pub.Rev) // the same content, so the same revision; only the lines are gone
	}
}

// lines returns st's lines, reading them again from the file when they were evicted. The read runs outside s.mu
// under st's claim, as bring's reads do.
func (s *Store) lines(st *runState) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	for st.reading != nil {
		ch := st.reading
		s.mu.Unlock()
		<-ch
		s.mu.Lock()
	}
	if !st.resident {
		old := st.pub
		st.reading = make(chan struct{})
		s.mu.Unlock()
		_, _ = s.read(st, nil)
		s.mu.Lock()
		s.resident += st.bytes // it was not resident, so it counted nothing before
		rev := old.Rev
		if st.b.Lines != old.Lines || (len(st.b.Events) > 0 && st.b.Events[len(st.b.Events)-1].Seq != old.LastSeq) {
			s.rev++
			rev = s.rev
		}
		st.publish(rev)
		close(st.reading)
		st.reading = nil
		s.touch(st)
		s.evict(st)
	}
	return st.pub.Events
}

// AllEvents is the run's lines: Events when they are in memory, else read again from its events file (the read
// model drops the lines of runs no page asked for when it holds more than MaxResidentBytes). The slice is shared and
// must not be modified.
func (r *Run) AllEvents() []Event {
	if r.Events != nil || r.st == nil || r.Lines == 0 {
		return r.Events
	}
	return r.st.store.lines(r.st)
}

// Load scans root. A root that does not exist yet is an empty snapshot, not an error.
func Load(root string) (*Snapshot, error) { return Open(root).Snapshot() }

// LoadNow is Load for a caller that must answer at once (the live state pages follow, internal/control/web live.go).
// It never waits for a run another request is reading and decodes itself only runs with little appended
// (nowaitBytes); those runs keep their last published version and a run never read yet is left out, with
// Snapshot.Partial set. The snapshot is still the ledger as of its Rev: the pending read moves the revision when it
// publishes. A run left for later is read by one background Snapshot. During a cold start this keeps /status.json
// and /events answering in milliseconds instead of behind seconds of decoding.
func LoadNow(root string) (*Snapshot, error) { return Open(root).snapshot(false) }

// LoadRun reads one run alone, with the whole line budget. A malformed id or a missing run is os.ErrNotExist.
func LoadRun(root, id string) (*Run, error) { return Open(root).Run(id) }

// Snapshot brings every run directory of the root up to date and returns them, newest start first, within the
// bounds (MaxRuns, MaxLines).
func (s *Store) Snapshot() (*Snapshot, error) { return s.snapshot(true) }

func (s *Store) snapshot(wait bool) (*Snapshot, error) {
	snap := &Snapshot{Root: s.root}
	// Before any events file is looked at: a lock seen free then means the look finds run_end if the run ended.
	live := s.liveRuns()
	ents, err := os.ReadDir(s.root)
	if errors.Is(err, os.ErrNotExist) {
		s.mu.Lock()
		snap.Rev = s.rev
		s.mu.Unlock()
		return snap, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read ledger root: %w", err)
	}
	type cand struct {
		id string
		fi os.FileInfo
	}
	var cands []cand
	present := map[string]bool{}
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "r-") || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		fi, err := os.Lstat(filepath.Join(s.root, e.Name(), "events.jsonl"))
		if err != nil || !fi.Mode().IsRegular() {
			continue
		}
		cands = append(cands, cand{e.Name(), fi})
		present[e.Name()] = true
	}
	snap.TotalRuns = len(cands)
	sort.Slice(cands, func(i, j int) bool { return cands[i].fi.ModTime().After(cands[j].fi.ModTime()) })
	if len(cands) > MaxRuns {
		cands = cands[:MaxRuns]
		snap.RunsCut = true
	}
	pubs := make([]*Run, 0, len(cands))
	s.mu.Lock()
	for id, st := range s.runs {
		if !present[id] && st.reading == nil { // a run being read leaves on a later look
			if st.resident {
				s.resident -= st.bytes
			}
			delete(s.runs, id)
			s.rev++
		}
	}
	ws := make([]want, 0, len(cands))
	for _, c := range cands {
		ws = append(ws, want{st: s.state(c.id), seen: c.fi, live: live[c.id]})
	}
	deferred := s.bring(ws, wait)
	s.evict(nil)
	for _, w := range ws {
		if w.st.pub == nil { // never read yet: LoadNow only
			snap.Partial = true
			continue
		}
		if !wait && (w.st.reading != nil || stale(w.st, w.seen, true)) {
			snap.Partial = true
		}
		pubs = append(pubs, w.st.pub)
	}
	snap.Rev = s.rev
	if deferred && !s.bg {
		s.bg = true
		go s.background()
	}
	s.mu.Unlock()

	total := 0
	for _, p := range pubs {
		total += p.Lines
	}
	if total <= MaxLines {
		snap.Runs, snap.Lines = pubs, total
	} else {
		budget := MaxLines
		for _, p := range pubs {
			r, used := p, p.Lines
			if limit := max(budget, 1); p.Lines > limit {
				r, used = cutRun(p, limit), limit
				snap.LinesCut = true
			}
			budget -= used
			snap.Lines += used
			snap.Runs = append(snap.Runs, r)
		}
	}
	sort.SliceStable(snap.Runs, func(i, j int) bool { return snap.Runs[i].Start.After(snap.Runs[j].Start) })
	return snap, nil
}

// background is the Snapshot a LoadNow left a big read to. It ends when that read is published, which moves the
// revision the next look sees.
func (s *Store) background() {
	_, _ = s.Snapshot()
	s.mu.Lock()
	s.bg = false
	s.mu.Unlock()
}

// bump moves the revision with no run changed, so open pages ask for their regions again: a chain verdict the
// overview showed as still being verified has arrived, or a check found another verdict than the one kept, which
// open pages show (chain.go).
func (s *Store) bump() {
	s.mu.Lock()
	s.rev++
	s.mu.Unlock()
}

// cutRun is p read only as far as its first limit lines, as the line bound has it.
func cutRun(p *Run, limit int) *Run {
	all := p.AllEvents()
	if len(all) <= limit {
		return p
	}
	r := replay(p.ID, all[:limit], true, &all[len(all)-1])
	r.Live, r.Rev = p.Live, p.Rev
	return r
}

// Run brings one run up to date and returns it with its lines in memory. A malformed id or a missing run is
// os.ErrNotExist.
func (s *Store) Run(id string) (*Run, error) {
	if !validRunID(id) {
		return nil, os.ErrNotExist
	}
	live := s.liveRuns()[id] // before the events file, as in snapshot
	fi, err := os.Lstat(filepath.Join(s.root, id, "events.jsonl"))
	if err != nil || !fi.Mode().IsRegular() {
		return nil, os.ErrNotExist
	}
	s.mu.Lock()
	st := s.state(id)
	s.bring([]want{{st: st, seen: fi, live: live}}, true)
	s.touch(st)
	s.evict(st)
	p := st.pub
	s.mu.Unlock()
	if p.Events == nil && p.Lines > 0 {
		p.AllEvents()
		s.mu.Lock()
		p = st.pub
		s.mu.Unlock()
	}
	if p.Lines > MaxLines {
		return cutRun(p, MaxLines), nil
	}
	return p, nil
}

// Changed is the runs of the snapshot that changed after revision since: new lines, a new run, a run that ended or
// whose live state changed. A run that left the root is not listed; the snapshot's Rev still moved.
func (s *Snapshot) Changed(since uint64) []*Run {
	var out []*Run
	for _, r := range s.Runs {
		if r.Rev > since {
			out = append(out, r)
		}
	}
	return out
}
