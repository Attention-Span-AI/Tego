// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/attention-span-ai/tego/internal/check/mirror"
	"github.com/attention-span-ai/tego/internal/ledger"
)

// MaxResidentBytes bounds the decoded lines the read model keeps (an estimate, eventBytes). Past it, the lines of the
// least recently used runs (live or ended) are dropped (their summaries, counts and asks stay) and read again from the
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
	// Source failures move the revision independently of cached record data.
	scanError     string
	scanLiveError string
	rootSeen      bool
	rootIdentity  os.FileInfo
	// recordEvidence remembers observed record files or recorded-line evidence for the store’s lifetime.
	recordEvidence map[string]bool
	anchor         string
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
			probes: map[string]lockProbe{}, recordEvidence: map[string]bool{}}
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
		if len(s.runs) >= MaxRuns {
			for key, old := range s.runs {
				if old.reading == nil {
					if old.resident {
						s.resident -= old.bytes
					}
					delete(s.runs, key)
					break
				}
			}
		}
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
// to under 2 s; docs/development/dashboard.md, "Cold start", has the numbers.

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
	if w.seen != nil {
		if s.recordEvidence == nil {
			s.recordEvidence = map[string]bool{}
		}
		s.recordEvidence[w.st.id] = true
	}
	w.st.reading = make(chan struct{})
	return &job{want: w, before: w.st.bytes, wasResident: w.st.resident}
}

// stale reports whether st must be read for seen: never read, or its events file is not the one it read. After
// waiting for another request's read (again), a file that read saw at least as far (the same identity, no larger,
// no newer mtime or ctime) is enough, so a request does not read twice what another just read. s.mu must be held and
// st not claimed.
func stale(st *runState, seen os.FileInfo, again bool) bool {
	if st.pub == nil || st.b.ReadError != "" {
		return true
	}
	if seen == nil {
		return !st.resident
	}
	now := idOf(seen)
	if now == st.file {
		return st.racy && !again // a racy file's unchanged stamps tell nothing, unless a read just made saw it as it is
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
			s.readOne(j)
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
				s.readOne(j)
			}
		}()
	}
	for _, j := range jobs {
		next <- j
	}
	close(next)
	wg.Wait()
}

// Publish and evict each finished cold read immediately. Keeping all completed
// jobs until the entire root finished would retain every run before eviction.
func (s *Store) readOne(j *job) {
	j.changed, j.err = s.read(j.st, j.seen)
	s.mu.Lock()
	s.finish(j)
	s.evict(nil)
	s.mu.Unlock()
}

// finish publishes a read run, under a new revision when anything a page shows changed, and ends its claim. s.mu
// must be held.
func (s *Store) finish(j *job) {
	st := j.st
	if st.off > 0 || st.file.size > 0 {
		if s.recordEvidence == nil {
			s.recordEvidence = map[string]bool{}
		}
		s.recordEvidence[st.id] = true
	}
	changed := j.changed
	var refusal *rereadRefusal
	if errors.As(j.err, &refusal) {
		changed = st.refuseReread(refusal) || changed
	} else {
		if j.err == nil && st.rereadErr != nil {
			st.rereadErr = nil
		}
		// A failed read is kept apart from malformed lines (Bad): ReadError holds the last reader failure and a
		// successful read clears it.
		readError := ""
		if j.err != nil {
			readError = j.err.Error()
		}
		if st.b.ReadError != readError {
			st.b.ReadError = readError
			changed = true
		}
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

// evict drops the lines of the least recently used runs until the resident estimate is under
// MaxResidentBytes, never those of keep or of a run being read. s.mu must be held.
func (s *Store) evict(keep *runState) {
	if s.resident <= MaxResidentBytes {
		return
	}
	var cands []*runState
	for _, st := range s.runs {
		if st.reading == nil && st.resident && st != keep && st.bytes > 0 {
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
		st.pairs = mirror.Pairs{}
		st.b.Events = nil
		signalMu.Lock()
		delete(signalCache, st.id)
		signalMu.Unlock()
		st.prog.Store(nil)
		s.rev++
		st.publish(s.rev) // root views now disclose that this window is absent
	}
}

// lines returns st's lines, reading them again from the file when they were evicted. The read runs outside s.mu
// under st's claim, as bring's reads do.
func (s *Store) lines(st *runState) []Event {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs[st.id] != st {
		return nil
	} // a pruned old version cannot repopulate the store
	for st.reading != nil {
		ch := st.reading
		s.mu.Unlock()
		<-ch
		s.mu.Lock()
	}
	if !st.resident {
		st.reading = make(chan struct{})
		s.mu.Unlock()
		err := st.loadWindow()
		s.mu.Lock()
		changed := true
		if err != nil {
			changed = st.refuseReread(err)
		} else if st.off >= st.file.size {
			// Rehydrating a prefix cannot clear an error reading its suffix.
			st.rereadErr = nil
			st.b.ReadError = ""
		}
		s.resident += st.bytes
		if changed {
			s.rev++ // the retained window's visibility or refusal changed
			st.publish(s.rev)
		}
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

// heldEvents is AllEvents without the read: the run's lines when they are in memory, else nil.
func (r *Run) heldEvents() []Event {
	if r.Events != nil || r.st == nil || r.Lines == 0 {
		return r.Events
	}
	s := r.st.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.runs[r.st.id] != r.st || !r.st.resident {
		return nil
	}
	return r.st.pub.Events
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
	live, liveErr := s.liveRuns()
	if liveErr != nil && !errors.Is(liveErr, fs.ErrNotExist) {
		snap.LiveError = liveErr.Error()
	}
	var ents []os.DirEntry
	err := s.checkRootIdentity()
	if err == nil {
		ents, err = os.ReadDir(s.root)
	}
	if err == nil {
		s.mu.Lock()
		s.rootSeen = true
		s.mu.Unlock()
	}
	if err != nil {
		s.mu.Lock()
		known := s.rootSeen || len(s.recordEvidence) > 0
		snap.Rev = s.rev
		s.mu.Unlock()
		if !known {
			if errors.Is(err, os.ErrNotExist) {
				return snap, nil
			}
			return nil, fmt.Errorf("read ledger root: %w", err)
		}
		// A failed root read can hide unobserved runs as well as remembered
		// requests. Use the same immutable-prefix path for every failure shape.
		snap.ReadError = fmt.Errorf("read ledger root: %w", err).Error()
		snap.ReadErrorListed = false
	}
	type cand struct {
		id        string
		fi        os.FileInfo
		failed    bool
		readError string
	}
	var cands []cand
	var unknownMissing []string
	present := map[string]bool{}
	addFailure := func(id, reason string) {
		present[id] = true
		cands = append(cands, cand{id: id, failed: true, readError: reason})
		if snap.ReadError == "" {
			snap.ReadError = reason
			snap.ReadErrorListed = true
		}
	}
	addMissing := func(id string) { addFailure(id, missingRecord(id)) }
	for _, e := range ents {
		if !e.IsDir() || !strings.HasPrefix(e.Name(), "r-") || e.Type()&os.ModeSymlink != 0 {
			continue
		}
		present[e.Name()] = true
		fi, err := os.Lstat(filepath.Join(s.root, e.Name(), "events.jsonl"))
		if errors.Is(err, fs.ErrNotExist) {
			if s.hasRecordEvidence(e.Name()) {
				addMissing(e.Name())
			} else {
				unknownMissing = append(unknownMissing, e.Name())
			}
			continue
		}
		if err != nil || !fi.Mode().IsRegular() {
			reason := recordReadFailure(s.root, e.Name(), err)
			if s.hasRecordEvidence(e.Name()) {
				addFailure(e.Name(), reason)
			} else {
				if snap.ReadError == "" || snap.ReadErrorListed {
					snap.ReadError = reason
				}
				snap.ReadErrorListed = false
			}
			continue
		}
		cands = append(cands, cand{id: e.Name(), fi: fi})
		present[e.Name()] = true
	}
	// The index also associates a run ID with this root after its directory is
	// gone. A positive chain head can then establish the missing recorded source.
	s.liveMu.Lock()
	var indexedMissing []string
	for id := range s.probes {
		if validRunID(id) && !present[id] {
			indexedMissing = append(indexedMissing, id)
		}
	}
	s.liveMu.Unlock()
	for _, id := range indexedMissing {
		if _, err := os.Lstat(filepath.Join(s.root, id)); errors.Is(err, fs.ErrNotExist) && !s.hasRecordEvidence(id) {
			unknownMissing = append(unknownMissing, id)
		}
	}
	// A directory disappearing cannot erase a previously observed record source.
	s.mu.Lock()
	var vanished []string
	for id := range s.recordEvidence {
		if !present[id] {
			vanished = append(vanished, id)
		}
	}
	s.mu.Unlock()
	for _, id := range vanished {
		present[id] = true
		if err != nil {
			addFailure(id, snap.ReadError)
		} else {
			addMissing(id)
		}
	}
	if len(unknownMissing) > 0 {
		heads := anchorHeadsNow(s.anchorPath(unknownMissing[0]), unknownMissing...)
		for i, h := range heads {
			if h.OK {
				s.rememberRecordEvidence(unknownMissing[i])
				present[unknownMissing[i]] = true
				addMissing(unknownMissing[i])
			} else if h.Err != nil {
				addFailure(unknownMissing[i], missingEvidenceError(unknownMissing[i], h.Err))
			}
		}
	}
	snap.TotalRuns = len(cands)
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].failed != cands[j].failed {
			return cands[i].failed
		}
		if cands[i].failed {
			return cands[i].id < cands[j].id
		}
		if mi, mj := cands[i].fi.ModTime(), cands[j].fi.ModTime(); !mi.Equal(mj) {
			return mi.After(mj)
		}
		// Files written within one clock tick carry the same time on some kernels: cut them by a fixed order,
		// not by listing order, so the same ledger keeps the same runs on every machine and every look.
		return cands[i].id > cands[j].id
	})
	if len(cands) > MaxRuns {
		cands = cands[:MaxRuns]
		snap.RunsCut = true
	}
	selected := map[string]bool{}
	for _, c := range cands {
		selected[c.id] = true
	}
	pubs := make([]*Run, 0, len(cands))
	s.mu.Lock()
	for id, st := range s.runs {
		if (!present[id] || !selected[id]) && st.reading == nil { // a run being read leaves on a later look
			if st.resident {
				s.resident -= st.bytes
			}
			delete(s.runs, id)
			s.rev++
		}
	}
	ws := make([]want, 0, len(cands))
	for _, c := range cands {
		if c.failed {
			st := s.state(c.id)
			pubs = append(pubs, s.publishReadFailure(st, live[c.id], wait, c.readError))
		} else {
			ws = append(ws, want{st: s.state(c.id), seen: c.fi, live: live[c.id]})
		}
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
	// No index is normal before any recorded run. Complete ended runs cannot
	// hold an actionable request either. Unfinished or omitted records can, so
	// a missing index there remains a read failure even after a dashboard restart.
	if errors.Is(liveErr, fs.ErrNotExist) {
		couldWait := snap.Partial || snap.RunsCut
		for _, p := range pubs {
			couldWait = couldWait || !p.Ended
		}
		if couldWait {
			snap.LiveError = liveErr.Error()
		}
	}
	if s.scanError != snap.ReadError || s.scanLiveError != snap.LiveError {
		s.scanError, s.scanLiveError = snap.ReadError, snap.LiveError
		s.rev++
	}
	for i, p := range pubs {
		pubs[i] = liveFailureView(s.runs[p.ID], p, snap.LiveError, s.rev)
	}
	snap.Rev = s.rev
	if deferred && !s.bg {
		s.bg = true
		go s.background()
	}
	s.mu.Unlock()

	total := 0
	for _, p := range pubs {
		snap.LinesCut = snap.LinesCut || p.Cut
		total += len(p.Events)
	}
	if total <= MaxLines {
		snap.Runs, snap.Lines = pubs, total
	} else {
		budget := MaxLines
		for _, p := range pubs {
			r, used := p, len(p.Events)
			if limit := max(budget, 0); len(p.Events) > limit {
				r, used = cutRun(p, limit), limit
				snap.LinesCut = true
			}
			budget -= used
			snap.Lines += used
			snap.Runs = append(snap.Runs, r)
		}
	}
	// A root request does not rehydrate every evicted run and pin every derived
	// index in its snapshot. Individual run pages rehydrate one bounded window.
	for i, p := range snap.Runs {
		if p.Events == nil && p.Lines > 0 {
			r := *p
			r.st = nil
			r.Cut = true
			r.memo = &runMemo{}
			snap.Runs[i] = &r
			snap.LinesCut = true
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

// cutRun limits the event window while preserving the full incremental summary.
func cutRun(p *Run, limit int) *Run {
	all := p.AllEvents()
	if len(all) <= limit {
		return p
	}
	r := *p
	r.Events = all[len(all)-limit:]
	r.Cut = true
	r.memo = &runMemo{}
	return &r
}

// Run brings one run up to date and returns it with its lines in memory. A malformed id or a missing run is
// os.ErrNotExist unless observed-source or recorded-line evidence makes its absence a read failure.
func (s *Store) Run(id string) (*Run, error) {
	if !validRunID(id) {
		return nil, os.ErrNotExist
	}
	if err := s.checkRootIdentity(); err != nil {
		s.mu.Lock()
		st := s.runs[id]
		if st == nil || st.pub == nil {
			s.mu.Unlock()
			return nil, err
		}
		p := s.publishReadFailure(st, st.pub.Live, true, fmt.Errorf("read ledger root: %w", err).Error())
		s.mu.Unlock()
		return s.withLiveFailure(p, err), nil
	}
	lives, liveErr := s.liveRuns() // before the events file, as in snapshot
	live := lives[id]
	fi, err := os.Lstat(filepath.Join(s.root, id, "events.jsonl"))
	if errors.Is(err, fs.ErrNotExist) {
		if reason := s.missingFailure(id); reason != "" {
			s.mu.Lock()
			st := s.state(id)
			p := s.publishReadFailure(st, live, true, reason)
			s.mu.Unlock()
			return s.withLiveFailure(p, liveErr), nil
		}
	}
	if err != nil || !fi.Mode().IsRegular() {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, os.ErrNotExist
		}
		s.mu.Lock()
		st := s.state(id)
		p := s.publishReadFailure(st, live, true, recordReadFailure(s.root, id, ledger.WithModeAdvice(filepath.Join(s.root, id), err)))
		s.mu.Unlock()
		return s.withLiveFailure(p, liveErr), nil
	}
	s.mu.Lock()
	st := s.state(id)
	s.bring([]want{{st: st, seen: fi, live: live}}, true)
	s.touch(st)
	s.evict(st)
	p, readErr := st.pub, st.rereadErr
	s.mu.Unlock()
	if readErr != nil {
		return nil, readErr
	}
	if p.Events == nil && p.Lines > 0 {
		p.AllEvents()
		s.mu.Lock()
		p, readErr = st.pub, st.rereadErr
		s.mu.Unlock()
		if readErr != nil {
			return nil, readErr
		}
	}
	p = s.withLiveFailure(p, liveErr)
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

// readError keeps a root snapshot's published refusals and also checks lazy
// consumers of an older, evicted snapshot against the Store's latest refusal.
func (r *Run) readError() error {
	if len(r.LineErrors) > 0 {
		var refusals []error
		for _, refusal := range r.LineErrors {
			refusals = append(refusals, errors.New(refusal.Reason))
		}
		return errors.Join(refusals...)
	}
	if r.ReadError != "" {
		return errors.New(r.ReadError)
	}
	if r.StartError != "" {
		return errors.New(r.StartError)
	}
	if r.st == nil || r.st.store == nil {
		return nil
	}
	s := r.st.store
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.st.rereadErr != nil {
		return r.st.rereadErr
	}
	return nil
}

// SetAnchor names the same chain anchor the dashboard verifies, for missing-record evidence.
func (s *Store) SetAnchor(path string) { s.mu.Lock(); s.anchor = path; s.mu.Unlock() }

func missingRecord(id string) string { return "read run " + id + ": its record file is missing" }

func recordReadFailure(root, id string, err error) string {
	if RootLaunched(root, id, err) {
		return RootLaunchedWords(id)
	}
	if err != nil {
		return fmt.Errorf("read run %s: %w", id, err).Error()
	}
	return fmt.Sprintf("read run %s: events.jsonl is not a regular file", id)
}

// hasRecordEvidence accepts a previously observed record file (even if empty), or evidence of lines.
// A file observed empty could have gained lines before it vanished. A contract copy and a lock precede the
// first event, so neither distinguishes an empty run after a dashboard restart.
func (s *Store) hasRecordEvidence(id string) bool {
	s.mu.Lock()
	known := s.recordEvidence[id]
	if st := s.runs[id]; st != nil && st.pub != nil {
		known = known || st.pub.Lines > 0 || st.pub.Bad > 0
	}
	s.mu.Unlock()
	if known {
		return true
	}
	fi, err := os.Lstat(filepath.Join(s.root, id, ledger.LastRefusalFile))
	positive := err == nil && fi.Mode().IsRegular() && fi.Size() > 0
	if positive {
		s.rememberRecordEvidence(id)
	}
	return positive
}

func (s *Store) anchorPath(id string) string {
	s.mu.Lock()
	anchor := s.anchor
	s.mu.Unlock()
	if anchor == "" {
		anchor = ledger.DefaultAnchorPath(filepath.Join(s.root, id))
	}
	return anchor
}

func (s *Store) rememberRecordEvidence(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.recordEvidence == nil {
		s.recordEvidence = map[string]bool{}
	}
	s.recordEvidence[id] = true
}

func missingEvidenceError(id string, err error) string {
	return missingRecord(id) + "; could not check chain evidence: " + err.Error()
}

func (s *Store) missingFailure(id string) string {
	if s.hasRecordEvidence(id) {
		return missingRecord(id)
	}
	// The account-wide chain needs a root association: a surviving directory
	// or a live-index entry. A foreign ID with neither cannot invent a run here.
	if fi, err := os.Lstat(filepath.Join(s.root, id)); err != nil || !fi.IsDir() {
		if !errors.Is(err, fs.ErrNotExist) {
			return ""
		}
		s.liveMu.Lock()
		_, indexed := s.probes[id]
		s.liveMu.Unlock()
		if !indexed {
			return ""
		}
	}
	head := anchorHeadsNow(s.anchorPath(id), id)[0]
	if head.OK {
		s.rememberRecordEvidence(id)
		return missingRecord(id)
	}
	if head.Err != nil {
		return missingEvidenceError(id, head.Err)
	}
	return ""
}

// publishReadFailure retains known requests and counters, with an explicit read
// failure. Waiting for an in-flight decoder prevents a second writer to its state.
func (s *Store) publishReadFailure(st *runState, live, wait bool, reason string) *Run {
	if st.reading != nil && !wait {
		p := Run{ID: st.id}
		if st.pub != nil {
			p = *st.pub
		}
		p.ReadError = reason
		p.Live = live && !p.Ended
		p.Rev = s.rev
		return &p
	}
	for st.reading != nil {
		ch := st.reading
		s.mu.Unlock()
		<-ch
		s.mu.Lock()
	}
	if st.pub == nil || st.b.ReadError != reason || st.live != live {
		st.b.ReadError = reason
		st.live = live
		s.rev++
		st.publish(s.rev)
	}
	return st.pub
}

// withLiveFailure keeps record counters readable while qualifying unknown liveness.
func (s *Store) withLiveFailure(p *Run, err error) *Run {
	if p == nil || p.Ended {
		return p
	}
	reason := ""
	if err != nil {
		reason = err.Error()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return liveFailureView(s.runs[p.ID], p, reason, s.rev)
}

// liveFailureView needs the store mutex. Its immutable view is reused until the
// record or reason changes. Publish releases it; an older request cannot cache
// an evicted version. Clearing the reason also moves the row's revision.
func liveFailureView(st *runState, p *Run, reason string, rev uint64) *Run {
	if p == nil || p.Ended {
		return p
	}
	if st != nil && st.pub != p {
		st = nil
	}
	if st != nil && st.liveSource == p && st.liveView != nil && st.liveView.LiveError == reason {
		return st.liveView
	}
	if reason == "" && (st == nil || st.liveView == nil) {
		return p
	}
	cp := *p
	cp.LiveError, cp.Rev = reason, rev
	if st != nil {
		st.liveSource, st.liveView = p, &cp
	}
	return &cp
}

// checkRootIdentity pins the directory that this process first reads. A readable
// replacement is still a failure: its index cannot retire this root's requests.
func (s *Store) checkRootIdentity() error {
	fi, err := os.Stat(s.root)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.rootIdentity != nil && !os.SameFile(s.rootIdentity, fi) {
		return errors.New("the record folder changed")
	}
	if fi.IsDir() && s.rootIdentity == nil {
		s.rootIdentity = fi
	}
	return nil
}
