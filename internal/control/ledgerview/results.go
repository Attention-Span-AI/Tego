// SPDX-License-Identifier: Apache-2.0

package ledgerview

import (
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/attention-span-ai/tego/internal/ledger"
)

// Result caches: the run page's heavy tabs (Receipt here; Least privilege and Unused in internal/control/rulesview)
// read the whole run with the strict decoder on every request, about 1 to 2 s for a run of 100k lines. A result is
// kept per run and reused while the run's events file is the same: its stamp (StampRun) is the file's device, inode,
// size and mtime, a digest of its last 4 KiB (so a file rewritten to the same size and mtime still differs) and
// whether the run is live. A caller adds what else its result reads (the contract copy, the chain anchor, the machine
// config) as the key. A run that gained a line is computed again; an ended run is computed once.
//
// A live run of a big ledger gains lines every second while its page refreshes itself, and computing its tab on
// every refresh would cost a core per viewer. So a live run's result that took at least liveCheap to compute is
// reused, though lines arrived since, as long as the rest of the key is the same and the file only grew: for
// liveEvery after it was finished, or twice what it cost when that is longer (a result that takes 3 s is computed at
// most once every 9 s, a third of one core however many viewers), and while another request is already computing
// the run's next one (so ten viewers start one computation, not ten). A result that is cheap (every run at the demo's
// scale) is never reused stale.
// Every result is dropped after maxResultAge in any case: what a result reads outside its key (a program installed on
// PATH, a dated contract entry that expired, a link under the ledger root) is seen within that time.

const (
	// tailStamp is how much of the end of the events file a stamp hashes: more than a line's envelope, so the last
	// line's id and seq are in it.
	tailStamp = 4 << 10
	// liveEvery is how long, at least, a live run's costly result is reused after it was finished while lines arrive
	// (twice its cost when that is longer).
	liveEvery = 2 * time.Second
	// liveCheap is the cost below which a live run's result is never reused stale.
	liveCheap = 250 * time.Millisecond
	// maxResultAge bounds every cached result's age.
	maxResultAge = 5 * time.Minute
)

// RunStamp is a run's events file as a cached result was computed from (StampRun). Comparable.
type RunStamp struct {
	events fileID
	tail   [sha256.Size]byte
	// Live is the run still being written: its lock held and its last line not run_end (ledger.State's running).
	Live bool
}

// StampRun is the stamp of run id's events file under root, read with the ledger's hardened open (no link followed,
// a regular file only); false when the run cannot be read, and a result is then computed uncached.
func StampRun(root, id string) (RunStamp, bool) {
	if !validRunID(id) {
		return RunStamp{}, false
	}
	dir := filepath.Join(root, id)
	// The lock is probed before the tail is read, as ledger.State does: a writer appends run_end and then releases
	// the lock, so a lock seen free means the tail read after it is final.
	held, herr := ledger.LockHeld(dir)
	f, err := ledger.OpenRegular(filepath.Join(dir, ledger.EventsFile))
	if err != nil {
		return RunStamp{}, false
	}
	defer func() { _ = f.Close() }() // opened read-only
	fi, err := f.Stat()
	if err != nil {
		return RunStamp{}, false
	}
	n := min(fi.Size(), tailStamp)
	buf := make([]byte, n)
	if m, err := f.ReadAt(buf, fi.Size()-n); (err != nil && !errors.Is(err, io.EOF)) || int64(m) != n {
		return RunStamp{}, false
	}
	return RunStamp{events: idOf(fi), tail: sha256.Sum256(buf), Live: herr == nil && held && !endsRun(buf)}, true
}

// endsRun reports whether the last terminated line in the tail b is run_end.
func endsRun(b []byte) bool {
	b = bytes.TrimSuffix(b, []byte{'\n'})
	if i := bytes.LastIndexByte(b, '\n'); i >= 0 {
		b = b[i+1:]
	}
	var head struct {
		Kind string `json:"kind"`
	}
	return json.Unmarshal(b, &head) == nil && head.Kind == "run_end"
}

// grewFrom reports whether s is the file of old, the same or longer: a live run's file that only had lines added.
func (s RunStamp) grewFrom(old RunStamp) bool {
	return s.events.dev == old.events.dev && s.events.ino == old.events.ino && s.events.size >= old.events.size
}

// Results is a bounded cache of one kind of result per run, most recently used kept: one entry per slot (a run), so
// the versions a live run goes through replace each other rather than fill it. K is the rest of the key besides the
// run's stamp. Safe for concurrent use; a value is shared by every caller that gets it and must not be modified.
type Results[K comparable, V any] struct {
	mu    sync.Mutex
	max   int
	timed bool // the result reads the clock while the run is live (a receipt's time taken)
	order *list.List
	slots map[string]*list.Element
	busy  map[string]int // the computations in flight per slot
	now   func() time.Time
	// computes counts the results computed, for tests.
	computes atomic.Int64
}

type resultEntry[K comparable, V any] struct {
	slot string
	run  RunStamp
	key  K
	val  V
	at   time.Time // when its computation started: the result holds at least what the file held then
	cost time.Duration
}

// done is when e's computation finished.
func (e *resultEntry[K, V]) done() time.Time { return e.at.Add(e.cost) }

// liveFor is how long after it finished a live run's costly result is reused while lines arrive.
func (e *resultEntry[K, V]) liveFor() time.Duration { return max(liveEvery, 2*e.cost) }

// NewResults is a cache of at most max results. timed marks a result that reads the clock while the run is live (the
// receipt's time taken to now): a live run's entry is then never reused as exact, only within liveEvery when costly.
func NewResults[K comparable, V any](max int, timed bool) *Results[K, V] {
	return &Results[K, V]{max: max, timed: timed, order: list.New(), slots: map[string]*list.Element{}, busy: map[string]int{},
		now: time.Now}
}

// Get is slot's result for the run as stamped and key, from the cache when it holds, else compute's. compute reports
// whether its result may be kept: a result that failed for a reason that passes (the request cancelled, a read
// error) is not.
func (c *Results[K, V]) Get(slot string, run RunStamp, key K, compute func() (V, bool)) V {
	c.mu.Lock()
	if el, ok := c.slots[slot]; ok {
		if e := el.Value.(*resultEntry[K, V]); c.usable(e, run, key) {
			c.order.MoveToFront(el)
			c.mu.Unlock()
			return e.val
		}
	}
	c.busy[slot]++
	c.mu.Unlock()
	c.computes.Add(1)
	start := c.now()
	v, keep := c.compute(slot, compute)
	if !keep {
		return v
	}
	e := &resultEntry[K, V]{slot: slot, run: run, key: key, val: v, at: start, cost: c.now().Sub(start)}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.slots[slot]; ok {
		if old := el.Value.(*resultEntry[K, V]); old.at.After(start) {
			return v // a computation that started later already stored a result at least as new
		}
		el.Value = e
		c.order.MoveToFront(el)
		return v
	}
	c.slots[slot] = c.order.PushFront(e)
	for c.order.Len() > c.max {
		back := c.order.Back()
		delete(c.slots, back.Value.(*resultEntry[K, V]).slot)
		c.order.Remove(back)
	}
	return v
}

// compute runs f with slot marked busy until it returns (or panics).
func (c *Results[K, V]) compute(slot string, f func() (V, bool)) (V, bool) {
	defer func() {
		c.mu.Lock()
		if c.busy[slot]--; c.busy[slot] <= 0 {
			delete(c.busy, slot)
		}
		c.mu.Unlock()
	}()
	return f()
}

// usable reports whether e answers for run and key now. Called with c.mu held.
func (c *Results[K, V]) usable(e *resultEntry[K, V], run RunStamp, key K) bool {
	now := c.now()
	age := now.Sub(e.at)
	if age < 0 || age >= maxResultAge || e.key != key {
		return false
	}
	if e.run == run && !(c.timed && run.Live) {
		return true
	}
	if !run.Live || !e.run.Live || e.cost < liveCheap || !run.grewFrom(e.run) {
		return false
	}
	return now.Sub(e.done()) < e.liveFor() || c.busy[e.slot] > 0
}

// Computes is how many results the cache computed, for tests in other packages.
func (c *Results[K, V]) Computes() int64 { return c.computes.Load() }
