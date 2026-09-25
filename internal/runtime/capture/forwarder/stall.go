// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"sync"
	"time"
)

// DefaultWriteStallTimeout is how long one chunk of a response may take to reach the client before the exchange
// gives its record copy back to the capture budget. R27 leaves the response without a deadline, so a
// client that stops reading holds its relay, and without this the relay held its copy as well: up to MaxBody of
// the budget each, so eight stalled responses at the defaults held all of it, and every later exchange of the run
// was recorded without a body and, where no usage could be read off the wire, reported unmetered, which ends a run
// with a token or cost budget. Thirty seconds is the request side's own figure (DefaultBodyIdleTimeout): a client
// reading a response as an SDK does takes each 32 KiB chunk within milliseconds, so a chunk still unwritten this
// long later is a client that is not reading. Nothing else changes: the relay keeps writing for as long as the
// client lets it, and only the record's copy ends, cut as a full budget cuts it (gap why=size-cap).
const DefaultWriteStallTimeout = 30 * time.Second

// stallGuard watches one relay's writes to the client and gives the record's copy back to the budget when a write
// stays unfinished for after. arm is called before each write and disarm after it, on the relay's goroutine; the
// timer's callback runs on its own, and touches the copy only while a write is armed, which is when the relay is
// not touching it, and under mu, which orders the two.
type stallGuard struct {
	after    time.Duration
	captured *held

	mu       sync.Mutex
	timer    *time.Timer
	armed    bool
	released bool
}

// arm starts the clock on one write.
func (g *stallGuard) arm() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.released {
		return // nothing left to give back
	}
	g.armed = true
	if g.timer == nil {
		g.timer = time.AfterFunc(g.after, g.fire)
		return
	}
	g.timer.Reset(g.after)
}

// disarm stops the clock once the write has returned, and reports whether the copy has been given back, by this
// write's stall or an earlier one's.
func (g *stallGuard) disarm() bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.armed = false
	if g.timer != nil {
		g.timer.Stop()
	}
	return g.released
}

// fire is the timer's callback. A callback that lost the race with disarm finds the guard disarmed and does
// nothing; one that lost it with disarm and a new arm fires into the next write early, which only happens when
// the last write took the whole timeout, so a copy is never given back for a client that is keeping up.
func (g *stallGuard) fire() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if !g.armed || g.released {
		return
	}
	g.captured.drop()
	g.released = true
}

// stop ends the guard; it is disarm with nothing to report.
func (g *stallGuard) stop() { _ = g.disarm() }
