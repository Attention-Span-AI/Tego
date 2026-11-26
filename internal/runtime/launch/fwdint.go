// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"encoding/binary"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Interrupt provenance (A51, ADR 0142). A user-scope run has two Tego processes in one job: the outer process that
// the person started and the launcher that systemd-run made in a new scope. They share a process group, so a
// group-directed INT (a terminal's Ctrl-C, a background job's `kill -INT -- -pgid`) reaches both, while
// `kill -INT <pid>` reaches one. The outer process used to forward every INT it saw to the launcher with kill(2), so a
// group-directed one arrived twice, and the second read as the person's deliberate repeat (the double-interrupt
// window escalates at once). os/signal hands a process the signal and no sender, so neither process can tell the
// cases apart alone.
//
// The two processes now count instead of signalling each other. Each counts the INT and QUIT arrivals it received
// itself, and the outer process tells the launcher its running count over one stream socket. The number of
// interrupts the pair has seen is, per signal, the larger of the two counts. The launcher acts on every increase of
// that number at once, so the first interrupt waits for nothing and the second acts when either count reaches two.
// Nothing but counts travels, and a count only grows, so no order between a signal, a report and anything else is
// relied on: an INT both processes received is one interrupt whichever arrives first, however late the other is
// read by its process or its report reaches the launcher, and no time window decides anything.
//
// What the rule cannot tell apart: one signal to each of the two processes sent separately (the launcher alone,
// then the outer process alone, in either order) is (1,1), the same two counts as one signal to the group, so it
// reads as one interrupt at any gap. A second signal to the same process is two. A signal a process coalesces with
// another that is still pending (os/signal and the kernel keep one pending bit per signal) is one arrival, so the
// counts are a lower bound; "at least one more since the last settle" is what they say.
//
// Frames: H (launcher to outer: I am listening), A (outer to launcher: so is the channel), N plus two uint64
// (outer to launcher: the outer process's running INT and QUIT counts). An outer process that has seen no H, or
// whose channel failed, still forwards with kill(2) as before. A peer that falls silent or whose channel closes
// counts as it last reported, and the launcher's own count still works alone. Both fall back to the old behaviour,
// never to a dropped interrupt.

// provenanceWait bounds a write to the peer. It does not pair anything; it only stops an unresponsive peer from
// holding the process back.
const provenanceWait = time.Second

// maxEmitted is the most interrupts of one kind the arbiter passes on for one arrival or report.
const maxEmitted = 2

const (
	frameHello = 'H'
	frameAck   = 'A'
	frameNote  = 'N'
)

// counts is the number of INT and QUIT arrivals a process has seen.
type counts [2]uint64

func interruptSlot(sig syscall.Signal) (int, bool) {
	switch sig {
	case syscall.SIGINT:
		return 0, true
	case syscall.SIGQUIT:
		return 1, true
	}
	return 0, false
}

var interruptSignals = [2]syscall.Signal{syscall.SIGINT, syscall.SIGQUIT}

// tally is the counting rule and nothing else: the launcher's own arrivals, the largest count the outer process has
// reported, and what has been acted on. It is pure, so its tests can run every order of arrivals and reports.
type tally struct {
	own, peer, acted counts
}

// arrival counts one INT or QUIT the launcher received itself.
func (t *tally) arrival(slot int) { t.own[slot]++ }

// report takes the outer process's running counts. A report never lowers a count, so a late or repeated one is
// harmless.
func (t *tally) report(c counts) {
	for i := range c {
		if c[i] > t.peer[i] {
			t.peer[i] = c[i]
		}
	}
}

// due returns, per signal, the interrupts the pair has seen since the last call: the larger of the two counts less
// what was acted on.
func (t *tally) due() counts {
	var n counts
	for i := range n {
		m := t.own[i]
		if t.peer[i] > m {
			m = t.peer[i]
		}
		n[i] = m - t.acted[i]
		t.acted[i] = m
	}
	return n
}

// Conn is the channel's stream: a nonblocking socket as an *os.File (so a deadline and a Close reach a blocked read and
// write), or any other stream with write deadlines.
type Conn interface {
	io.ReadWriteCloser
	SetWriteDeadline(time.Time) error
}

// frameWriter serialises the writes of one end: the reader goroutine acknowledges while the owner's loop notes.
type frameWriter struct {
	mu   sync.Mutex
	conn Conn
}

func (w *frameWriter) write(b []byte) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_ = w.conn.SetWriteDeadline(time.Now().Add(provenanceWait))
	_, err := w.conn.Write(b)
	return err
}

// Arbiter is the launcher's end: it turns the INT and QUIT deliveries of in, and the outer process's counts, into the
// interrupts the person made, and passes every other signal through.
type Arbiter struct {
	conn Conn
	in   <-chan os.Signal
	w    frameWriter

	out    chan os.Signal
	frames chan counts
	ready  chan struct{}
	done   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

// NewArbiter starts the launcher's end on conn. The caller reads Signals and calls Close when the run is over.
func NewArbiter(conn Conn, in <-chan os.Signal) *Arbiter {
	a := &Arbiter{conn: conn, in: in, w: frameWriter{conn: conn}, out: make(chan os.Signal, 16),
		frames: make(chan counts, 16), ready: make(chan struct{}), done: make(chan struct{})}
	a.wg.Add(2)
	go a.read()
	go a.run()
	return a
}

// Signals is the filtered stream.
func (a *Arbiter) Signals() <-chan os.Signal { return a.out }

// Ready is closed once the outer process has acknowledged the channel; it stays open if it never does.
func (a *Arbiter) Ready() <-chan struct{} { return a.ready }

// Close ends both goroutines and the channel and joins them.
func (a *Arbiter) Close() {
	a.once.Do(func() {
		close(a.done)
		_ = a.conn.Close()
	})
	a.wg.Wait()
}

func (a *Arbiter) read() {
	defer a.wg.Done()
	defer close(a.frames)
	for {
		var tag [1]byte
		if _, err := io.ReadFull(a.conn, tag[:]); err != nil {
			return
		}
		switch tag[0] {
		case frameAck:
			select {
			case <-a.ready:
			default:
				close(a.ready)
			}
		case frameNote:
			var b [16]byte
			if _, err := io.ReadFull(a.conn, b[:]); err != nil {
				return
			}
			select {
			case a.frames <- counts{binary.BigEndian.Uint64(b[:8]), binary.BigEndian.Uint64(b[8:])}:
			case <-a.done:
				return
			}
		default:
			// Not this protocol. The channel ends for both sides: closing it makes the outer process's next write
			// fail, so it stops counting for a launcher that no longer listens and forwards by signal again, and
			// the launcher counts its own arrivals alone. Left open, an interrupt sent to the outer process alone
			// would be written into a socket nobody reads and lost.
			_ = a.conn.Close()
			return
		}
	}
}

func (a *Arbiter) run() {
	defer a.wg.Done()
	defer close(a.out)
	if a.w.write([]byte{frameHello}) != nil {
		// No outer process listens: every arrival stands for itself.
		a.passThrough()
		return
	}
	var t tally
	frames := a.frames
	for {
		select {
		case <-a.done:
			return
		case s, ok := <-a.in:
			if !ok {
				return
			}
			sig, isSig := s.(syscall.Signal)
			slot, isInt := interruptSlot(sig)
			if !isSig || !isInt {
				if !a.emit(s, 1) {
					return
				}
				continue
			}
			t.arrival(slot)
		case c, ok := <-frames:
			if !ok {
				frames = nil // the peer counts as it last reported
				continue
			}
			t.report(c)
		}
		for i, n := range t.due() {
			// Two is all a run can use (the second interrupt forces the stop), so a count that jumped further,
			// such as a report written by another writer of the channel, does not hold the loop emitting.
			if !a.emit(interruptSignals[i], min(n, maxEmitted)) {
				return
			}
		}
	}
}

// passThrough forwards every signal unchanged once the channel could not be started.
func (a *Arbiter) passThrough() {
	for {
		select {
		case <-a.done:
			return
		case s, ok := <-a.in:
			if !ok || !a.emit(s, 1) {
				return
			}
		}
	}
}

func (a *Arbiter) emit(s os.Signal, n uint64) bool {
	for ; n > 0; n-- {
		select {
		case a.out <- s:
		case <-a.done:
			return false
		}
	}
	return true
}

// Gate is the outer process's end. Its owner calls Note for every INT or QUIT it receives.
type Gate struct {
	w    frameWriter
	live atomic.Bool
	done chan struct{}
	wg   sync.WaitGroup
	once sync.Once
	mu   sync.Mutex // orders Note's count with its frame
	seen counts
}

// NewGate starts the outer end on conn.
func NewGate(conn Conn) *Gate {
	g := &Gate{w: frameWriter{conn: conn}, done: make(chan struct{})}
	g.wg.Add(1)
	go g.read()
	return g
}

// Close ends the channel and joins its goroutine.
func (g *Gate) Close() {
	g.once.Do(func() {
		close(g.done)
		g.live.Store(false)
		_ = g.w.conn.Close()
	})
	g.wg.Wait()
}

func (g *Gate) read() {
	defer g.wg.Done()
	defer g.live.Store(false)
	for {
		var tag [1]byte
		if _, err := io.ReadFull(g.w.conn, tag[:]); err != nil {
			return
		}
		if tag[0] != frameHello {
			return // not this protocol: end it, and the owner forwards by signal again
		}
		g.live.Store(true)
		if g.w.write([]byte{frameAck}) != nil {
			return
		}
	}
}

// Note counts an INT or QUIT the outer process received and reports its running counts. It reports true when the
// launcher will judge it from the counts, and false when the owner must forward it itself because no launcher
// listens (or the signal is another).
func (g *Gate) Note(sig syscall.Signal) bool {
	i, ok := interruptSlot(sig)
	if !ok || !g.live.Load() {
		return false
	}
	g.mu.Lock()
	defer g.mu.Unlock()
	g.seen[i]++
	var b [17]byte
	b[0] = frameNote
	binary.BigEndian.PutUint64(b[1:9], g.seen[0])
	binary.BigEndian.PutUint64(b[9:], g.seen[1])
	if g.w.write(b[:]) != nil {
		g.live.Store(false)
		g.seen[i]--
		return false
	}
	return true
}
