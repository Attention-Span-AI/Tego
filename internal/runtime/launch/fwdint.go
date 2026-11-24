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
// group-directed INT (a background job's `kill -INT -- -pgid`) reaches both, while `kill -INT <pid>` reaches one.
// The outer process used to forward every INT it saw to the launcher with kill(2), so a group-directed one arrived
// twice, and the second read as the person's deliberate repeat (the double-interrupt window escalates at once).
// os/signal hands a process the signal and no sender, so neither process can tell the cases apart alone.
//
// The two processes now ask each other instead of signalling each other. Both count the INT and QUIT arrivals they
// see. The launcher, after each arrival of its own or a note from the outer process, drains its pending signals
// behind a marker it sends itself, asks the outer process (which does the same) for its counts, and takes for each
// signal the larger of the two new counts: an INT both saw is one interrupt, one that only one saw is one interrupt,
// and two separate sends are two. No time window decides anything. The arrivals are paired only by their counts, so
// two deliberate sends to two different processes within one round trip (microseconds) read as one interrupt.
//
// The channel is one stream socket. Frames: H (launcher to outer: I am listening), A (outer to launcher: so is
// the channel), N (outer to launcher: I counted an arrival), Q (launcher to outer: your counts), R plus two
// uint64 (outer to launcher: INT then QUIT). An outer process that has seen no H, or whose channel failed, still
// forwards with kill(2) as before, and a launcher whose outer process does not answer in provenanceWait counts its
// own arrivals alone. Both fall back to the old behaviour, never to a dropped interrupt.

// interruptMarker is the signal a process sends itself to know every earlier arrival has been read: the first
// real-time signal numbers the Go runtime and the C library leave to programs, queued behind INT and QUIT.
const interruptMarker = syscall.Signal(40)

// provenanceWait bounds every wait on the peer and on the marker. It does not pair anything; it only stops an
// unresponsive peer from holding an interrupt back.
const provenanceWait = time.Second

const (
	frameHello = 'H'
	frameAck   = 'A'
	frameNote  = 'N'
	frameQuery = 'Q'
	frameReply = 'R'
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

func sendMarker() error { return syscall.Kill(os.Getpid(), interruptMarker) }

// Conn is the channel's stream: a nonblocking socket as an *os.File (so a deadline and a Close reach a blocked read and
// write), or any other stream with write deadlines.
type Conn interface {
	io.ReadWriteCloser
	SetWriteDeadline(time.Time) error
}

// frameWriter serialises the writes of one end: the reader goroutine acknowledges while the main loop answers.
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

// Arbiter is the launcher's end: it turns the INT and QUIT deliveries of in, and the outer process's notes, into the
// interrupts the person made, and passes every other signal through.
type Arbiter struct {
	conn Conn
	in   <-chan os.Signal
	mark func() error
	w    frameWriter

	out    chan os.Signal
	frames chan arbiterFrame
	ready  chan struct{}
	done   chan struct{}
	wg     sync.WaitGroup
	once   sync.Once
}

type arbiterFrame struct {
	tag   byte
	count counts
}

// NewArbiter starts the launcher's end on conn. in must also deliver interruptMarker (NotifyMarked); mark nil sends
// it to this process. The caller reads Signals and calls Close when the run is over.
func NewArbiter(conn Conn, in <-chan os.Signal, mark func() error) *Arbiter {
	if mark == nil {
		mark = sendMarker
	}
	a := &Arbiter{conn: conn, in: in, mark: mark, w: frameWriter{conn: conn}, out: make(chan os.Signal, 16),
		frames: make(chan arbiterFrame, 16), ready: make(chan struct{}), done: make(chan struct{})}
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
		f, err := readFrame(a.conn)
		if err != nil {
			return
		}
		if f.tag == frameAck {
			select {
			case <-a.ready:
			default:
				close(a.ready)
			}
			continue
		}
		select {
		case a.frames <- f:
		case <-a.done:
			return
		}
	}
}

func readFrame(r io.Reader) (arbiterFrame, error) {
	var tag [1]byte
	if _, err := io.ReadFull(r, tag[:]); err != nil {
		return arbiterFrame{}, err
	}
	f := arbiterFrame{tag: tag[0]}
	if f.tag == frameReply {
		var b [16]byte
		if _, err := io.ReadFull(r, b[:]); err != nil {
			return arbiterFrame{}, err
		}
		f.count[0] = binary.BigEndian.Uint64(b[:8])
		f.count[1] = binary.BigEndian.Uint64(b[8:])
	}
	return f, nil
}

type arbiterState struct {
	seen, accSeen, accOuter counts
	broken                  bool
}

func (a *Arbiter) run() {
	defer a.wg.Done()
	defer close(a.out)
	if a.w.write([]byte{frameHello}) != nil {
		// No outer process listens: every arrival stands for itself.
		a.passThrough()
		return
	}
	var st arbiterState
	frames := a.frames
	for {
		dirty := false
		select {
		case <-a.done:
			return
		case s, ok := <-a.in:
			if !ok {
				return
			}
			dirty = a.arrival(&st, s)
		case f, ok := <-frames:
			if !ok {
				st.broken = true
				frames = nil
				continue
			}
			dirty = f.tag == frameNote
		}
		for dirty {
			dirty = a.resolve(&st)
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

// arrival counts an INT or QUIT, drops a stray marker and passes anything else on. It reports whether a
// resolution is due.
func (a *Arbiter) arrival(st *arbiterState, s os.Signal) bool {
	sig, ok := s.(syscall.Signal)
	if !ok {
		a.emit(s, 1)
		return false
	}
	if sig == interruptMarker {
		return false
	}
	i, isInt := interruptSlot(sig)
	if !isInt {
		a.emit(s, 1)
		return false
	}
	st.seen[i]++
	return true
}

// resolve settles what the counts say since the last one and reports whether more arrivals came meanwhile.
func (a *Arbiter) resolve(st *arbiterState) bool {
	if st.broken {
		a.settle(st, st.seen, st.accOuter)
		return false
	}
	a.drain(st)
	snap := st.seen
	outer, ok := a.ask(st)
	if !ok {
		st.broken = true
		outer = st.accOuter
	}
	a.settle(st, snap, outer)
	return st.seen != st.accSeen
}

// settle emits, per signal, the larger of the arrivals each side counted since the last settle.
func (a *Arbiter) settle(st *arbiterState, seen, outer counts) {
	for i, sig := range interruptSignals {
		mine, theirs := seen[i]-st.accSeen[i], outer[i]-st.accOuter[i]
		st.accSeen[i], st.accOuter[i] = seen[i], outer[i]
		n := mine
		if theirs > n {
			n = theirs
		}
		if !a.emit(sig, n) {
			return
		}
	}
}

// drain reads in until this process's own marker comes back, so the arrivals already delivered are counted.
func (a *Arbiter) drain(st *arbiterState) {
	if a.mark() != nil {
		return
	}
	timer := time.NewTimer(provenanceWait)
	defer timer.Stop()
	for {
		select {
		case s, ok := <-a.in:
			if !ok {
				return
			}
			if sig, isSig := s.(syscall.Signal); isSig && sig == interruptMarker {
				return
			}
			a.arrival(st, s)
		case <-timer.C:
			return
		case <-a.done:
			return
		}
	}
}

// ask returns the outer process's counts, or false when it does not answer.
func (a *Arbiter) ask(st *arbiterState) (counts, bool) {
	if a.w.write([]byte{frameQuery}) != nil {
		return counts{}, false
	}
	timer := time.NewTimer(provenanceWait)
	defer timer.Stop()
	for {
		select {
		case f, ok := <-a.frames:
			if !ok {
				return counts{}, false
			}
			if f.tag == frameReply {
				return f.count, true
			}
			// A note ahead of the reply is part of it: the outer process wrote it first.
		case s, ok := <-a.in:
			if !ok {
				return counts{}, false
			}
			a.arrival(st, s) // counted now, settled by the next round
		case <-timer.C:
			return counts{}, false
		case <-a.done:
			return counts{}, false
		}
	}
}

// Gate is the outer process's end. Its owner calls Note for every INT or QUIT it receives and answers Queries().
type Gate struct {
	w       frameWriter
	live    atomic.Bool
	queries chan struct{}
	done    chan struct{}
	wg      sync.WaitGroup
	once    sync.Once
	mark    func() error
	seen    counts // read and written only by the owner's loop
}

// NewGate starts the outer end on conn. mark nil sends interruptMarker to this process.
func NewGate(conn Conn, mark func() error) *Gate {
	if mark == nil {
		mark = sendMarker
	}
	g := &Gate{w: frameWriter{conn: conn}, queries: make(chan struct{}, 1), done: make(chan struct{}), mark: mark}
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

// Queries yields once per question of the launcher; answer each with Answer.
func (g *Gate) Queries() <-chan struct{} { return g.queries }

func (g *Gate) read() {
	defer g.wg.Done()
	defer g.live.Store(false)
	for {
		f, err := readFrame(g.w.conn)
		if err != nil {
			return
		}
		switch f.tag {
		case frameHello:
			g.live.Store(true)
			if g.w.write([]byte{frameAck}) != nil {
				return
			}
		case frameQuery:
			select {
			case g.queries <- struct{}{}:
			default: // the launcher asks one question at a time
			}
		default:
			return // not this protocol: end it, and the owner forwards by signal again
		}
	}
}

// Note counts an INT or QUIT the outer process received. It reports true when the launcher will judge it from the
// counts, and false when the owner must forward it itself because no launcher listens (or the signal is another).
func (g *Gate) Note(sig syscall.Signal) bool {
	i, ok := interruptSlot(sig)
	if !ok || !g.live.Load() {
		return false
	}
	g.seen[i]++
	if g.w.write([]byte{frameNote}) != nil {
		g.live.Store(false)
		g.seen[i]--
		return false
	}
	return true
}

// Answer reads in behind a marker so the arrivals already delivered are counted, then replies with the counts. It
// returns every other signal it read, for the owner to handle as it would have.
func (g *Gate) Answer(in <-chan os.Signal) []os.Signal {
	var others []os.Signal
	if g.mark() == nil {
		timer := time.NewTimer(provenanceWait)
		defer timer.Stop()
	drain:
		for {
			select {
			case s, ok := <-in:
				if !ok {
					break drain
				}
				sig, isSig := s.(syscall.Signal)
				if isSig && sig == interruptMarker {
					break drain
				}
				if i, isInt := interruptSlot(sig); isSig && isInt {
					g.seen[i]++
					continue
				}
				others = append(others, s)
			case <-timer.C:
				break drain
			case <-g.done:
				break drain
			}
		}
	}
	var b [17]byte
	b[0] = frameReply
	binary.BigEndian.PutUint64(b[1:9], g.seen[0])
	binary.BigEndian.PutUint64(b[9:], g.seen[1])
	if g.w.write(b[:]) != nil {
		g.live.Store(false)
	}
	return others
}

// IsMarker reports whether s is the marker, which the owner of a Gate drops from its own handling.
func IsMarker(s os.Signal) bool {
	sig, ok := s.(syscall.Signal)
	return ok && sig == interruptMarker
}
