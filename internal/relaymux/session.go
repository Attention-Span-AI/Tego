// SPDX-License-Identifier: Apache-2.0

package relaymux

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
)

// MaxStreams bounds the streams open at once: a browser uses a handful of connections per origin, and each stream
// may buffer up to Window bytes in each direction.
const MaxStreams = 64

// ErrClosed is returned by a stream or session used after the session ended.
var ErrClosed = errors.New("the relay has ended")

// Options says which end a Session is.
type Options struct {
	// Opener is the Windows end, which opens one stream per accepted connection; the Linux end accepts them.
	Opener bool
	// Port is the dashboard port the Linux end announces in its HELLO; the Windows end sends 0.
	Port uint16
}

// Session is one end of the multiplex over a pipe.
type Session struct {
	r      io.ReadCloser
	w      io.WriteCloser
	opener bool

	wmu  sync.Mutex
	wbuf []byte

	mu       sync.Mutex
	streams  map[uint32]*Stream
	lastID   uint32 // the highest stream id opened, by either end
	accepted chan *Stream
	err      error // why the session ended; nil while it runs
	done     chan struct{}

	peerPort uint16
}

// Start sends this end's HELLO, reads the other end's and starts the reader. r and w are the pipe's two halves;
// the session closes both when it ends.
func Start(r io.ReadCloser, w io.WriteCloser, o Options) (*Session, error) {
	s := &Session{r: r, w: w, opener: o.Opener, streams: map[uint32]*Stream{}, done: make(chan struct{})}
	if !o.Opener {
		s.accepted = make(chan *Stream, MaxStreams)
	}
	if err := s.send(TypeHello, 0, helloPayload(o.Port)); err != nil {
		s.closePipe()
		return nil, err
	}
	f, buf, err := ReadFrame(r, nil)
	if err == nil && f.Type != TypeHello {
		err = protocolf("the first frame is type %d, not HELLO", f.Type)
	}
	if err == nil {
		s.peerPort, err = parseHello(f.Payload)
	}
	if err != nil {
		s.closePipe()
		return nil, err
	}
	go s.read(buf)
	return s, nil
}

// PeerPort is the port the other end announced in its HELLO.
func (s *Session) PeerPort() uint16 { return s.peerPort }

// Done is closed when the session has ended; Err then says why.
func (s *Session) Done() <-chan struct{} { return s.done }

// Err is why the session ended: io.EOF when the other end closed the pipe, the other end's GOAWAY reason, a
// protocol error, or ErrClosed after Close. It is nil while the session runs.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// Close ends the session and every stream on it.
func (s *Session) Close() error {
	s.end(ErrClosed)
	return nil
}

// GoAway tells the other end why this end is ending the session, then ends it.
func (s *Session) GoAway(reason string) {
	_ = s.send(TypeGoAway, 0, []byte(clip(reason)))
	s.end(fmt.Errorf("%w: %s", ErrClosed, clip(reason)))
}

// Open starts a new stream (the Windows end only).
func (s *Session) Open() (*Stream, error) {
	if !s.opener {
		return nil, errors.New("only the opening end opens streams")
	}
	// The id is taken and its OPEN written under the write lock, so OPENs reach the other end in id order, which it
	// requires (opened), however many goroutines open at once.
	s.wmu.Lock()
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		s.wmu.Unlock()
		return nil, err
	}
	if len(s.streams) >= MaxStreams {
		s.mu.Unlock()
		s.wmu.Unlock()
		return nil, fmt.Errorf("more than %d connections at once", MaxStreams)
	}
	if s.lastID == ^uint32(0) {
		s.mu.Unlock()
		s.wmu.Unlock()
		return nil, errors.New("stream ids exhausted; start the relay again")
	}
	s.lastID++
	st := s.newStream(s.lastID)
	s.mu.Unlock()
	err := s.sendLocked(TypeOpen, st.id, nil)
	s.wmu.Unlock()
	if err != nil {
		s.end(fmt.Errorf("writing to the relay pipe: %w", err))
		return nil, err
	}
	return st, nil
}

// Accept waits for the other end's next stream (the Linux end only).
func (s *Session) Accept() (*Stream, error) {
	if s.opener {
		return nil, errors.New("the opening end does not accept streams")
	}
	select {
	case st := <-s.accepted:
		return st, nil
	case <-s.done:
		select {
		case st := <-s.accepted:
			return st, nil
		default:
		}
		return nil, s.Err()
	}
}

// newStream registers stream id with a full window each way. s.mu is held.
func (s *Session) newStream(id uint32) *Stream {
	st := &Stream{s: s, id: id, credit: Window}
	st.cond = sync.NewCond(&st.mu)
	s.streams[id] = st
	return st
}

// send writes one frame. A failed write ends the session.
func (s *Session) send(t byte, id uint32, payload []byte) error {
	s.wmu.Lock()
	err := s.sendLocked(t, id, payload)
	s.wmu.Unlock()
	if err != nil {
		s.end(fmt.Errorf("writing to the relay pipe: %w", err))
	}
	return err
}

// sendLocked writes one frame; s.wmu is held.
func (s *Session) sendLocked(t byte, id uint32, payload []byte) error {
	s.wbuf = AppendFrame(s.wbuf[:0], t, id, payload)
	_, err := s.w.Write(s.wbuf)
	return err
}

// read is the session's one reader. It never blocks on a stream: a stream's buffer holds at most the window this
// end granted, and a peer that sends past it ends the session.
func (s *Session) read(buf []byte) {
	for {
		f, nbuf, err := ReadFrame(s.r, buf)
		buf = nbuf
		if err == nil {
			err = s.dispatch(f)
		}
		if err != nil {
			s.end(err)
			return
		}
	}
}

// dispatch applies one frame read after HELLO.
func (s *Session) dispatch(f Frame) error {
	switch f.Type {
	case TypeHello:
		return protocolf("a second HELLO")
	case TypeGoAway:
		return fmt.Errorf("the other end ended the relay: %s", printable(f.Payload))
	case TypeOpen:
		return s.opened(f.Stream)
	}
	s.mu.Lock()
	st, live := s.streams[f.Stream]
	known := f.Stream <= s.lastID
	s.mu.Unlock()
	if !live {
		if known {
			return nil // a frame for a stream this end already closed: the other end has not seen the CLOSE yet
		}
		return protocolf("frame type %d for stream %d, which was never opened", f.Type, f.Stream)
	}
	switch f.Type {
	case TypeData:
		return st.received(f.Payload)
	case TypeWindow:
		st.granted(int(binary.BigEndian.Uint32(f.Payload)))
	case TypeCloseWrite:
		st.peerDone()
	case TypeClose:
		s.forget(st)
		reason := "closed by the other end"
		if len(f.Payload) > 0 {
			reason = printable(f.Payload)
		}
		st.abort(reason)
	}
	return nil
}

// opened handles OPEN on the accepting end: ids only grow, and past MaxStreams a stream is refused at once.
func (s *Session) opened(id uint32) error {
	if s.opener {
		return protocolf("the accepting end opened stream %d", id)
	}
	s.mu.Lock()
	if id <= s.lastID {
		s.mu.Unlock()
		return protocolf("stream %d opened again or out of order", id)
	}
	s.lastID = id
	if len(s.streams) >= MaxStreams {
		s.mu.Unlock()
		return s.send(TypeClose, id, []byte("too many connections at once"))
	}
	st := s.newStream(id)
	s.mu.Unlock()
	s.accepted <- st // never blocks: at most MaxStreams streams are live, the channel holds as many
	return nil
}

func (s *Session) forget(st *Stream) {
	s.mu.Lock()
	if s.streams[st.id] == st {
		delete(s.streams, st.id)
	}
	s.mu.Unlock()
}

// end records why the session ended (the first reason wins), closes the pipe and fails every stream.
func (s *Session) end(err error) {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return
	}
	s.err = err
	streams := s.streams
	s.streams = map[uint32]*Stream{}
	close(s.done)
	s.mu.Unlock()
	// Closing a pipe half can wait for a read or write in flight on it; ending must not.
	go s.closePipe()
	for _, st := range streams {
		st.abort("the relay ended: " + err.Error())
	}
}

func (s *Session) closePipe() {
	_ = s.w.Close()
	_ = s.r.Close()
}

// Stream is one relayed connection: an io.ReadWriteCloser with a half-close.
type Stream struct {
	s  *Session
	id uint32

	mu      sync.Mutex
	cond    *sync.Cond
	rbuf    []byte // received and not yet read
	unacked int    // read and not yet returned to the other end as credit
	rEOF    bool   // the other end sent CLOSEWRITE
	aborted string // the other end sent CLOSE, or the session ended
	credit  int    // bytes this end may still send
	wClosed bool   // this end sent CLOSEWRITE
	closed  bool   // this end closed the stream
}

// ID is the stream's id.
func (st *Stream) ID() uint32 { return st.id }

func (st *Stream) received(p []byte) error {
	st.mu.Lock()
	defer st.mu.Unlock()
	if st.rEOF {
		return protocolf("data after the half-close on stream %d", st.id)
	}
	if len(st.rbuf)+st.unacked+len(p) > Window {
		return protocolf("stream %d sent past its window", st.id)
	}
	if st.closed {
		return nil
	}
	st.rbuf = append(st.rbuf, p...)
	st.cond.Broadcast()
	return nil
}

func (st *Stream) granted(n int) {
	st.mu.Lock()
	st.credit += n
	if st.credit > Window {
		st.credit = Window // a peer cannot widen the window past its size
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) peerDone() {
	st.mu.Lock()
	st.rEOF = true
	st.cond.Broadcast()
	st.mu.Unlock()
}

func (st *Stream) abort(reason string) {
	st.mu.Lock()
	if st.aborted == "" {
		st.aborted = reason
	}
	st.cond.Broadcast()
	st.mu.Unlock()
}

// Read returns the bytes the other end sent. Bytes already received are always delivered, even after the other end
// closed the stream; then a half-close reads as io.EOF and an abort as an error naming its reason.
func (st *Stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	st.mu.Lock()
	for len(st.rbuf) == 0 && !st.rEOF && st.aborted == "" && !st.closed {
		st.cond.Wait()
	}
	if len(st.rbuf) == 0 {
		var err error
		switch {
		case st.closed:
			err = ErrClosed
		case st.rEOF:
			err = io.EOF
		default:
			err = errors.New(st.aborted)
		}
		st.mu.Unlock()
		return 0, err
	}
	n := copy(p, st.rbuf)
	st.rbuf = st.rbuf[n:]
	if len(st.rbuf) == 0 {
		st.rbuf = nil
	}
	st.unacked += n
	credit := 0
	if st.unacked >= Window/4 || len(st.rbuf) == 0 {
		credit, st.unacked = st.unacked, 0
	}
	live := st.aborted == ""
	st.mu.Unlock()
	if credit > 0 && live {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], uint32(credit))
		_ = st.s.send(TypeWindow, st.id, b[:])
	}
	return n, nil
}

// Write sends p, waiting for credit as the other end hands earlier bytes on.
func (st *Stream) Write(p []byte) (int, error) {
	sent := 0
	for len(p) > 0 {
		st.mu.Lock()
		for st.credit == 0 && st.aborted == "" && !st.closed && !st.wClosed {
			st.cond.Wait()
		}
		switch {
		case st.closed, st.wClosed:
			st.mu.Unlock()
			return sent, ErrClosed
		case st.aborted != "":
			err := errors.New(st.aborted)
			st.mu.Unlock()
			return sent, err
		}
		n := min(len(p), st.credit, MaxData)
		st.credit -= n
		st.mu.Unlock()
		if err := st.s.send(TypeData, st.id, p[:n]); err != nil {
			return sent, err
		}
		sent += n
		p = p[n:]
	}
	return sent, nil
}

// CloseWrite tells the other end this end sends no more.
func (st *Stream) CloseWrite() error {
	st.mu.Lock()
	if st.wClosed || st.closed || st.aborted != "" {
		st.mu.Unlock()
		return nil
	}
	st.wClosed = true
	st.cond.Broadcast()
	st.mu.Unlock()
	return st.s.send(TypeCloseWrite, st.id, nil)
}

// Close ends the stream in both directions.
func (st *Stream) Close() error { return st.Abort("") }

// Abort ends the stream in both directions, telling the other end why (reason may be empty).
func (st *Stream) Abort(reason string) error {
	st.mu.Lock()
	if st.closed {
		st.mu.Unlock()
		return nil
	}
	st.closed = true
	tell := st.aborted == ""
	st.rbuf = nil
	st.cond.Broadcast()
	st.mu.Unlock()
	st.s.forget(st)
	if !tell {
		return nil
	}
	return st.s.send(TypeClose, st.id, []byte(clip(reason)))
}

// clip bounds a reason to what a CLOSE or GOAWAY frame carries, in printable ASCII.
func clip(reason string) string {
	reason = printable([]byte(reason))
	if len(reason) > maxReason {
		reason = reason[:maxReason]
	}
	return reason
}

// printable is b with every byte outside printable ASCII shown as '?', for logs and messages.
func printable(b []byte) string {
	var sb strings.Builder
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			c = '?'
		}
		sb.WriteByte(c)
	}
	return sb.String()
}
