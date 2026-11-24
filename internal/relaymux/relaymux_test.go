// SPDX-License-Identifier: Apache-2.0

package relaymux

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// pipePair is two connected ends' pipes, kernel pipes as wsl.exe's are (buffered, unlike io.Pipe): what a writes
// (aw), b reads (br), and what b writes (bw), a reads (ar).
func pipePair() (ar io.ReadCloser, aw io.WriteCloser, br io.ReadCloser, bw io.WriteCloser) {
	r1, w1, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	r2, w2, err := os.Pipe()
	if err != nil {
		panic(err)
	}
	return r1, w2, r2, w1
}

// sessions starts a Windows end and a Linux end (announcing port 8484) over in-memory pipes.
func sessions(t *testing.T) (win, lin *Session) {
	t.Helper()
	ar, aw, br, bw := pipePair()
	type res struct {
		s   *Session
		err error
	}
	c := make(chan res, 1)
	go func() {
		s, err := Start(br, bw, Options{Port: 8484})
		c <- res{s, err}
	}()
	win, err := Start(ar, aw, Options{Opener: true})
	if err != nil {
		t.Fatal(err)
	}
	r := <-c
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() { _ = win.Close(); _ = r.s.Close() })
	return win, r.s
}

// echo serves every stream the Linux end accepts by sending back what it reads, then half-closing.
func echo(lin *Session) {
	for {
		st, err := lin.Accept()
		if err != nil {
			return
		}
		go func() {
			_, _ = io.Copy(st, st)
			_ = st.CloseWrite()
		}()
	}
}

// exchange sends data on a new stream, half-closes, and returns everything the other end sent back.
func exchange(win *Session, data []byte) ([]byte, error) {
	st, err := win.Open()
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.Close() }()
	werr := make(chan error, 1)
	go func() {
		_, err := st.Write(data)
		if err == nil {
			err = st.CloseWrite()
		}
		werr <- err
	}()
	got, err := io.ReadAll(st)
	if err != nil {
		return nil, err
	}
	return got, <-werr
}

func roundTrip(t *testing.T, win *Session, data []byte) []byte {
	t.Helper()
	got, err := exchange(win, data)
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestFrameRoundTrip(t *testing.T) {
	var b []byte
	b = AppendFrame(b, TypeHello, 0, helloPayload(8484))
	b = AppendFrame(b, TypeOpen, 7, nil)
	b = AppendFrame(b, TypeData, 7, []byte("GET / HTTP/1.1\r\n"))
	b = AppendFrame(b, TypeWindow, 7, binary.BigEndian.AppendUint32(nil, 16))
	b = AppendFrame(b, TypeCloseWrite, 7, nil)
	b = AppendFrame(b, TypeClose, 7, []byte("why"))
	b = AppendFrame(b, TypeGoAway, 0, []byte("bye"))
	r := bytes.NewReader(b)
	var buf []byte
	want := []byte{TypeHello, TypeOpen, TypeData, TypeWindow, TypeCloseWrite, TypeClose, TypeGoAway}
	for _, typ := range want {
		var f Frame
		var err error
		f, buf, err = ReadFrame(r, buf)
		if err != nil {
			t.Fatal(err)
		}
		if f.Type != typ {
			t.Fatalf("type %d, want %d", f.Type, typ)
		}
	}
	if _, _, err := ReadFrame(r, buf); err != io.EOF {
		t.Fatalf("after the last frame: %v", err)
	}
}

func TestReadFrameRefuses(t *testing.T) {
	for name, b := range map[string][]byte{
		"unknown type":      AppendFrame(nil, 9, 1, nil),
		"oversized data":    append(AppendFrame(nil, TypeData, 1, nil)[:5], 0, 0, 0x80, 1),
		"oversized reason":  AppendFrame(nil, TypeClose, 1, make([]byte, maxReason+1)),
		"hello on a stream": AppendFrame(nil, TypeHello, 1, helloPayload(1)),
		"data on stream 0":  AppendFrame(nil, TypeData, 0, []byte("x")),
		"goaway on stream":  AppendFrame(nil, TypeGoAway, 3, nil),
		"zero window":       AppendFrame(nil, TypeWindow, 1, make([]byte, 4)),
		"short window":      AppendFrame(nil, TypeWindow, 1, []byte{1}),
		"payload on open":   AppendFrame(nil, TypeOpen, 1, []byte("x")),
	} {
		if _, _, err := ReadFrame(bytes.NewReader(b), nil); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want a protocol error", name, err)
		}
	}
	trunc := AppendFrame(nil, TypeData, 1, []byte("abcdef"))
	if _, _, err := ReadFrame(bytes.NewReader(trunc[:len(trunc)-2]), nil); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated payload: %v", err)
	}
}

func TestHelloCarriesPort(t *testing.T) {
	win, lin := sessions(t)
	if win.PeerPort() != 8484 || lin.PeerPort() != 0 {
		t.Fatalf("ports %d and %d", win.PeerPort(), lin.PeerPort())
	}
}

func TestBulkBothWays(t *testing.T) {
	win, lin := sessions(t)
	go echo(lin)
	data := make([]byte, 16<<20+12345)
	if _, err := rand.Read(data); err != nil {
		t.Fatal(err)
	}
	got := roundTrip(t, win, data)
	if sha256.Sum256(got) != sha256.Sum256(data) {
		t.Fatalf("%d bytes back, not the %d sent", len(got), len(data))
	}
}

func TestTwentyConcurrentStreams(t *testing.T) {
	win, lin := sessions(t)
	go echo(lin)
	var wg sync.WaitGroup
	errs := make(chan error, 20)
	for i := range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			data := bytes.Repeat([]byte{byte(i)}, 300<<10+i)
			st, err := win.Open()
			if err != nil {
				errs <- err
				return
			}
			defer func() { _ = st.Close() }()
			go func() { _, _ = st.Write(data); _ = st.CloseWrite() }()
			got, err := io.ReadAll(st)
			if err == nil && !bytes.Equal(got, data) {
				err = errors.New("stream data changed")
			}
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
}

// TestSlowStreamDoesNotStallOthers: a stream whose reader never reads fills only its own window; another stream
// still completes.
func TestSlowStreamDoesNotStallOthers(t *testing.T) {
	win, lin := sessions(t)
	stuck := make(chan *Stream, 1)
	go func() {
		first := true
		for {
			st, err := lin.Accept()
			if err != nil {
				return
			}
			if first {
				first = false
				stuck <- st // never read
				continue
			}
			go func() { _, _ = io.Copy(st, st); _ = st.CloseWrite() }()
		}
	}()
	slow, err := win.Open()
	if err != nil {
		t.Fatal(err)
	}
	wrote := make(chan int, 1)
	go func() {
		n, _ := slow.Write(make([]byte, 4*Window))
		wrote <- n
	}()
	<-stuck
	done := make(chan []byte, 1)
	go func() {
		got, err := exchange(win, []byte("hello through the relay"))
		if err != nil {
			got = []byte(err.Error())
		}
		done <- got
	}()
	select {
	case got := <-done:
		if string(got) != "hello through the relay" {
			t.Fatalf("got %q", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a stalled stream held back another stream")
	}
	select {
	case n := <-wrote:
		t.Fatalf("the slow stream wrote %d bytes past its window", n)
	default:
	}
	_ = slow.Close()
	if n := <-wrote; n > Window {
		t.Fatalf("the slow stream sent %d bytes with a window of %d", n, Window)
	}
}

func TestHalfCloseKeepsTheOtherDirection(t *testing.T) {
	win, lin := sessions(t)
	go func() {
		st, err := lin.Accept()
		if err != nil {
			return
		}
		req, _ := io.ReadAll(st) // until the Windows end's half-close
		_, _ = st.Write(append([]byte("answer to "), req...))
		_ = st.CloseWrite()
	}()
	got := roundTrip(t, win, []byte("question"))
	if string(got) != "answer to question" {
		t.Fatalf("got %q", got)
	}
}

func TestAbortReachesTheOtherEnd(t *testing.T) {
	win, lin := sessions(t)
	go func() {
		st, err := lin.Accept()
		if err == nil {
			_ = st.Abort("the dashboard is not running")
		}
	}()
	st, err := win.Open()
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.ReadAll(st)
	if err == nil || !strings.Contains(err.Error(), "the dashboard is not running") {
		t.Fatalf("read after abort: %v", err)
	}
}

func TestGoAwayEndsBothEnds(t *testing.T) {
	win, lin := sessions(t)
	st, err := win.Open()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lin.Accept(); err != nil {
		t.Fatal(err)
	}
	lin.GoAway("the dashboard moved to another port")
	select {
	case <-win.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("GOAWAY did not end the Windows end")
	}
	if err := win.Err(); err == nil || !strings.Contains(err.Error(), "moved to another port") {
		t.Fatalf("Windows end ended with %v", err)
	}
	if _, err := st.Read(make([]byte, 1)); err == nil {
		t.Fatal("a stream outlived its session")
	}
	if _, err := win.Open(); err == nil {
		t.Fatal("opened a stream on an ended session")
	}
}

func TestPipeEndEndsSession(t *testing.T) {
	win, lin := sessions(t)
	_ = lin.Close() // the Linux end's process exits: its pipe ends close
	select {
	case <-win.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session outlived its pipe")
	}
}

// rawPeer is a hand-driven Linux end: the test writes frames to the session under test and reads its replies.
func rawPeer(t *testing.T, opener bool) (s *Session, peerIn io.Writer, peerOut io.Reader) {
	t.Helper()
	ar, aw, br, bw := pipePair()
	if _, err := bw.Write(AppendFrame(nil, TypeHello, 0, helloPayload(9))); err != nil {
		t.Fatal(err)
	}
	s, err := Start(ar, aw, Options{Opener: opener})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close(); _ = bw.Close(); _ = br.Close() })
	return s, bw, br
}

func endedWithProtocolError(t *testing.T, s *Session) {
	t.Helper()
	select {
	case <-s.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("the session did not end")
	}
	if !errors.Is(s.Err(), ErrProtocol) {
		t.Fatalf("ended with %v, want a protocol error", s.Err())
	}
}

func TestPeerPastItsWindowEndsSession(t *testing.T) {
	s, in, out := rawPeer(t, false)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	frames := AppendFrame(nil, TypeOpen, 1, nil)
	for range Window/MaxData + 1 {
		frames = AppendFrame(frames, TypeData, 1, make([]byte, MaxData))
	}
	go func() { _, _ = in.Write(frames) }()
	endedWithProtocolError(t, s)
}

func TestAcceptingEndCannotOpen(t *testing.T) {
	s, in, out := rawPeer(t, true)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	go func() { _, _ = in.Write(AppendFrame(nil, TypeOpen, 1, nil)) }()
	endedWithProtocolError(t, s)
}

func TestStreamIdsOnlyGrow(t *testing.T) {
	s, in, out := rawPeer(t, false)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	go func() {
		_, _ = in.Write(append(AppendFrame(nil, TypeOpen, 5, nil), AppendFrame(nil, TypeOpen, 5, nil)...))
	}()
	endedWithProtocolError(t, s)
}

func TestFrameForUnopenedStreamEndsSession(t *testing.T) {
	s, in, out := rawPeer(t, true)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	go func() { _, _ = in.Write(AppendFrame(nil, TypeData, 3, []byte("x"))) }()
	endedWithProtocolError(t, s)
}

func TestSecondHelloEndsSession(t *testing.T) {
	s, in, out := rawPeer(t, true)
	go func() { _, _ = io.Copy(io.Discard, out) }()
	go func() { _, _ = in.Write(AppendFrame(nil, TypeHello, 0, helloPayload(9))) }()
	endedWithProtocolError(t, s)
}

func TestWrongProtocolRefused(t *testing.T) {
	for name, first := range map[string][]byte{
		"another version": AppendFrame(nil, TypeHello, 0, []byte("tego-relay/0\x00\x01")),
		"no HELLO":        AppendFrame(nil, TypeOpen, 1, nil),
	} {
		ar, aw, br, bw := pipePair()
		if _, err := bw.Write(first); err != nil {
			t.Fatal(err)
		}
		if _, err := Start(ar, aw, Options{Opener: true}); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: Start: %v, want a protocol error", name, err)
		}
		_ = bw.Close()
		_ = br.Close()
	}
}

func TestTooManyStreamsRefusedOne(t *testing.T) {
	win, lin := sessions(t)
	var held []*Stream
	for range MaxStreams {
		st, err := win.Open()
		if err != nil {
			t.Fatal(err)
		}
		held = append(held, st)
	}
	if _, err := win.Open(); err == nil {
		t.Fatal("opened more than MaxStreams")
	}
	for range MaxStreams {
		if _, err := lin.Accept(); err != nil {
			t.Fatal(err)
		}
	}
	_ = held[0].Close()
	time.Sleep(50 * time.Millisecond)
	if _, err := win.Open(); err != nil {
		t.Fatalf("after a close: %v", err)
	}
}

func FuzzReadFrame(f *testing.F) {
	f.Add(AppendFrame(nil, TypeHello, 0, helloPayload(8484)))
	f.Add(AppendFrame(AppendFrame(nil, TypeOpen, 1, nil), TypeData, 1, []byte("GET /")))
	f.Add(AppendFrame(nil, TypeWindow, 2, []byte{0, 0, 1, 0}))
	f.Add([]byte{3, 0, 0, 0, 1, 0xff, 0xff, 0xff, 0xff})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := bytes.NewReader(b)
		var buf []byte
		for {
			var fr Frame
			var err error
			fr, buf, err = ReadFrame(r, buf)
			if err != nil {
				return
			}
			if len(fr.Payload) > maxPayload(fr.Type) {
				t.Fatalf("type %d payload %d over its limit", fr.Type, len(fr.Payload))
			}
		}
	})
}

// FuzzSession feeds arbitrary frames to a Linux end after a correct HELLO: it must end or keep running, never
// panic, and never hand out a stream whose reads exceed what was sent.
func FuzzSession(f *testing.F) {
	f.Add(AppendFrame(AppendFrame(nil, TypeOpen, 1, nil), TypeData, 1, []byte("GET / HTTP/1.1\r\n\r\n")))
	f.Add(AppendFrame(AppendFrame(nil, TypeOpen, 1, nil), TypeClose, 1, []byte("x")))
	f.Add(AppendFrame(nil, TypeGoAway, 0, []byte("bye")))
	f.Fuzz(func(t *testing.T, b []byte) {
		ar, aw, br, bw := pipePair()
		go func() { _, _ = io.Copy(io.Discard, br); _ = br.Close() }()
		go func() {
			_, _ = bw.Write(AppendFrame(nil, TypeHello, 0, helloPayload(0)))
			_, _ = bw.Write(b)
			_ = bw.Close()
		}()
		s, err := Start(ar, aw, Options{Port: 1})
		if err != nil {
			return
		}
		defer func() { _ = s.Close() }()
		go func() {
			for {
				st, err := s.Accept()
				if err != nil {
					return
				}
				go func() {
					n, _ := io.Copy(io.Discard, st)
					if n > int64(len(b)) {
						panic("read more than was sent")
					}
					_ = st.Close()
				}()
			}
		}()
		select {
		case <-s.Done():
		case <-time.After(2 * time.Second):
			t.Fatal("the session did not end at the pipe's end")
		}
	})
}
