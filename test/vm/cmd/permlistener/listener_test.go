// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The tests below stand a socketpair in for the fanotify group. The listener reads event records from one end
// and writes its eight-byte responses to it, as it does on the group descriptor, and the test is the kernel at
// the other end: it writes the records, collects the responses, and sees which descriptors the listener closed.
// Nothing here needs a privilege; the real group is the integration tests' (integration_test.go).

var selfPid = int32(os.Getpid())

const (
	foreignPid = int32(4242)
	waitFor    = 5 * time.Second
)

type reply struct {
	fd   int32
	word uint32
}

type rig struct {
	t       *testing.T
	l       *listener
	kernel  int // the test's end of the "group"
	replies chan reply
	drained chan struct{}

	unmarks atomic.Int32

	mu      sync.Mutex
	closed  []int
	touched []string
	statted []string
	comms   map[int32]string

	stopOnce sync.Once
	final    stats
}

// allowTouchCfg is a small allow-touch configuration: the decisions touch two files and stat one, with no
// pause, and the deadline is the default, long enough that it never answers for a worker unless a test wants it.
func allowTouchCfg(workers int) config {
	return config{
		mode:     modeAllowTouch,
		marks:    []string{"/"},
		workers:  workers,
		touch:    []string{"/touch/a", "/touch/b"},
		stat:     []string{"/stat/a"},
		deadline: 10 * time.Second,
	}
}

func newRig(t *testing.T, cfg config, tweak func(*listener)) *rig {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatalf("socketpair: %v", err)
	}
	if err := unix.SetNonblock(fds[0], true); err != nil {
		t.Fatal(err)
	}
	// A listener that stops reading must fail a test, not hang it on a full socket.
	if err := unix.SetsockoptTimeval(fds[1], unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		t.Fatal(err)
	}
	l, err := newListener(cfg, fds[0])
	if err != nil {
		t.Fatalf("newListener: %v", err)
	}
	r := &rig{
		t: t, l: l, kernel: fds[1], comms: map[int32]string{},
		replies: make(chan reply, 8192), drained: make(chan struct{}),
	}
	l.unmark = func() error { r.unmarks.Add(1); return nil }
	l.touch = func(p string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.touched = append(r.touched, p)
		return nil
	}
	l.stat = func(p string) error {
		r.mu.Lock()
		defer r.mu.Unlock()
		r.statted = append(r.statted, p)
		return nil
	}
	l.comm = func(pid int32) string {
		r.mu.Lock()
		defer r.mu.Unlock()
		return r.comms[pid]
	}
	l.closeFD = func(fd int) {
		r.mu.Lock()
		r.closed = append(r.closed, fd)
		r.mu.Unlock()
		_ = unix.Close(fd)
	}
	l.logf = t.Logf
	// The kernel takes every response the listener writes. The socket this stands in for is nonblocking, like the
	// group, and refuses a write with EAGAIN once about 270 responses are unread; a listener answering a queue of
	// events faster than the drain below reads them would lose responses to the stand-in, not to anything it did.
	l.write = func(fd int, b []byte) (int, error) {
		for {
			n, err := unix.Write(fd, b)
			if !errors.Is(err, unix.EAGAIN) {
				return n, err
			}
			_, _ = unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}, 100)
		}
	}
	if tweak != nil {
		tweak(l)
	}
	go r.drain()
	t.Cleanup(func() {
		r.stop()
		<-r.drained // the listener closed its end, so the drain read EOF
		_ = unix.Close(r.kernel)
	})
	l.start()
	return r
}

// drain collects the responses as they are written, so a listener is never held up by a test that has not
// read them yet (a socket holds only so many).
func (r *rig) drain() {
	defer close(r.drained)
	var raw [64]byte
	for {
		n, err := unix.Read(r.kernel, raw[:])
		switch {
		case n == 8:
			r.replies <- reply{
				fd:   int32(binary.NativeEndian.Uint32(raw[0:4])),
				word: binary.NativeEndian.Uint32(raw[4:8]),
			}
		case errors.Is(err, unix.EINTR):
		default:
			return
		}
	}
}

func (r *rig) stop() stats {
	r.stopOnce.Do(func() { r.final = r.l.stop() })
	return r.final
}

// send writes a record naming a fresh descriptor of /dev/null, as the kernel would name the opened file, and
// returns that descriptor.
func (r *rig) send(mask uint64, pid int32) int32 {
	r.t.Helper()
	return r.sendFile("/dev/null", mask, pid)
}

func (r *rig) sendFile(path string, mask uint64, pid int32) int32 {
	r.t.Helper()
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		r.t.Fatalf("open %s: %v", path, err)
	}
	r.sendRaw(rec(3, mask, int32(fd), pid, 0))
	return int32(fd)
}

func (r *rig) sendRaw(b []byte) {
	r.t.Helper()
	if _, err := unix.Write(r.kernel, b); err != nil {
		r.t.Fatalf("write a record: %v (the listener stopped reading?)", err)
	}
}

// response is the next response the listener wrote.
func (r *rig) response() (fd int32, word uint32) {
	r.t.Helper()
	select {
	case rp := <-r.replies:
		return rp.fd, rp.word
	case <-time.After(waitFor):
		r.t.Fatalf("no response within %v", waitFor)
		return 0, 0
	}
}

func (r *rig) noResponseWithin(d time.Duration) {
	r.t.Helper()
	select {
	case rp := <-r.replies:
		r.t.Fatalf("unexpected response for fd %d: %d", rp.fd, rp.word)
	case <-time.After(d):
	}
}

func (r *rig) closedFDs() []int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]int(nil), r.closed...)
}

func (r *rig) touches() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.touched...)
}

func (r *rig) statCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.statted)
}

func (r *rig) setComm(pid int32, comm string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.comms[pid] = comm
}

func TestSelfEventsAreAnsweredOnTheReaderWhileEveryWorkerIsStuck(t *testing.T) {
	t.Parallel()
	stuck := make(chan struct{})
	r := newRig(t, allowTouchCfg(1), func(l *listener) {
		l.sleep = func(time.Duration, <-chan struct{}) { <-stuck }
	})
	t.Cleanup(func() { close(stuck) }) // runs before the rig's stop: a stop waits for its workers
	r.send(unix.FAN_OPEN_PERM, foreignPid)
	own := r.send(unix.FAN_OPEN_PERM, selfPid)
	fd, word := r.response()
	if fd != own || word != unix.FAN_ALLOW {
		t.Fatalf("first response = fd %d word %d, want the listener's own fd %d allowed: its own open was handed to a worker", fd, word, own)
	}
	r.noResponseWithin(50 * time.Millisecond) // the foreign open waits for its worker, which is stuck
}

func TestForeignEventsAreDecidedByAWorkerThenAllowed(t *testing.T) {
	t.Parallel()
	r := newRig(t, allowTouchCfg(2), nil)
	r.setComm(77, "tego")
	r.setComm(78, "sh")
	a := r.send(unix.FAN_OPEN_PERM, 77)
	b := r.send(unix.FAN_OPEN_EXEC_PERM, 78)
	// The listener may answer and close the first descriptor before the second is opened, so the two records
	// can name one number (GitHub's runner: 12 and 12): the answers are compared as a multiset.
	var answered []int32
	for range 2 {
		fd, word := r.response()
		if word != unix.FAN_ALLOW {
			t.Fatalf("the response for %d is %#x, want FAN_ALLOW", fd, word)
		}
		answered = append(answered, fd)
	}
	sent := []int32{a, b}
	slices.Sort(answered)
	slices.Sort(sent)
	if !slices.Equal(answered, sent) {
		t.Fatalf("responses for %v, want one each for %d and %d", answered, a, b)
	}
	st := r.stop()
	if st.Events != 2 || st.Tego != 1 || st.Exec != 1 || st.Self != 0 || st.Late != 0 || st.Denied != 0 || st.Failed != 0 {
		t.Errorf("stats = %+v, want 2 events (one exec, one from a tego), nothing else", st)
	}
	touched := r.touches()
	sort.Strings(touched)
	want := []string{"/touch/a", "/touch/a", "/touch/b", "/touch/b"}
	if !equalStrings(touched, want) {
		t.Errorf("touched %v, want each decision to open both files: %v", touched, want)
	}
	if got := r.statCalls(); got != 2 {
		t.Errorf("stat ran %d times, want once per decision", got)
	}
}

// TestTegoCountsEveryOpenerWhoseCommBeginsWithTego: a pairs run starts a copy of the build beside the first
// (tego-b, tego-pie), and the group seeing the copy's opens is as much the point as seeing the first's.
func TestTegoCountsEveryOpenerWhoseCommBeginsWithTego(t *testing.T) {
	t.Parallel()
	r := newRig(t, allowTouchCfg(2), nil)
	comms := map[int32]string{90: "tego", 91: "tego-b", 92: "tego-pie", 93: "sh", 94: "xtego", 95: ""}
	for pid, comm := range comms {
		r.setComm(pid, comm)
		r.send(unix.FAN_OPEN_PERM, pid)
	}
	for range comms {
		r.response()
	}
	if st := r.stop(); st.Tego != 3 || st.Events != int64(len(comms)) {
		t.Errorf("stats = %+v, want 3 of the %d events counted as tego's", st, len(comms))
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestDenyAnswersTheTargetOnlyAndByNameOrInode(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret")
	alias := filepath.Join(dir, "alias")
	other := filepath.Join(dir, "other")
	for _, p := range []string{secret, other} {
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(secret, alias); err != nil {
		t.Fatal(err)
	}
	cfg := config{mode: modeDeny, marks: []string{dir}, path: secret, deadline: time.Second}
	r := newRig(t, cfg, nil)
	cases := []struct {
		name string
		path string
		mask uint64
		pid  int32
		want uint32
	}{
		{"the target", secret, unix.FAN_OPEN_PERM, foreignPid, unix.FAN_DENY},
		{"another file", other, unix.FAN_OPEN_PERM, foreignPid, unix.FAN_ALLOW},
		{"a hard link of the target", alias, unix.FAN_OPEN_PERM, foreignPid, unix.FAN_DENY},
		{"the target, opened by the listener itself", secret, unix.FAN_OPEN_PERM, selfPid, unix.FAN_ALLOW},
		{"the target, as an exec", secret, unix.FAN_OPEN_EXEC_PERM, foreignPid, unix.FAN_DENY},
	}
	for _, c := range cases {
		want := r.sendFile(c.path, c.mask, c.pid)
		fd, word := r.response()
		if fd != want || word != c.want {
			t.Errorf("%s: response fd %d word %d, want fd %d word %d", c.name, fd, word, want, c.want)
		}
	}
	st := r.stop()
	if st.Events != 5 || st.Denied != 3 || st.Self != 1 || st.Late != 0 {
		t.Errorf("stats = %+v, want 5 events, 3 denied, 1 own", st)
	}
	if len(r.touches()) != 0 {
		t.Errorf("deny mode opened files: %v", r.touches())
	}
}

func TestAnEventNobodyAnswersByTheDeadlineIsAllowedOnceAndCountedLate(t *testing.T) {
	t.Parallel()
	cfg := allowTouchCfg(1)
	cfg.deadline = 40 * time.Millisecond
	stuck := make(chan struct{})
	r := newRig(t, cfg, func(l *listener) {
		l.sleep = func(time.Duration, <-chan struct{}) { <-stuck }
	})
	var once sync.Once
	release := func() { once.Do(func() { close(stuck) }) }
	t.Cleanup(release)
	begin := time.Now()
	want := r.send(unix.FAN_OPEN_PERM, foreignPid)
	fd, word := r.response()
	if fd != want || word != unix.FAN_ALLOW {
		t.Fatalf("response = fd %d word %d, want fd %d allowed by the deadline", fd, word, want)
	}
	if took := time.Since(begin); took < cfg.deadline {
		t.Errorf("answered after %v, before the %v deadline", took, cfg.deadline)
	}
	release() // the worker wakes up after its event was answered
	st := r.stop()
	if st.Late != 1 || st.Events != 1 {
		t.Errorf("stats = %+v, want 1 event, 1 late", st)
	}
	r.noResponseWithin(50 * time.Millisecond) // a second answer would land on a descriptor number the kernel may have reused
	if got := r.closedFDs(); len(got) != 1 || got[0] != int(want) {
		t.Errorf("closed %v, want the event descriptor %d once", got, want)
	}
	if got := r.touches(); len(got) != 0 {
		t.Errorf("the worker touched %v for an event that was already answered", got)
	}
}

// TestTheReaderDoesNotWaitForAWorkerOrAFullQueue: if the reader blocked handing a foreign event to a worker
// (a bounded queue, every worker busy), the listener's own opens, made by those same workers, could not be
// answered, and every decision would wait on a reader that waits on them.
func TestTheReaderDoesNotWaitForAWorkerOrAFullQueue(t *testing.T) {
	t.Parallel()
	const queued = 600
	stuck := make(chan struct{})
	r := newRig(t, allowTouchCfg(1), func(l *listener) {
		l.sleep = func(time.Duration, <-chan struct{}) { <-stuck }
	})
	var once sync.Once
	release := func() { once.Do(func() { close(stuck) }) }
	t.Cleanup(release)
	foreign := map[int32]bool{}
	for range queued {
		foreign[r.send(unix.FAN_OPEN_PERM, foreignPid)] = true
	}
	own := r.send(unix.FAN_OPEN_PERM, selfPid)
	fd, word := r.response()
	if fd != own || word != unix.FAN_ALLOW {
		t.Fatalf("with %d decisions queued the own open was answered %d/%d, want fd %d allowed first", queued, fd, word, own)
	}
	release()
	for range queued {
		fd, word := r.response()
		if !foreign[fd] || word != unix.FAN_ALLOW {
			t.Fatalf("response fd %d word %d: not one of the queued events, or not allowed", fd, word)
		}
		delete(foreign, fd)
	}
}

// TestStopRemovesTheMarksThenAnswersWhatIsStillInTheGroup: the events that entered the group in the instant
// before the marks went are read and answered after the marks are gone, and stop returns only when every one is.
func TestStopRemovesTheMarksThenAnswersWhatIsStillInTheGroup(t *testing.T) {
	t.Parallel()
	var r *rig
	var late []int32
	r = newRig(t, allowTouchCfg(2), func(l *listener) {
		l.unmark = func() error {
			r.unmarks.Add(1)
			for range 3 {
				late = append(late, r.send(unix.FAN_OPEN_PERM, foreignPid))
			}
			late = append(late, r.send(unix.FAN_OPEN_PERM, selfPid))
			return nil
		}
	})
	st := r.stop()
	if got := r.unmarks.Load(); got != 1 {
		t.Fatalf("marks removed %d times, want once", got)
	}
	got := map[int32]uint32{}
	for range late {
		fd, word := r.response()
		got[fd] = word
	}
	for _, fd := range late {
		if got[fd] != unix.FAN_ALLOW {
			t.Errorf("event %d answered %d after the marks were removed, want allowed", fd, got[fd])
		}
	}
	if st.Events != 4 || st.Self != 1 {
		t.Errorf("stats = %+v, want the 4 late events counted", st)
	}
	if n := len(r.closedFDs()); n != 4 {
		t.Errorf("closed %d event descriptors, want 4", n)
	}
}

func TestStopDoesNotWaitOutADecisionsDelay(t *testing.T) {
	t.Parallel()
	cfg := allowTouchCfg(2)
	cfg.delay = time.Hour
	r := newRig(t, cfg, nil)
	want := r.send(unix.FAN_OPEN_PERM, foreignPid)
	r.noResponseWithin(50 * time.Millisecond) // the worker sleeps on its delay
	begin := time.Now()
	r.stop()
	if took := time.Since(begin); took > waitFor {
		t.Fatalf("stop took %v with a decision sleeping an hour", took)
	}
	if fd, word := r.response(); fd != want || word != unix.FAN_ALLOW {
		t.Errorf("response = fd %d word %d, want fd %d allowed", fd, word, want)
	}
	if got := r.touches(); len(got) != 0 {
		t.Errorf("a decision cut short by the stop still touched %v", got)
	}
}

// TestEveryEventGetsOneResponseAndOneClose races the deadline against the workers on purpose: whichever wins,
// the event is answered once and its descriptor closed once, because a second response would name a number the
// kernel may have handed to another event by then.
func TestEveryEventGetsOneResponseAndOneClose(t *testing.T) {
	t.Parallel()
	const total = 300
	cfg := allowTouchCfg(8)
	cfg.deadline = 2 * time.Millisecond
	rng := rand.New(rand.NewPCG(1, 2))
	var rngMu sync.Mutex
	r := newRig(t, cfg, func(l *listener) {
		l.sleep = func(time.Duration, <-chan struct{}) {
			rngMu.Lock()
			d := time.Duration(rng.IntN(4000)) * time.Microsecond
			rngMu.Unlock()
			time.Sleep(d)
		}
	})
	// Every descriptor is opened before the first record is sent: the listener closes them as it answers, and a
	// number it has closed would be handed to the next open, so two events would share a name in this test's
	// books (as, in the kernel, they may; that is why a response is written once).
	fds := make([]int32, total)
	for i := range fds {
		fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		fds[i] = int32(fd)
	}
	sent := map[int32]bool{}
	own := 0
	for i, fd := range fds {
		pid := foreignPid
		if i%5 == 0 {
			pid = selfPid
			own++
		}
		sent[fd] = true
		r.sendRaw(rec(3, unix.FAN_OPEN_PERM, fd, pid, 0))
	}
	seen := map[int32]int{}
	for range total {
		fd, word := r.response()
		if word != unix.FAN_ALLOW {
			t.Fatalf("fd %d answered %d", fd, word)
		}
		seen[fd]++
	}
	st := r.stop()
	r.noResponseWithin(50 * time.Millisecond)
	closed := map[int]int{}
	for _, fd := range r.closedFDs() {
		closed[fd]++
	}
	for fd := range sent {
		if seen[fd] != 1 {
			t.Errorf("fd %d got %d responses", fd, seen[fd])
		}
		if closed[int(fd)] != 1 {
			t.Errorf("fd %d closed %d times", fd, closed[int(fd)])
		}
	}
	if st.Events != total || st.Self != int64(own) {
		t.Errorf("stats = %+v, want %d events, %d of them its own", st, total, own)
	}
	if st.Late > int64(total-own) {
		t.Errorf("late %d exceeds the %d events a worker decides", st.Late, total-own)
	}
	t.Logf("late %d of %d decided events at a %v deadline", st.Late, total-own, cfg.deadline)
}

func TestAMalformedTailIsCountedAndTheRecordsBeforeItAreAnswered(t *testing.T) {
	t.Parallel()
	r := newRig(t, config{mode: modeDeny, marks: []string{"/"}, path: "/nonexistent/x", deadline: time.Second}, nil)
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.sendRaw(cat(rec(3, unix.FAN_OPEN_PERM, int32(fd), foreignPid, 0), make([]byte, 10)))
	if got, word := r.response(); got != int32(fd) || word != unix.FAN_ALLOW {
		t.Fatalf("response = fd %d word %d, want fd %d allowed", got, word, fd)
	}
	st := r.stop()
	if st.Malformed != 1 || st.Events != 1 {
		t.Errorf("stats = %+v, want 1 event and 1 malformed read", st)
	}
}

func TestRecordsThatAskForNoAnswerAreClosedNotAnswered(t *testing.T) {
	t.Parallel()
	r := newRig(t, allowTouchCfg(1), nil)
	r.sendRaw(rec(3, unix.FAN_Q_OVERFLOW, -1, 0, 0)) // FAN_NOFD
	notify, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	r.sendRaw(rec(3, 0x20, int32(notify), foreignPid, 0)) // a notification open: no response is read
	// A permission event after them proves the reader went on, and orders the check below.
	want := r.send(unix.FAN_OPEN_PERM, selfPid)
	if fd, _ := r.response(); fd != want {
		t.Fatalf("first response names fd %d, want %d: a record that wants no answer got one", fd, want)
	}
	st := r.stop()
	r.noResponseWithin(30 * time.Millisecond)
	if st.Events != 1 {
		t.Errorf("events = %d, want only the permission event counted", st.Events)
	}
	if closed := r.closedFDs(); !contains(closed, notify) {
		t.Errorf("the notification record's descriptor %d was not closed (closed %v)", notify, closed)
	}
}

func contains(s []int, v int) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

func TestAnUnknownMetadataVersionEndsTheReaderAndIsReported(t *testing.T) {
	t.Parallel()
	r := newRig(t, allowTouchCfg(1), nil)
	r.sendRaw(rec(2, unix.FAN_OPEN_PERM, 0, foreignPid, 0))
	select {
	case <-r.l.readerDone:
	case <-time.After(waitFor):
		t.Fatal("the reader went on reading a group whose ABI it does not speak")
	}
	if err := r.l.err(); !errors.Is(err, errVersion) {
		t.Fatalf("err = %v, want the version error", err)
	}
	r.stop() // and the shutdown still completes
}

func TestAResponseThatCannotBeWrittenIsCountedAndTheDescriptorStillClosed(t *testing.T) {
	t.Parallel()
	r := newRig(t, allowTouchCfg(1), func(l *listener) {
		l.write = func(int, []byte) (int, error) { return 0, unix.EIO }
	})
	want := r.send(unix.FAN_OPEN_PERM, selfPid)
	r.noResponseWithin(100 * time.Millisecond)
	st := r.stop()
	if st.Failed != 1 || st.Events != 1 {
		t.Errorf("stats = %+v, want 1 event and 1 failed", st)
	}
	if got := r.closedFDs(); len(got) != 1 || got[0] != int(want) {
		t.Errorf("closed %v, want fd %d", got, want)
	}
}

func TestAnInterruptedResponseWriteIsRetried(t *testing.T) {
	t.Parallel()
	var calls atomic.Int32
	r := newRig(t, allowTouchCfg(1), func(l *listener) {
		l.write = func(fd int, b []byte) (int, error) {
			if calls.Add(1) == 1 {
				return 0, unix.EINTR
			}
			return unix.Write(fd, b)
		}
	})
	want := r.send(unix.FAN_OPEN_PERM, selfPid)
	if fd, word := r.response(); fd != want || word != unix.FAN_ALLOW {
		t.Fatalf("response = fd %d word %d, want fd %d allowed", fd, word, want)
	}
	if st := r.stop(); st.Failed != 0 || calls.Load() != 2 {
		t.Errorf("failed %d after %d writes, want 0 after 2", st.Failed, calls.Load())
	}
}

func TestStatsLine(t *testing.T) {
	t.Parallel()
	st := stats{Mode: modeDeny, Events: 10, Tego: 3, Self: 4, Late: 1, Denied: 2, Exec: 5, Failed: 6, Malformed: 7}
	want := "PERMLISTENER-STATS events=10 tego=3 self=4 late=1 denied=2 exec=5 failed=6 malformed=7 mode=deny"
	if got := st.String(); got != want {
		t.Errorf("stats line\n got %q\nwant %q", got, want)
	}
}

func TestTouchAndStatAndCommAreTheRealThings(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	f := filepath.Join(dir, "f")
	if err := os.WriteFile(f, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := touchFile(f); err != nil {
		t.Errorf("touchFile of a readable file: %v", err)
	}
	if err := touchFile(filepath.Join(dir, "missing")); !errors.Is(err, unix.ENOENT) {
		t.Errorf("touchFile of a missing file = %v, want ENOENT", err)
	}
	if err := statPath(dir); err != nil {
		t.Errorf("statPath of a directory: %v", err)
	}
	if err := statPath(filepath.Join(dir, "missing")); !errors.Is(err, unix.ENOENT) {
		t.Errorf("statPath of a missing path = %v, want ENOENT", err)
	}
	want, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Fatal(err)
	}
	if got := commOf(int32(os.Getpid())); got+"\n" != string(want) {
		t.Errorf("commOf(self) = %q, /proc/self/comm holds %q", got, want)
	}
	if got := commOf(0x7ffffff0); got != "" {
		t.Errorf("commOf of no process = %q, want empty", got)
	}
}

func TestFileOfNamesTheOpenFile(t *testing.T) {
	t.Parallel()
	f := filepath.Join(t.TempDir(), "named")
	if err := os.WriteFile(f, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(f, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	path, dev, ino, err := fileOf(int32(fd))
	if err != nil {
		t.Fatalf("fileOf: %v", err)
	}
	wdev, wino := fileID(t, f)
	if path != f || dev != wdev || ino != wino {
		t.Errorf("fileOf = %q %d/%d, want %q %d/%d", path, dev, ino, f, wdev, wino)
	}
	if _, _, _, err := fileOf(-1); err == nil {
		t.Error("fileOf(-1) succeeded")
	}
}
