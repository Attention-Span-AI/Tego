// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"
)

const (
	// readBuffer is the read(2) buffer: a few hundred whole records. The kernel returns whole records only.
	readBuffer = 8192
	// pollMS is how long the reader waits for an event before it looks at the stop flag.
	pollMS = 100
	// commTego is what the comm of a Tego process begins with: the launchers and, by fork, their stages (a run's
	// own opens and execs), and the copies a pairs run starts beside the first, tego-b and tego-pie.
	commTego = "tego"
)

// pending is one permission event that has not been answered. Whoever answers it first wins the CAS and is the
// only one that writes its response and closes its descriptor: the descriptor number is the event's name in
// the response, and once it is closed the kernel may hand the number to the next event.
type pending struct {
	ev       event
	answered atomic.Bool
	deferred bool                       // handed to a worker, so counted in listener.inflight
	timer    atomic.Pointer[time.Timer] // the deadline of a deferred event; stopped by whoever answers it
}

// counters are what the stats line reports.
type counters struct {
	events, tego, own, late, denied, exec, failed, malformed atomic.Int64
}

// listener reads one fanotify group and answers every permission event it is sent, exactly once.
//
// One reader goroutine reads the group. It answers an event of this process's own at once, because the opens a
// worker makes while it decides are events of this group too, and the worker is blocked in its open until the
// reader answers: a reader that waited for workers would wait on itself. For the same reason it never blocks on
// anything a worker holds (the work queue is unbounded) and opens nothing on the marked mounts itself.
//
// In allow-touch mode every other event goes to a worker, which decides it (decide) and answers FAN_ALLOW. An
// event no worker has answered by the deadline is answered FAN_ALLOW by its timer and counted late, so this
// helper cannot be the stall it exists to provoke in somebody else. In deny mode the reader answers every event
// itself, FAN_DENY for the target and FAN_ALLOW for the rest.
type listener struct {
	cfg  config
	fd   int   // the group
	self int32 // this process's thread group id: the pid of its own opens
	tgt  target

	// The hooks are the real calls unless a test replaces them.
	unmark  func() error
	touch   func(path string) error
	stat    func(path string) error
	comm    func(pid int32) string
	sleep   func(d time.Duration, quit <-chan struct{})
	closeFD func(fd int)
	write   func(fd int, p []byte) (int, error)
	logf    func(format string, args ...any)

	queue    *workQueue
	inflight sync.WaitGroup // events handed to a worker and not yet answered
	workers  sync.WaitGroup
	stopping atomic.Bool   // the marks are gone: the reader reads what is left and ends
	quit     chan struct{} // closed once the reader has ended: a decision stops waiting out its delay
	stopOnce sync.Once
	final    stats

	// readerDone is closed when the reader has ended, normally or not. run waits on it as well as on its context.
	readerDone chan struct{}

	failMu  sync.Mutex
	failure error

	n counters
}

func newListener(cfg config, fd int) (*listener, error) {
	l := &listener{
		cfg: cfg, fd: fd, self: int32(os.Getpid()),
		unmark:     func() error { return nil },
		touch:      touchFile,
		stat:       statPath,
		comm:       commOf,
		sleep:      sleepUntil,
		closeFD:    func(fd int) { _ = unix.Close(fd) },
		write:      unix.Write,
		logf:       func(format string, args ...any) { fmt.Fprintf(os.Stderr, "permlistener: "+format+"\n", args...) },
		queue:      newWorkQueue(),
		quit:       make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	if cfg.mode == modeDeny {
		t, err := newTarget(cfg.path)
		if err != nil {
			return nil, err
		}
		l.tgt = t
	}
	return l, nil
}

// start runs the workers and the reader.
func (l *listener) start() {
	for range l.cfg.workers {
		l.workers.Add(1)
		go l.work()
	}
	go l.read()
}

// read is the reader goroutine.
func (l *listener) read() {
	defer close(l.readerDone)
	buf := make([]byte, readBuffer)
	pfd := []unix.PollFd{{Fd: int32(l.fd), Events: unix.POLLIN}}
	for {
		stopping := l.stopping.Load()
		timeout := pollMS
		if stopping {
			timeout = 0 // the marks are gone: read what is queued, and end when nothing is
		}
		n, err := unix.Poll(pfd, timeout)
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			l.fail(fmt.Errorf("poll the group: %w", err))
			return
		case n == 0:
			if stopping {
				return
			}
			continue
		}
		got, err := unix.Read(l.fd, buf)
		switch {
		case errors.Is(err, unix.EINTR), errors.Is(err, unix.EAGAIN):
			continue
		case err != nil:
			l.fail(fmt.Errorf("read the group: %w", err))
			return
		case got == 0:
			l.fail(errors.New("the group reads end of file"))
			return
		}
		if !l.batch(buf[:got]) {
			return
		}
	}
}

// batch handles one read. It reports false when the reader must end.
func (l *listener) batch(b []byte) bool {
	events, err := parseEvents(b)
	for _, ev := range events {
		l.handle(ev)
	}
	if err == nil {
		return true
	}
	l.n.malformed.Add(1)
	if errors.Is(err, errVersion) {
		l.fail(err)
		return false
	}
	l.logf("malformed read: %v", err)
	return true
}

// handle routes one record.
func (l *listener) handle(ev event) {
	if !ev.isPermission() {
		// An overflow or a notification wants no response, but one that carries a descriptor owns it.
		if ev.Fd >= 0 {
			l.closeFD(int(ev.Fd))
		}
		return
	}
	if ev.Fd < 0 {
		// A response names its event by the descriptor, so one without cannot be answered; the kernel releases it
		// when the group closes.
		l.n.malformed.Add(1)
		l.logf("permission event %#x from %d carries no descriptor", ev.Mask, ev.Pid)
		return
	}
	l.n.events.Add(1)
	if ev.isExec() {
		l.n.exec.Add(1)
	}
	self := ev.Pid == l.self
	isTarget := false
	if l.cfg.mode == modeDeny && !self {
		isTarget = l.isTarget(ev.Fd)
	}
	p := &pending{ev: ev}
	switch r := l.cfg.route(self, isTarget); r {
	case routeSelf:
		l.n.own.Add(1)
		l.respond(p, r.response())
	case routeAllow, routeDeny:
		l.respond(p, r.response())
	case routeDecide:
		l.hand(p)
	}
}

// isTarget reports whether the event's file is deny mode's target. A file this listener cannot identify is
// allowed and counted failed: a refusal it could not make shows in the test that expected it.
func (l *listener) isTarget(fd int32) bool {
	path, dev, ino, err := fileOf(fd)
	if err != nil {
		if l.n.failed.Add(1) == 1 {
			l.logf("cannot identify the file of fd %d: %v (counted in failed)", fd, err)
		}
		return false
	}
	return l.tgt.matches(path, dev, ino)
}

// hand gives an event to the workers, with its deadline.
func (l *listener) hand(p *pending) {
	p.deferred = true
	l.inflight.Add(1)
	p.timer.Store(time.AfterFunc(l.cfg.deadline, func() {
		if l.respond(p, unix.FAN_ALLOW) {
			l.n.late.Add(1)
		}
	}))
	l.queue.push(p)
}

// respond writes the event's one response and closes its descriptor. It reports whether this call was the one
// that answered: an event already answered (its worker beat the deadline, or the deadline beat its worker) is
// left alone.
func (l *listener) respond(p *pending, response uint32) bool {
	if !p.answered.CompareAndSwap(false, true) {
		return false
	}
	if err := l.writeResponse(p.ev.Fd, response); err != nil {
		if l.n.failed.Add(1) == 1 {
			l.logf("response for fd %d: %v (counted in failed)", p.ev.Fd, err)
		}
	} else if response == unix.FAN_DENY {
		l.n.denied.Add(1)
	}
	l.closeFD(int(p.ev.Fd))
	if t := p.timer.Load(); t != nil {
		t.Stop()
	}
	if p.deferred {
		l.inflight.Done()
	}
	return true
}

func (l *listener) writeResponse(fd int32, response uint32) error {
	raw := encodeResponse(fd, response)
	for {
		n, err := l.write(l.fd, raw[:])
		switch {
		case errors.Is(err, unix.EINTR):
			continue
		case err != nil:
			return err
		case n != len(raw):
			return fmt.Errorf("short write: %d of %d bytes", n, len(raw))
		}
		return nil
	}
}

// work is a worker goroutine.
func (l *listener) work() {
	defer l.workers.Done()
	for {
		p, ok := l.queue.pop()
		if !ok {
			return
		}
		l.decide(p)
	}
}

// decide is allow-touch's decision: note who is asking, wait out the delay that widens the window, open and read
// the files, stat the paths, answer FAN_ALLOW. The opens are on the marked mount, so they are events of this
// group, which the reader answers (self), and of every other group on it, which is the point.
func (l *listener) decide(p *pending) {
	if p.answered.Load() {
		return // the deadline came while the event waited for a worker
	}
	if strings.HasPrefix(l.comm(p.ev.Pid), commTego) {
		l.n.tego.Add(1)
	}
	l.sleep(l.cfg.delay, l.quit)
	// Answered while this worker slept, or the listener is stopping and its marks are gone: nothing is left to
	// provoke, so the opens are skipped and the answer, if still owed, is FAN_ALLOW all the same.
	if !p.answered.Load() && !l.quitting() {
		for _, f := range l.cfg.touch {
			l.try("touch", f, l.touch)
		}
		for _, f := range l.cfg.stat {
			l.try("stat", f, l.stat)
		}
	}
	l.respond(p, unix.FAN_ALLOW)
}

// try runs one of a decision's calls. A failure leaves the decision weaker than it claims to be, so it is
// counted and the first is logged; it never changes the answer.
func (l *listener) try(kind, path string, fn func(string) error) {
	if err := fn(path); err != nil {
		if l.n.failed.Add(1) == 1 {
			l.logf("%s %s: %v (counted in failed)", kind, path, err)
		}
	}
}

func (l *listener) quitting() bool {
	select {
	case <-l.quit:
		return true
	default:
		return false
	}
}

// fail records the first reason the reader ended other than a stop.
func (l *listener) fail(err error) {
	l.failMu.Lock()
	defer l.failMu.Unlock()
	if l.failure == nil {
		l.failure = err
		l.logf("%v", err)
	}
}

// err is the reason the reader ended, nil if it has not or ended because it was stopped.
func (l *listener) err() error {
	l.failMu.Lock()
	defer l.failMu.Unlock()
	return l.failure
}

// stop ends the listener and returns its counters. The marks come down first, so no new event can enter the
// group; then the reader reads what is left, and stop waits until every event that was handed to a worker has
// been answered, by the worker or by its deadline. Only then is the group closed: the kernel releases anything
// still unanswered when it is, but an event this listener read and had not answered is a decision it lost.
// Workers still waiting on an open of their own are released by that close.
func (l *listener) stop() stats {
	l.stopOnce.Do(func() {
		if err := l.unmark(); err != nil {
			l.logf("remove the marks: %v", err)
		}
		l.stopping.Store(true)
		<-l.readerDone
		close(l.quit)
		l.inflight.Wait()
		_ = unix.Close(l.fd)
		l.queue.close()
		l.workers.Wait()
		l.final = l.snapshot()
	})
	return l.final
}

func (l *listener) snapshot() stats {
	return stats{
		Mode:      l.cfg.mode,
		Events:    l.n.events.Load(),
		Tego:      l.n.tego.Load(),
		Self:      l.n.own.Load(),
		Late:      l.n.late.Load(),
		Denied:    l.n.denied.Load(),
		Exec:      l.n.exec.Load(),
		Failed:    l.n.failed.Load(),
		Malformed: l.n.malformed.Load(),
	}
}

// stats is the counters at the end. Its line is what the pairs harness reads: events is every permission event
// the group delivered; self those of this process's own opens; tego those whose opener's comm begins with tego
// (the launchers and stages, copies included, which proves the group saw their opens); late those answered at the
// deadline instead of by a decision; denied those answered FAN_DENY; exec those that were execs; failed
// responses that could not be written and decisions that could not open what they were to; malformed reads the
// parser refused.
type stats struct {
	Mode                                                      mode
	Events, Tego, Self, Late, Denied, Exec, Failed, Malformed int64
}

func (s stats) String() string {
	return fmt.Sprintf("PERMLISTENER-STATS events=%d tego=%d self=%d late=%d denied=%d exec=%d failed=%d malformed=%d mode=%s",
		s.Events, s.Tego, s.Self, s.Late, s.Denied, s.Exec, s.Failed, s.Malformed, s.Mode)
}

// workQueue is an unbounded FIFO. The reader must never wait to hand an event over (listener), so there is no
// capacity to run out of: the deadline bounds how long an event can sit in it instead.
type workQueue struct {
	mu     sync.Mutex
	cond   *sync.Cond
	items  []*pending
	head   int
	closed bool
}

func newWorkQueue() *workQueue {
	q := &workQueue{}
	q.cond = sync.NewCond(&q.mu)
	return q
}

func (q *workQueue) push(p *pending) {
	q.mu.Lock()
	q.items = append(q.items, p)
	q.mu.Unlock()
	q.cond.Signal()
}

// pop waits for an item. It reports false once the queue is closed and empty.
func (q *workQueue) pop() (*pending, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	for q.head == len(q.items) && !q.closed {
		q.cond.Wait()
	}
	if q.head == len(q.items) {
		return nil, false
	}
	p := q.items[q.head]
	q.items[q.head] = nil
	q.head++
	if q.head == len(q.items) {
		q.items, q.head = q.items[:0], 0
	}
	return p, true
}

func (q *workQueue) close() {
	q.mu.Lock()
	q.closed = true
	q.mu.Unlock()
	q.cond.Broadcast()
}

// The real calls behind the hooks.

// sleepUntil waits d, or until quit is closed.
func sleepUntil(d time.Duration, quit <-chan struct{}) {
	if d <= 0 {
		return
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-quit:
	}
}

// ignoringEINTR retries a call a signal interrupted.
func ignoringEINTR(f func() error) error {
	for {
		if err := f(); !errors.Is(err, unix.EINTR) {
			return err
		}
	}
}

// touchFile opens a file, reads the first page of it and closes it: the part of a decision that makes an event
// on the marked mount.
func touchFile(path string) error {
	var fd int
	if err := ignoringEINTR(func() (err error) {
		fd, err = unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC, 0)
		return err
	}); err != nil {
		return err
	}
	var page [4096]byte
	rerr := ignoringEINTR(func() error { _, err := unix.Read(fd, page[:]); return err })
	cerr := unix.Close(fd)
	if rerr != nil {
		return rerr
	}
	return cerr
}

// statPath stats a path: the part of a decision that walks the marked mount without opening anything on it.
func statPath(path string) error {
	var st unix.Stat_t
	return ignoringEINTR(func() error { return unix.Stat(path, &st) })
}

// commOf is the comm of a process, or "" when it cannot be read. procfs is not a marked mount, so this adds no
// event of its own.
func commOf(pid int32) string {
	fd, err := unix.Open("/proc/"+strconv.Itoa(int(pid))+"/comm", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return ""
	}
	defer func() { _ = unix.Close(fd) }()
	var buf [64]byte
	n, err := unix.Read(fd, buf[:])
	if err != nil || n <= 0 {
		return ""
	}
	return strings.TrimSuffix(string(buf[:n]), "\n")
}

// fileOf names the file an event descriptor is open on, as the path procfs reads back and the device and inode.
// Neither call opens anything, so neither can be an event of a group that marks the file's mount.
func fileOf(fd int32) (path string, dev, ino uint64, err error) {
	var buf [unix.PathMax]byte
	n, err := unix.Readlink("/proc/self/fd/"+strconv.Itoa(int(fd)), buf[:])
	if err != nil {
		return "", 0, 0, err
	}
	var st unix.Stat_t
	if err := unix.Fstat(int(fd), &st); err != nil {
		return "", 0, 0, err
	}
	return string(buf[:n]), uint64(st.Dev), uint64(st.Ino), nil
}
