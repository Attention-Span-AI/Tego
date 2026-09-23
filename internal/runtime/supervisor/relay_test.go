// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// blockingKernel is a fakeKernel whose relayed connect never returns on its own, which is what a blocking
// socket's connect(2) does against a route that drops SYNs: the kernel runs its whole retry schedule
// (~127 s at the default tcp_syn_retries=6) before it gives up. entered fires once the relay is inside the
// syscall; release lets it finish, standing in for that schedule expiring.
type blockingKernel struct {
	*fakeKernel
	entered chan struct{}
	release chan struct{}
}

func (b *blockingKernel) ConnectRaw(fd int, sa []byte) error {
	close(b.entered)
	<-b.release
	return b.fakeKernel.ConnectRaw(fd, sa)
}

// blockingConnectLoop builds a loop whose one allowed destination relays into a connect that blocks.
func blockingConnectLoop(t *testing.T) (*Loop, *blockingKernel) {
	t.Helper()
	f := newFake()
	f.put(0x40000, sockaddrIn4("10.0.0.5", 8080))
	b := &blockingKernel{fakeKernel: f, entered: make(chan struct{}), release: make(chan struct{})}
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: b, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return l, b
}

// TestRunReturnsWhileARelayedConnectIsStillBlocked is the liveness property the relay exists for.
//
// handleConnect performs the allowed connect itself, on a pidfd_getfd duplicate that shares the target's
// open file description — so a blocking target socket gives a blocking connect(2) with no deadline, which
// §4 states deliberately. Performed inline on the worker, that syscall is unreachable by cancellation:
// the wake byte and the 200 ms poll slice only reach a worker inside receive(), never one inside a
// handler. Run ends in workers.Wait(), so a single connect to an allowed but blackholed host pinned Run
// for the kernel's whole retry schedule — the runner's group.Wait() behind it too, which is what appends
// run_end and releases the run directory's flock. The run outlived by minutes the deadline that had
// already SIGKILLed the agent, and `tego status` still reported it live throughout.
//
// With DefaultWorkers=4 the same shape parks the entire pool, and then no notification of any kind is
// received: every openat, execve and mkdir from every thread of the run stays trapped in the kernel.
func TestRunReturnsWhileARelayedConnectIsStillBlocked(t *testing.T) {
	l, b := blockingConnectLoop(t)
	b.queue(sysNotif{ID: 1, Pid: 4242, Data: sysData(connectNR(), 5, 0x40000, 16)})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	<-b.entered // the worker is inside the relayed connect, exactly where cancellation could not reach
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		close(b.release) // unpark the relay so the test process can exit
		t.Fatal("Run did not return while a relayed connect was in flight: shutdown is bounded by the network, not by the run's own cancellation")
	}

	// The notification is abandoned rather than answered: the syscall's real result will never be known
	// and I3 forbids inventing one. Closing the listener is what fails the trapped syscall closed.
	if b.respCount() != 0 {
		got, _ := b.lastResp()
		t.Errorf("answered %+v for a relay whose result was never known (I3)", got)
	}
	if !b.closedList {
		t.Error("Run returned without closing the listener")
	}

	// The duplicate belongs to the relay goroutine from the moment it starts: closing it while the kernel
	// is still inside the syscall would free the fd number under a live connect. It is closed once the
	// syscall returns, and not before.
	if bal := b.fdBalance(); bal == 0 {
		t.Error("the duplicate was closed while the connect was still in flight")
	}
	close(b.release)
	waitFor(t, func() bool { return b.fdBalance() == 0 })
}

// TestRelayedConnectReturnsTheRealResult pins that the goroutine changed nothing about the answer: an
// allowed connect still carries the real result of the connect performed on the target's own socket (I3,
// R9), and the duplicate is still closed inside the notification that took it (E28).
func TestRelayedConnectReturnsTheRealResult(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("10.0.0.5", 8080))
	f.connectErr = unix.ECONNREFUSED
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	l, _ := newTestLoop(t, f, pol)

	l.handle(notifFor(connectNR(), 4242, 5, 0x40000, 16))

	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response")
	}
	if got.Error != -int32(unix.ECONNREFUSED) || got.Val != -1 {
		t.Errorf("response = {error=%d val=%d}, want the real ECONNREFUSED relayed verbatim", got.Error, got.Val)
	}
	if len(f.connects) != 1 {
		t.Fatalf("connects = %d, want the one this loop performed on the duplicate", len(f.connects))
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open once the handler returned", f.fdBalance())
	}
}

// TestRelayedSendIsAlsoCancellable: the Fast-Open relay has the same shape as the connect one — a
// blocking sendto on the duplicate, with the TCP handshake inside it when MSG_FASTOPEN is set — so it is
// bounded by the same cancellation.
func TestRelayedSendIsAlsoCancellable(t *testing.T) {
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.put(0x40000, sockaddrIn4("10.0.0.5", 8080))
	f.put(0x50000, []byte("payload"))
	held := make(chan struct{})
	b := &holdingSendKernel{fakeKernel: f, entered: make(chan struct{}), release: held}
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	l, err := New(testListener(), pol, &testSink{}, Options{kernel: b, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	n := notifFor(sendToNR(), 4242, 5, 0x50000, 7, 0, 0x40000, 16)
	cancelled := make(chan struct{})
	n.done = cancelled

	returned := make(chan struct{})
	go func() { l.handle(n); close(returned) }()
	<-b.entered
	close(cancelled)

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		close(held)
		t.Fatal("the handler stayed inside a relayed Fast-Open send after the run was cancelled")
	}
	if !n.detached {
		t.Error("the notification was not marked detached, so finish() would answer for a send whose result is unknown")
	}
	if f.respCount() != 0 {
		t.Error("an answer was fabricated for a send that was still in flight (I3)")
	}
	close(held)
	waitFor(t, func() bool { return f.fdBalance() == 0 })
}

// holdingSendKernel blocks the relayed send the way blockingKernel blocks the relayed connect.
type holdingSendKernel struct {
	*fakeKernel
	entered chan struct{}
	release chan struct{}
}

func (h *holdingSendKernel) SendToRaw(fd int, p []byte, flags int, sa []byte) (int, error) {
	close(h.entered)
	<-h.release
	return h.fakeKernel.SendToRaw(fd, p, flags, sa)
}

// TestPoolKeepsReceivingWhileARelayIsParked is the starvation R21 and E17 do not contemplate.
//
// R21 sizes the pool for handlers measured in microseconds ("the (Workers+1)th notifying thread blocks
// inside its own trapped syscall until one frees up") and E17 reads pool exhaustion as npm-install-shaped
// latency at 4-8 µs a notification. R9's connect-on-duplicate is neither: the duplicate shares the
// target's open file description, so an allowed connect to a declared host whose route has started
// dropping SYNs runs the kernel's whole retry schedule (~127 s at tcp_syn_retries=6) with the worker
// parked inside it. At DefaultWorkers=4, four threads of one connection pool dialling one such host park
// every worker — and because only a worker inside receive() ever calls NOTIF_RECV, nothing is received at
// all after that: every openat, execve, mkdir, unlink and rename of every thread of the run stays trapped
// in the kernel. The agent is not slow, it is stopped, and `tego` shows a healthy run throughout.
//
// One worker stands in for the four here. With the connect parked, an ordinary record-and-continue
// notification must still be received and answered.
func TestPoolKeepsReceivingWhileARelayIsParked(t *testing.T) {
	l, b := blockingConnectLoop(t) // Workers: 1, and its one allowed destination blocks in connect
	b.put(0x60000, cstr("/work/new"))
	b.queue(sysNotif{ID: 1, Pid: 4242, Data: sysData(connectNR(), 5, 0x40000, 16)})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	<-b.entered // the pool's only worker is now inside the relayed connect
	b.queue(sysNotif{ID: 2, Pid: 4242, Data: sysData(nrFor(t, "mkdirat"), argCWD, 0x60000, 0o755)})

	waitFor(t, func() bool { return b.respCount() == 1 })
	if got, _ := b.lastResp(); got.ID != 2 || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want the mkdirat CONTINUEd while the connect is still parked (R15)", got)
	}
	if got := l.standby.Load(); got != 1 {
		t.Errorf("standby = %d, want the one worker that backfilled the parked relay (R21)", got)
	}

	// The retry schedule expires: the relay returns its real result, the worker that carried it answers
	// and then retires, because its place in the pool is already taken.
	close(b.release)
	waitFor(t, func() bool { return b.respCount() == 2 && l.standby.Load() == 0 })

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return")
	}
	if b.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", b.fdBalance())
	}
}

// TestRelayNoticesTheTargetAbandoningItsSyscall is the seccomp notifier's documented hazard for a
// supervisor that emulates a blocking syscall, which is exactly what R9 and R12 do.
//
// A signal delivered to the target while this loop is mid-handler cancels the notification, and the
// kernel then RESTARTS the target's syscall and raises a fresh notification for it — seccomp_unotify(2),
// "Interaction with SA_RESTART signal handlers": "the kernel will restart the target's system call.
// Consequently, the supervisor will receive another user-space notification", and it "will occur even for
// the blocking system calls listed in signal(7) that would never normally be restarted by the SA_RESTART
// flag". Because the connect and the Fast-Open send happen on the duplicate *before* NOTIF_SEND, the side
// effect is already done when SEND comes back ENOENT, and the restart does it a second time: the same
// bytes on the wire twice for a relayed send, EISCONN for a restarted connect, two allow lines in an
// append-only ledger for one call the agent made once. This needs no attacker — `tego stop` sends
// SIGTERM, PR_SET_PDEATHSIG fires on the child stage, and SIGCHLD or a profiler's SIGALRM is enough.
//
// The same page says what a supervisor must do about it: "when the supervisor wishes to emulate a
// blocking system call, it must do so in such a way that it gets informed if the target's system call is
// interrupted by a signal handler ... it could employ a separate thread that uses the
// SECCOMP_IOCTL_NOTIF_ID_VALID operation to check if the target is still blocked". Before this, nothing
// did: respond() swallowed the ENOENT as an ordinary target death (E2) and the duplicate side effect was
// invisible even in the log.
func TestRelayNoticesTheTargetAbandoningItsSyscall(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("10.0.0.5", 8080))
	b := &blockingKernel{fakeKernel: f, entered: make(chan struct{}), release: make(chan struct{})}
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: b, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// handleConnect brackets five times before the relay starts (two around the sockaddr read, two around
	// the pidfd acquire, one immediately before the duplicate is used, E31); all five still succeed, and
	// the target abandons the syscall once the connect is under way.
	b.staleAfter = 5
	n := notifFor(connectNR(), 4242, 5, 0x40000, 16)

	returned := make(chan struct{})
	go func() { l.handle(n); close(returned) }()
	<-b.entered

	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		close(b.release)
		t.Fatal("the handler waited on a relay the target had already abandoned: the cancellation is only discovered when NOTIF_SEND returns ENOENT, by which time the connect has happened and the kernel has restarted the syscall")
	}
	if !n.gone {
		t.Error("the notification was not marked gone, so a later respond would answer an id the kernel has withdrawn (R19)")
	}
	if b.respCount() != 0 {
		got, _ := b.lastResp()
		t.Errorf("answered %+v for a syscall the target is no longer in", got)
	}
	if got := l.metrics.orphaned.Load(); got != 1 {
		t.Errorf("orphaned = %d, want 1: a side effect performed for a syscall that will be restarted is counted, not swallowed", got)
	}

	// The connect itself is real and may already have opened the connection, so it is recorded even
	// though no answer reached the agent; result_unknown is what separates this line from the duplicate
	// the kernel's restart is about to produce.
	ev := sink.one(t)
	if ev.Kind != record.KindNet || ev.Verdict != record.VerdictAllow {
		t.Fatalf("event = %s/%s, want an allowed net line for the connect this loop performed", ev.Kind, ev.Verdict)
	}
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !p.ResultUnknown {
		t.Error("result_unknown is unset: the line is indistinguishable from a connect whose result the agent actually received")
	}
	close(b.release)
	waitFor(t, func() bool { return b.fdBalance() == 0 })
}

// TestConnectIsNeverContinuedWhateverItDecides pins I2 across every outcome handleConnect has when it
// decides a connect. A contract with no net: section decides none, and there I2's CONTINUE is the rule
// (TestConnectWithNoNetSection); this table carries no Contract, so it fails closed on that bit.
//
// It is here because of a live cross-document conflict, not a hypothetical one. docs/p0/supervisor.md R9
// and I2 say a connect is decided here and relayed on a duplicate, never CONTINUEd;
// docs/p0/enforce-cgroup-observe.md §5 R5 says the tier-2 seccomp handler "answers CONTINUE and reads
// reason_val", which would hand the kernel back a sockaddr a sibling thread can rewrite between this
// loop's decision and the kernel's own read (the reason the AF_UNSPEC carve-out is relayed rather than
// continued). Whichever way that conflict is resolved, flipping this package to CONTINUE is a decision
// someone has to make deliberately: this test is what makes it impossible to make by accident.
func TestConnectIsNeverContinuedWhateverItDecides(t *testing.T) {
	const addr = 0x40000
	allowed := []agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}
	tests := []struct {
		name   string
		rules  []agent.NetRule
		sa     []byte
		dupErr error
	}{
		{name: "allowed, relayed on the duplicate (R9)", rules: allowed, sa: sockaddrIn4("10.0.0.5", 8080)},
		{name: "unmatched destination (R7)", sa: sockaddrIn4("10.0.0.5", 8080)},
		{name: "unreadable sockaddr (R5, args-unreadable)"},
		{name: "duplicate lost to fd reuse (E33, fd-raced)", rules: allowed,
			sa: sockaddrIn4("10.0.0.5", 8080), dupErr: unix.EBADF},
		{name: "AF_UNSPEC disassociation (R4)", sa: make([]byte, 16)},
		{name: "unmatched unix socket (R11)",
			sa: append([]byte{unix.AF_UNIX, 0}, cstr("/run/other.sock")...)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			addrlen := uint64(16)
			if len(tc.sa) > 0 {
				f.put(addr, tc.sa)
				addrlen = uint64(len(tc.sa))
			}
			f.dupErr = tc.dupErr
			l, _ := newTestLoop(t, f, testPolicy(tc.rules, nil, []netip.AddrPort{}))
			l.handle(notifFor(connectNR(), 4242, 5, addr, addrlen))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v: a connect decision is never answered CONTINUE (I2)", got)
			}
			if f.respCount() != 1 {
				t.Errorf("responses = %d, want exactly one (I11)", f.respCount())
			}
		})
	}
}

// orphaningKernel parks every relayed connect and Fast-Open send until release closes and, the moment a
// relay is inside the syscall, withdraws the notification named by withdraw: the shape a signal gives a
// target blocked in a connect to a route that drops SYNs (E35). entered counts the relays that reached
// the syscall at all. A zero withdraw withdraws nothing.
type orphaningKernel struct {
	*fakeKernel
	withdraw uint64 // guarded by fakeKernel.mu
	entered  int    // guarded by fakeKernel.mu
	release  chan struct{}
}

func (o *orphaningKernel) park() {
	o.mu.Lock()
	o.entered++
	if o.withdraw != 0 {
		o.stale[o.withdraw] = true
	}
	o.mu.Unlock()
	<-o.release
}

func (o *orphaningKernel) ConnectRaw(fd int, sa []byte) error {
	o.park()
	return o.fakeKernel.ConnectRaw(fd, sa)
}

func (o *orphaningKernel) SendToRaw(fd int, p []byte, flags int, sa []byte) (int, error) {
	o.park()
	return o.fakeKernel.SendToRaw(fd, p, flags, sa)
}

// TestOrphanedRelaysAreBounded is E28 for the relays nobody waits on any more.
//
// maxStandby bounds the standby workers, and with them the relays a handler is still parked on. An
// orphaned relay is not one of those: its handler returns relayOrphaned and the worker retires, giving
// the standby slot back, while the goroutine keeps its pidfd_getfd duplicate until the kernel's connect
// returns — the whole SYN retry schedule against a blackholed route. The kernel restarts the abandoned
// syscall into a fresh notification and a fresh relay, so an agent signalled on a loop while connecting
// to an allowed host that drops SYNs grew goroutines and descriptors without limit: 192 orphans held 192
// duplicates against maxStandby=64, with standby and starved both at zero. Past relayCeiling the next
// relay is refused, fail-closed, before it starts, and the ceiling lifts again as the kernel returns.
func TestOrphanedRelaysAreBounded(t *testing.T) {
	const saAddr, bufAddr = 0x40000, 0x50000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.put(saAddr, sockaddrIn4("10.0.0.5", 8080))
	f.put(bufAddr, []byte("ping"))
	o := &orphaningKernel{fakeKernel: f, release: make(chan struct{})}
	released := false
	defer func() {
		if !released {
			close(o.release)
		}
	}()
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: o, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	ceiling := int(l.relayCeiling())
	id := uint64(1000)
	next := func(n *notif) *notif {
		id++
		n.id = id
		o.mu.Lock()
		o.withdraw = id
		o.mu.Unlock()
		return n
	}

	for i := 0; i < ceiling; i++ {
		l.handle(next(notifFor(connectNR(), 4242, 5, saAddr, 16)))
	}
	if got := l.metrics.orphaned.Load(); got != int64(ceiling) {
		t.Fatalf("orphaned = %d, want %d", got, ceiling)
	}
	if got := f.fdBalance(); got != ceiling {
		t.Fatalf("open duplicates = %d, want one per orphaned relay (%d)", got, ceiling)
	}
	if ceiling <= maxStandby {
		t.Fatalf("ceiling %d does not exceed maxStandby %d: this test must orphan more relays than standbys", ceiling, maxStandby)
	}

	for _, tc := range []struct {
		name string
		n    *notif
	}{
		{"connect", notifFor(connectNR(), 4242, 5, saAddr, 16)},
		{"Fast-Open sendto", notifFor(sendToNR(), 4242, 5, bufAddr, 4, unix.MSG_FASTOPEN, saAddr, 16)},
	} {
		t.Run("past the ceiling, "+tc.name, func(t *testing.T) {
			o.mu.Lock()
			entered := o.entered
			o.mu.Unlock()
			n := next(tc.n)

			l.handle(n)

			got, ok := f.lastResp()
			if !ok || got.ID != n.id {
				t.Fatalf("no answer for notification %d: relay %d past a ceiling of %d was started and orphaned like the rest", n.id, ceiling+1, ceiling)
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) || got.Val != -1 {
				t.Errorf("response = %+v, want R10's errno: past the ceiling the relay is refused, never continued (I2)", got)
			}
			o.mu.Lock()
			reached := o.entered - entered
			o.mu.Unlock()
			if reached != 0 {
				t.Errorf("%d relays reached the syscall past the ceiling", reached)
			}
			evs := sink.all()
			if ev := evs[len(evs)-1]; ev.Verdict != record.VerdictRefused || ev.Rule != ruleRelayLimit {
				t.Errorf("event = {verdict=%s rule=%s}, want {refused %s}", ev.Verdict, ev.Rule, ruleRelayLimit)
			}
			if got := f.fdBalance(); got != ceiling {
				t.Errorf("open duplicates = %d, want %d: the refused handler closes the duplicate it took", got, ceiling)
			}
		})
	}
	if got := l.metrics.relayLimited.Load(); got != 2 {
		t.Errorf("relayLimited = %d, want 2", got)
	}

	// The kernel's retry schedules expire: every orphan closes its duplicate and gives its slot back, and
	// the ceiling is not a latch.
	close(o.release)
	released = true
	waitFor(t, func() bool { return f.fdBalance() == 0 && l.relays.Load() == 0 })
	n := next(notifFor(connectNR(), 4242, 5, saAddr, 16))
	o.mu.Lock()
	o.withdraw = 0 // this one is answered
	o.mu.Unlock()
	l.handle(n)
	if got, _ := f.lastResp(); got.ID != n.id || got.Error != 0 || got.Val != 0 {
		t.Errorf("response = %+v, want the relayed connect's real result once relays have drained", got)
	}
}
