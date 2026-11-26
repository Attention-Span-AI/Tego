// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// interleavings calls visit once for every order in which a launcher arrivals and b outer reports can happen, the
// launcher's arrivals and the outer process's reports each keeping their own order (a count only grows).
func interleavings(a, b int, visit func(order []bool)) {
	var walk func(order []bool, la, lb int)
	walk = func(order []bool, la, lb int) {
		if la == a && lb == b {
			visit(order)
			return
		}
		if la < a {
			walk(append(order[:len(order):len(order)], true), la+1, lb)
		}
		if lb < b {
			walk(append(order[:len(order):len(order)], false), la, lb+1)
		}
	}
	walk(nil, 0, 0)
}

// The rule over every order of deliveries and reports. Each case is the pair (interrupts the launcher received
// itself, interrupts the outer process received itself); the outer process reports its running count after each.
func TestTallyAgreesOnTheLargerCountInEveryOrder(t *testing.T) {
	for _, tc := range []struct {
		name       string
		launcher   int
		outer      int
		interrupts uint64
	}{
		{"the group once", 1, 1, 1},
		{"the outer process alone", 0, 1, 1},
		{"the launcher alone", 1, 0, 1},
		{"the outer process, then the group", 1, 2, 2},
		{"the group, then the launcher alone", 2, 1, 2},
		{"the group twice", 2, 2, 2},
		{"the launcher, then the outer process (indistinguishable from the group once)", 1, 1, 1},
		{"the launcher, the outer process, the launcher", 2, 1, 2},
		{"the launcher twice", 2, 0, 2},
		{"the outer process twice", 0, 2, 2},
	} {
		for slot, sig := range interruptSignals {
			t.Run(tc.name+" "+sig.String(), func(t *testing.T) {
				interleavings(tc.launcher, tc.outer, func(order []bool) {
					var tl tally
					var total uint64
					ownN, peerN := uint64(0), uint64(0)
					for _, own := range order {
						if own {
							ownN++
							tl.arrival(slot)
						} else {
							peerN++
							var c counts
							c[slot] = peerN
							tl.report(c)
						}
						due := tl.due()
						if due[1-slot] != 0 {
							t.Fatalf("order %v: the other signal was counted from %v", order, sig)
						}
						total += due[slot]
						want := ownN
						if peerN > want {
							want = peerN
						}
						if total != want {
							t.Fatalf("order %v: acted on %d interrupts after %d own and %d reported, want %d", order, total, ownN, peerN, want)
						}
					}
					if total != tc.interrupts {
						t.Fatalf("order %v: %d interrupts, want %d", order, total, tc.interrupts)
					}
				})
			})
		}
	}
}

// A peer that dies or falls silent counts as it last reported, and the launcher's own count still works alone. A
// report that repeats or arrives out of date lowers nothing.
func TestTallyDeadSilentAndStaleReports(t *testing.T) {
	for last := 0; last <= 2; last++ {
		for own := 0; own <= 3; own++ {
			var tl tally
			var total uint64
			for r := 1; r <= last; r++ { // the peer reported up to last and then went silent
				tl.report(counts{uint64(r)})
				total += tl.due()[0]
			}
			tl.report(counts{0}) // a stale report
			total += tl.due()[0]
			for i := 0; i < own; i++ {
				tl.arrival(0)
				total += tl.due()[0]
			}
			want := uint64(own)
			if uint64(last) > want {
				want = uint64(last)
			}
			if total != want {
				t.Fatalf("peer reported %d then silent, launcher received %d: %d interrupts, want %d", last, own, total, want)
			}
		}
	}
	var tl tally
	tl.arrival(1)
	if due := tl.due(); due != (counts{0, 1}) {
		t.Fatalf("QUIT counts %v, want one QUIT and no INT", due)
	}
}

// provenanceRig is both processes of a user-scope run with their signal channels in the hands of the test: a send to
// "the group" puts the signal on both, a send to one process on that process alone, and the outer loop is the one
// executeUserScope runs: it hands every INT or QUIT to the gate and forwards by signal what the gate does not take.
type provenanceRig struct {
	arb          *Arbiter
	gate         *Gate
	launcherIn   chan os.Signal
	outerIn      chan os.Signal
	outerHandled chan os.Signal // what the outer process would forward by kill(2)
	stop         chan struct{}
	stopped      chan struct{}
}

func newProvenanceRig(t *testing.T) *provenanceRig {
	t.Helper()
	lc, oc := net.Pipe()
	r := &provenanceRig{launcherIn: make(chan os.Signal, 16), outerIn: make(chan os.Signal, 16),
		outerHandled: make(chan os.Signal, 16), stop: make(chan struct{}), stopped: make(chan struct{})}
	r.gate = NewGate(oc)
	go func() {
		defer close(r.stopped)
		for {
			select {
			case <-r.stop:
				return
			case s := <-r.outerIn:
				if !r.gate.Note(s.(syscall.Signal)) {
					r.outerHandled <- s
				}
			}
		}
	}()
	r.arb = NewArbiter(lc, r.launcherIn)
	select {
	case <-r.arb.Ready():
	case <-time.After(5 * time.Second):
		t.Fatal("the outer process never acknowledged the channel")
	}
	t.Cleanup(func() {
		close(r.stop)
		<-r.stopped
		r.arb.Close()
		r.gate.Close()
	})
	return r
}

// send delivers a signal to the launcher, the outer process or both, in the order the arguments say.
func (r *provenanceRig) send(to string, sig syscall.Signal) {
	switch to {
	case "group":
		r.launcherIn <- sig
		r.outerIn <- sig
	case "group, outer first":
		r.outerIn <- sig
		r.launcherIn <- sig
	case "launcher":
		r.launcherIn <- sig
	case "outer":
		r.outerIn <- sig
	}
}

// interrupts counts what the launcher is given, waiting for want and a short quiet after it.
func (r *provenanceRig) interrupts(t *testing.T, sig syscall.Signal, want int) {
	t.Helper()
	for i := 0; i < want; i++ {
		select {
		case s := <-r.arb.Signals():
			if s != sig {
				t.Fatalf("got %v, want %v", s, sig)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%d of %d interrupts arrived", i, want)
		}
	}
	select {
	case s := <-r.arb.Signals():
		t.Fatalf("an extra %v arrived: more than the %d the person made", s, want)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestProvenanceGroupSendIsOneInterrupt(t *testing.T) {
	for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT} {
		for _, to := range []string{"group", "group, outer first"} {
			t.Run(sig.String()+" "+to, func(t *testing.T) {
				r := newProvenanceRig(t)
				r.send(to, sig)
				r.interrupts(t, sig, 1)
				select {
				case s := <-r.outerHandled:
					t.Fatalf("the outer process forwarded %v by signal as well", s)
				default:
				}
			})
		}
	}
}

// The defect of public issue 81: one send reached both processes, but one of them read its copy long after the
// other's was acted on (a descheduled thread, a slow runner). It is one interrupt whichever process is late and
// however late it is, because the second count only meets the larger one that was already acted on.
func TestProvenanceGroupSendIsOneInterruptAtAnyLag(t *testing.T) {
	for _, late := range []string{"outer", "launcher"} {
		for _, lag := range []time.Duration{0, 5 * time.Millisecond, 300 * time.Millisecond} {
			t.Run(late+" late by "+lag.String(), func(t *testing.T) {
				r := newProvenanceRig(t)
				first, second := "launcher", "outer"
				if late == "launcher" {
					first, second = "outer", "launcher"
				}
				r.send(first, syscall.SIGINT)
				r.interrupts(t, syscall.SIGINT, 1) // acted on before the other copy is read
				time.Sleep(lag)
				r.send(second, syscall.SIGINT)
				select {
				case s := <-r.arb.Signals():
					t.Fatalf("an extra %v arrived: one send counted as two", s)
				case <-time.After(100 * time.Millisecond):
				}
			})
		}
	}
}

func TestProvenanceOneProcessSendIsOneInterrupt(t *testing.T) {
	for _, to := range []string{"launcher", "outer"} {
		t.Run(to, func(t *testing.T) {
			r := newProvenanceRig(t)
			r.send(to, syscall.SIGINT)
			r.interrupts(t, syscall.SIGINT, 1)
		})
	}
}

// A second signal to a process that already counted one is a deliberate repeat, whatever else was sent between and
// whichever process each one reached. Two signals to two different processes are not: they are the two counts one
// signal to the group makes, so they are one (ADR 0142, A51).
func TestProvenanceDeliberateRepeatsAreKept(t *testing.T) {
	for _, tc := range []struct {
		sends []string
		want  []int // interrupts acted on after each send
	}{
		{[]string{"group", "group"}, []int{1, 1}},
		{[]string{"outer", "group"}, []int{1, 1}},
		{[]string{"group", "launcher"}, []int{1, 1}},
		{[]string{"launcher", "launcher"}, []int{1, 1}},
		{[]string{"outer", "outer"}, []int{1, 1}},
		{[]string{"launcher", "outer", "launcher"}, []int{1, 0, 1}},
		{[]string{"outer", "launcher", "outer"}, []int{1, 0, 1}},
		{[]string{"launcher", "outer"}, []int{1, 0}},
		{[]string{"outer", "launcher"}, []int{1, 0}},
	} {
		for _, sig := range []syscall.Signal{syscall.SIGINT, syscall.SIGQUIT} {
			t.Run(sig.String()+" "+strings.Join(tc.sends, ", then "), func(t *testing.T) {
				r := newProvenanceRig(t)
				for i, to := range tc.sends {
					r.send(to, sig)
					r.interrupts(t, sig, tc.want[i])
				}
			})
		}
	}
}

func TestProvenanceOtherSignalsPassUnchanged(t *testing.T) {
	r := newProvenanceRig(t)
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGHUP} {
		r.launcherIn <- sig
		select {
		case s := <-r.arb.Signals():
			if s != sig {
				t.Fatalf("got %v, want %v", s, sig)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%v was held back", sig)
		}
	}
	// Signals that are not interrupts are no part of the count and the outer process's gate leaves them to its owner.
	r.outerIn <- syscall.SIGHUP
	select {
	case s := <-r.outerHandled:
		if s != syscall.SIGHUP {
			t.Fatalf("got %v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the gate took a SIGHUP")
	}
	r.launcherIn <- syscall.SIGINT
	r.interrupts(t, syscall.SIGINT, 1)
}

// An outer process that does not answer holds nothing back: the launcher counts its own arrivals, with no wait.
func TestProvenanceSilentOuterProcessDoesNotHoldBackAnInterrupt(t *testing.T) {
	lc, oc := net.Pipe()
	in := make(chan os.Signal, 16)
	a := NewArbiter(lc, in)
	defer a.Close()
	go func() { // reads the hello, never answers
		buf := make([]byte, 1)
		for {
			if _, err := oc.Read(buf); err != nil {
				return
			}
		}
	}()
	defer oc.Close()
	for i := 0; i < 2; i++ {
		in <- syscall.SIGINT
		select {
		case s := <-a.Signals():
			if s != syscall.SIGINT {
				t.Fatalf("got %v", s)
			}
		case <-time.After(provenanceWait / 2):
			t.Fatalf("interrupt %d waited for an outer process that never answered", i+1)
		}
	}
}

// An outer process that reported once and then died counts as it last reported; the launcher's own count carries on.
func TestProvenanceOuterProcessGoneKeepsItsLastCount(t *testing.T) {
	r := newProvenanceRig(t)
	r.send("outer", syscall.SIGINT)
	r.interrupts(t, syscall.SIGINT, 1)
	r.gate.Close() // the channel closes under the launcher
	r.send("launcher", syscall.SIGINT)
	r.interrupts(t, syscall.SIGINT, 0) // (1,1): the dead outer process's interrupt and this one are the group's
	r.send("launcher", syscall.SIGINT)
	r.interrupts(t, syscall.SIGINT, 1)
}

// With no listening launcher the outer process keeps forwarding by signal itself.
func TestProvenanceGateWithoutALauncherForwardsItself(t *testing.T) {
	_, oc := net.Pipe()
	g := NewGate(oc)
	defer g.Close()
	if g.live.Load() || g.Note(syscall.SIGINT) {
		t.Fatal("a gate nobody announced to judged an interrupt")
	}
}

// A report that jumps far ahead (the channel is private, but a count is only a number) makes the second interrupt and
// no more: the loop does not emit billions, and it goes on counting.
func TestProvenanceAHugeReportIsBounded(t *testing.T) {
	lc, oc := net.Pipe()
	in := make(chan os.Signal, 16)
	a := NewArbiter(lc, in)
	defer a.Close()
	defer oc.Close()
	hello := make([]byte, 1)
	if _, err := oc.Read(hello); err != nil || hello[0] != frameHello {
		t.Fatalf("hello: %v %q", err, hello)
	}
	var b [17]byte
	b[0] = frameNote
	binary.BigEndian.PutUint64(b[1:9], 1<<62)
	if _, err := oc.Write(b[:]); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < maxEmitted; i++ {
		select {
		case <-a.Signals():
		case <-time.After(3 * time.Second):
			t.Fatalf("interrupt %d never arrived", i+1)
		}
	}
	select {
	case <-a.Signals():
		t.Fatal("more than the two a run can use")
	case <-time.After(100 * time.Millisecond):
	}
	in <- syscall.SIGTERM
	select {
	case s := <-a.Signals():
		if s != syscall.SIGTERM {
			t.Fatalf("got %v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loop stopped after a huge report")
	}
}

// stubConn is a channel whose reads and writes the test scripts: it hands out the bytes in in, then blocks until it is
// closed; its writes succeed until failAfter of them have been made.
type stubConn struct {
	in        chan byte
	closed    chan struct{}
	once      sync.Once
	failAfter int64
	writes    atomic.Int64
}

func newStubConn(failAfter int64) *stubConn {
	return &stubConn{in: make(chan byte, 16), closed: make(chan struct{}), failAfter: failAfter}
}

func (c *stubConn) Read(p []byte) (int, error) {
	select {
	case b := <-c.in:
		p[0] = b
		return 1, nil
	case <-c.closed:
		return 0, io.EOF
	}
}

func (c *stubConn) Write(p []byte) (int, error) {
	if c.writes.Add(1) > c.failAfter {
		return 0, io.ErrClosedPipe
	}
	return len(p), nil
}

func (c *stubConn) SetWriteDeadline(time.Time) error { return nil }

func (c *stubConn) Close() error { c.once.Do(func() { close(c.closed) }); return nil }

// An outer process whose note cannot be written takes the interrupt back: Note says false, so its owner forwards by
// signal, and its count does not keep the interrupt it handed back.
func TestProvenanceGateWhoseWriteFailsForwardsItself(t *testing.T) {
	c := newStubConn(1) // the acknowledgement goes out; the first note does not
	g := NewGate(c)
	defer g.Close()
	c.in <- frameHello
	for end := time.Now().Add(3 * time.Second); !g.live.Load() || c.writes.Load() < 1; time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the gate never went live and acknowledged")
		}
	}
	if g.Note(syscall.SIGINT) {
		t.Fatal("the gate said the launcher will judge an interrupt it could not report")
	}
	if g.live.Load() {
		t.Fatal("the gate stayed live after a failed write")
	}
	if g.seen != (counts{}) {
		t.Fatalf("the gate kept %v of an interrupt it handed back", g.seen)
	}
	if g.Note(syscall.SIGQUIT) {
		t.Fatal("a gate that is not live judged a QUIT")
	}
}

// A frame the launcher does not know ends the channel for both sides: the outer process's next write fails, so an
// interrupt sent to it alone is forwarded by signal and not lost in a socket nobody reads; the launcher counts alone.
func TestProvenanceUnknownFrameEndsTheChannel(t *testing.T) {
	r := newProvenanceRig(t)
	if err := r.gate.w.write([]byte{'X'}); err != nil {
		t.Fatal(err)
	}
	for end := time.Now().Add(3 * time.Second); r.gate.live.Load(); time.Sleep(time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal("the outer process still thinks the launcher listens")
		}
	}
	r.send("outer", syscall.SIGINT)
	select {
	case s := <-r.outerHandled:
		if s != syscall.SIGINT {
			t.Fatalf("got %v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("an interrupt sent to the outer process alone was lost")
	}
	r.send("launcher", syscall.SIGINT)
	r.interrupts(t, syscall.SIGINT, 1)
}
