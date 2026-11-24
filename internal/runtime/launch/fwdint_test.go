// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

// provenanceRig is both processes of a user-scope run with their signal channels in the hands of the test: a send to
// "the group" puts the signal on both, a send to one process on that process alone.
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
	r.gate = NewGate(oc, func() error { r.outerIn <- interruptMarker; return nil })
	go func() { // the outer process's loop, as executeUserScope runs it
		defer close(r.stopped)
		for {
			select {
			case <-r.stop:
				return
			case s := <-r.outerIn:
				if IsMarker(s) {
					continue
				}
				if !r.gate.Note(s.(syscall.Signal)) {
					r.outerHandled <- s
				}
			case <-r.gate.Queries():
				for _, o := range r.gate.Answer(r.outerIn) {
					r.outerHandled <- o
				}
			}
		}
	}()
	r.arb = NewArbiter(lc, r.launcherIn, func() error { r.launcherIn <- interruptMarker; return nil })
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

func (r *provenanceRig) send(to string, sig syscall.Signal) {
	if to != "outer" {
		r.launcherIn <- sig
	}
	if to != "launcher" {
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
		t.Run(sig.String(), func(t *testing.T) {
			r := newProvenanceRig(t)
			r.send("group", sig)
			r.interrupts(t, sig, 1)
			select {
			case s := <-r.outerHandled:
				t.Fatalf("the outer process forwarded %v by signal as well", s)
			default:
			}
		})
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

// Deliberate repeats stay repeats, whichever process each one reached: the pairing is by counts since the last
// settled question, never by a window of time.
func TestProvenanceDeliberateRepeatsAreKept(t *testing.T) {
	for _, tc := range [][]string{
		{"group", "group"},
		{"launcher", "outer"},
		{"outer", "launcher"},
		{"outer", "group"},
		{"group", "launcher"},
		{"launcher", "launcher"},
		{"outer", "outer"},
	} {
		t.Run(tc[0]+" then "+tc[1], func(t *testing.T) {
			r := newProvenanceRig(t)
			for _, to := range tc {
				r.send(to, syscall.SIGINT)
				r.interrupts(t, syscall.SIGINT, 1)
			}
		})
	}
}

func TestProvenanceOtherSignalsPassUnchanged(t *testing.T) {
	r := newProvenanceRig(t)
	r.launcherIn <- syscall.SIGTERM
	select {
	case s := <-r.arb.Signals():
		if s != syscall.SIGTERM {
			t.Fatalf("got %v", s)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SIGTERM was held back")
	}
	// A stop signal that reaches the outer process while it answers is handed back to be handled, not lost.
	r.outerIn <- syscall.SIGHUP
	r.launcherIn <- syscall.SIGINT
	r.interrupts(t, syscall.SIGINT, 1)
}

// An outer process that does not answer holds nothing back: the launcher counts its own arrivals, as before.
func TestProvenanceSilentOuterProcessDoesNotHoldBackAnInterrupt(t *testing.T) {
	lc, oc := net.Pipe()
	in := make(chan os.Signal, 16)
	a := NewArbiter(lc, in, func() error { in <- interruptMarker; return nil })
	defer a.Close()
	go func() { // reads the hello and the question, never answers
		buf := make([]byte, 1)
		for {
			if _, err := oc.Read(buf); err != nil {
				return
			}
		}
	}()
	defer oc.Close()
	in <- syscall.SIGINT
	select {
	case s := <-a.Signals():
		if s != syscall.SIGINT {
			t.Fatalf("got %v", s)
		}
	case <-time.After(3 * provenanceWait):
		t.Fatal("the interrupt waited for an outer process that never answered")
	}
	in <- syscall.SIGINT // the channel is judged broken: the next one needs no wait
	select {
	case <-a.Signals():
	case <-time.After(provenanceWait / 2):
		t.Fatal("a second interrupt waited again")
	}
}

// With no listening launcher the outer process keeps forwarding by signal itself.
func TestProvenanceGateWithoutALauncherForwardsItself(t *testing.T) {
	_, oc := net.Pipe()
	g := NewGate(oc, nil)
	defer g.Close()
	if g.live.Load() || g.Note(syscall.SIGINT) {
		t.Fatal("a gate nobody announced to judged an interrupt")
	}
}
