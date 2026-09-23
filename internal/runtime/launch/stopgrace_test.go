// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"syscall"
	"testing"
	"time"
)

// graceHandler is a handler whose marker says stopped and asks for requested.
func graceHandler(t *testing.T, stopGrace, requested time.Duration, marker bool) (*SignalHandler, *fakeKiller) {
	t.Helper()
	k := newFakeKiller()
	h, err := NewSignalHandler(&fakeSignaler{}, k, SignalPolicy{
		StopGrace:      stopGrace,
		StopRequested:  func() bool { return marker },
		RequestedGrace: func() time.Duration { return requested },
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.stopTimer)
	return h, k
}

// killedWithin reports whether the killer fired within d.
func killedWithin(k *fakeKiller, d time.Duration) bool {
	select {
	case <-k.done:
		return true
	case <-time.After(d):
		return false
	}
}

// TestRequestedGraceOutlastsStopGrace is STOP-GRACE-FLAG: `tego stop --grace` longer than the
// machine's stop_grace is the launcher's own grace for that stop. The launcher used to arm its timer
// with stop_grace alone, so it killed the run before the requested grace was up.
//
// Also pins runtime-launch.md R9: a `tego stop --grace` SIGTERM runs the timer for the requested grace.
func TestRequestedGraceOutlastsStopGrace(t *testing.T) {
	h, k := graceHandler(t, 20*time.Millisecond, 400*time.Millisecond, true)
	start := time.Now()
	h.Handle(syscall.SIGTERM)
	if killedWithin(k, 200*time.Millisecond) {
		t.Fatalf("cgroup.kill after %v: the requested 400ms grace was not honoured", time.Since(start))
	}
	if !killedWithin(k, 5*time.Second) {
		t.Fatal("cgroup.kill never written after the requested grace")
	}
	if o := h.Outcome(); !o.Stopped || !o.Escalated {
		t.Fatalf("outcome %+v", o)
	}
}

// TestRequestedGraceCanBeShorter: a --grace shorter than stop_grace kills sooner.
func TestRequestedGraceCanBeShorter(t *testing.T) {
	h, k := graceHandler(t, time.Hour, 20*time.Millisecond, true)
	h.Handle(syscall.SIGTERM)
	if !killedWithin(k, 5*time.Second) {
		t.Fatal("the requested 20ms grace did not replace an hour of stop_grace")
	}
}

// TestRequestedGraceNeedsTheStopsOwnSIGTERM: the requested grace belongs to the SIGTERM `tego stop`
// sends. Without a marker, with a marker that asks for nothing, or armed by SIGINT or SIGHUP, the
// timer runs for the machine's stop_grace.
//
// Also pins runtime-launch.md R9: only SIGTERM carries the requested grace.
func TestRequestedGraceNeedsTheStopsOwnSIGTERM(t *testing.T) {
	cases := []struct {
		name      string
		sig       syscall.Signal
		marker    bool
		requested time.Duration
	}{
		{"no marker", syscall.SIGTERM, false, time.Hour},
		{"a marker asking for nothing", syscall.SIGTERM, true, 0},
		{"SIGINT finding a marker", syscall.SIGINT, true, time.Hour},
		{"SIGHUP finding a marker", syscall.SIGHUP, true, time.Hour},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, k := graceHandler(t, 20*time.Millisecond, tc.requested, tc.marker)
			h.Handle(tc.sig)
			if !killedWithin(k, 5*time.Second) {
				t.Fatal("the machine's 20ms stop_grace did not apply")
			}
		})
	}
}

// TestLaterTriggerNeverExtendsTheTimer: once armed, the timer is neither restarted nor lengthened by a
// later stop signal, whatever grace that one's marker asks for — a process that can signal the
// launcher must not be able to postpone the escalation.
//
// Also pins runtime-launch.md R9: a later trigger never extends the timer.
func TestLaterTriggerNeverExtendsTheTimer(t *testing.T) {
	marker := false
	k := newFakeKiller()
	h, err := NewSignalHandler(&fakeSignaler{}, k, SignalPolicy{
		StopGrace:      80 * time.Millisecond,
		StopRequested:  func() bool { return marker },
		RequestedGrace: func() time.Duration { return time.Hour },
	})
	if err != nil {
		t.Fatal(err)
	}
	defer h.stopTimer()
	h.Handle(syscall.SIGTERM)
	marker = true
	h.Handle(syscall.SIGTERM)
	if !killedWithin(k, 5*time.Second) {
		t.Fatal("a later SIGTERM with a marker extended the first trigger's stop_grace")
	}
}
