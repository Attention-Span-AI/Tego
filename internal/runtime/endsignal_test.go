// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

type escalationNotice chan struct{}

func (k escalationNotice) Kill() error { close(k); return nil }

// graceHandler is a signal handler with a stop_grace of grace, the stop marker present or not. The killer is a stand-in
// (cgroup.kill is not written); the handler's own state machine is the real one.
func graceHandler(t *testing.T, grace time.Duration, marker bool) (*launch.SignalHandler, <-chan struct{}) {
	t.Helper()
	killed := make(escalationNotice)
	h, err := launch.NewSignalHandler(nopSignaler{}, killed, launch.SignalPolicy{
		StopGrace: grace, StopRequested: func() bool { return marker }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.Run(ctx, nil); err != nil {
			t.Error(err)
		}
	})
	return h, killed
}

// TestRunEndSignalNamesTheSignalThatStartedTheStop pins what run_end.signal means for a run that was asked to stop
// (spec/identity/RUN-IDENTITY.md "Signals": `run_end reason=signal signal=<n> escalated=<bool>`). The agent's wait
// status says 9 after cgroup.kill, and the line used to carry that; `escalated` already says the kill happened, and
// signal is the one that started the stop. Not escalated, it is what the kernel reported for the agent (an agent that
// the first signal did not end, and that then died of another signal, records that one), else the signal that started
// the stop when the agent left by its own exit. Each escalated row drives the handler's real sequence: a stop_grace
// that runs out (a real timer), and a second SIGINT within the double-interrupt window under an hour of grace.
func TestRunEndSignalNamesTheSignalThatStartedTheStop(t *testing.T) {
	killed := syscall.WaitStatus(uint32(syscall.SIGKILL))
	for _, tc := range []struct {
		name    string
		grace   time.Duration
		marker  bool
		signals []syscall.Signal
		status  syscall.WaitStatus
		reason  identity.EndReason
		wantSig int
		escal   bool
	}{
		{"SIGTERM, the agent dies of it within the grace", time.Hour, false, []syscall.Signal{syscall.SIGTERM},
			syscall.WaitStatus(uint32(syscall.SIGTERM)), identity.ReasonSignal, int(syscall.SIGTERM), false},
		{"SIGHUP, the agent exits by itself within the grace", time.Hour, false, []syscall.Signal{syscall.SIGHUP},
			syscall.WaitStatus(3 << 8), identity.ReasonSignal, int(syscall.SIGHUP), false},
		{"SIGTERM, the agent dies of SIGABRT within the grace", time.Hour, false, []syscall.Signal{syscall.SIGTERM},
			syscall.WaitStatus(uint32(syscall.SIGABRT)), identity.ReasonSignal, int(syscall.SIGABRT), false},
		{"SIGTERM, the grace runs out", 20 * time.Millisecond, false, []syscall.Signal{syscall.SIGTERM},
			killed, identity.ReasonSignal, int(syscall.SIGTERM), true},
		{"two SIGINT in a row under a long grace", time.Hour, false, []syscall.Signal{syscall.SIGINT, syscall.SIGINT},
			killed, identity.ReasonSignal, int(syscall.SIGINT), true},
		{"tego stop, the agent leaves within the grace", time.Hour, true, []syscall.Signal{syscall.SIGTERM},
			syscall.WaitStatus(uint32(syscall.SIGTERM)), identity.ReasonStopped, int(syscall.SIGTERM), false},
		{"tego stop, the grace runs out", 20 * time.Millisecond, true, []syscall.Signal{syscall.SIGTERM},
			killed, identity.ReasonStopped, int(syscall.SIGTERM), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, killed := graceHandler(t, tc.grace, tc.marker)
			r := &runner{signals: h}
			r.wait.Status = tc.status
			for _, s := range tc.signals {
				h.Handle(s)
			}
			if tc.escal {
				select {
				case <-killed:
				case <-time.After(10 * time.Second):
					t.Fatal("the handler did not escalate")
				}
			}
			reason, _, sig, escalated := r.ending()
			if reason != tc.reason || sig != tc.wantSig || escalated != tc.escal {
				t.Fatalf("run_end reason=%s signal=%d escalated=%v, want %s %d %v", reason, sig, escalated,
					tc.reason, tc.wantSig, tc.escal)
			}
		})
	}
}

// TestRunEndSignalOfALimitKillIsTheKill keeps the other half: a run a limit ended was ended by cgroup.kill, and
// its line says 9, even when a stop signal had also arrived and escalated.
func TestRunEndSignalOfALimitKillIsTheKill(t *testing.T) {
	h, _ := graceHandler(t, time.Hour, false)
	r := &runner{signals: h}
	r.wait.Status = syscall.WaitStatus(uint32(syscall.SIGKILL))
	h.Handle(syscall.SIGTERM)
	h.Escalate()
	r.terminal = identity.ReasonLimit
	reason, _, sig, escalated := r.ending()
	if reason != identity.ReasonLimit || sig != int(syscall.SIGKILL) || !escalated {
		t.Fatalf("run_end reason=%s signal=%d escalated=%v, want limit 9 true", reason, sig, escalated)
	}
}
