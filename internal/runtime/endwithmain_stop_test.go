// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// stopRun is a runner whose agent's main process has already died of sig (so the wait status says so), with one
// more process left in the run's cgroup, and a real signal handler on a cgroup whose cgroup.kill the handler and
// endWithMain both write. The test, not a clock, decides which of the two kills comes first.
type stopRun struct {
	r  *runner
	cg *emptyingCgroups
	h  *launch.SignalHandler
}

func newStopRun(t *testing.T, mainSig syscall.Signal, marker bool) *stopRun {
	t.Helper()
	child, mainPID := sleepingChild(t)
	if err := unix.Kill(mainPID, unix.Signal(mainSig)); err != nil {
		t.Fatal(err)
	}
	_, leftPID := sleepingChild(t) // stands in for what the main process left running
	cg := newEmptyingCgroups(t, 0)
	if err := os.WriteFile(filepath.Join(cg.root, "cgroup.procs"), []byte(strconv.Itoa(leftPID)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	h, err := launch.NewSignalHandler(nopSignaler{}, cgroup.Killer{Manager: cg, Cgroup: cgroup.Cgroup{Path: cg.root}},
		launch.SignalPolicy{StopGrace: time.Hour, StopRequested: func() bool { return marker }})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { // the run's shutdown: the handler's worker returns and its timer is stopped
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := h.Run(ctx, nil); err != nil {
			t.Error(err)
		}
	})
	r := &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root}, queue: NewQueue(8),
		child: child, rt: &agent.RuleTable{Contract: &agent.Contract{}}, stopGrace: 100 * time.Millisecond, signals: h}
	return &stopRun{r: r, cg: cg, h: h}
}

func (s *stopRun) kills() int {
	s.cg.mu.Lock()
	defer s.cg.mu.Unlock()
	return s.cg.kills
}

// TestRunEndEscalatedWhenTheEndOfTheMainProcessKilledAStop: a run that was asked to stop, whose main process left on
// the signal and left processes behind that ignore it, was ended by cgroup.kill after stop_grace whichever of the
// two grace timers (the signal handler's, from the first stop signal; endWithMain's, from the main process's exit)
// wrote it. run_end must say escalated in both orders, with the signal and exit code the spec gives an escalated
// stop, and a run nobody asked to stop must not.
func TestRunEndEscalatedWhenTheEndOfTheMainProcessKilledAStop(t *testing.T) {
	for _, tc := range []struct {
		name     string
		first    syscall.Signal // the stop signal the handler saw, 0 for none
		mainSig  syscall.Signal // what the main process died of
		marker   bool           // a `tego stop`
		handler  bool           // the handler's own timer fires first (the reverse order)
		reason   identity.EndReason
		wantCode int
		wantSig  int
		escal    bool
		kills    int
	}{
		// The order the Debian 13 row saw: the main process left, the handler's timer is still pending when
		// endWithMain's own grace (timed from the exit) runs out and writes the kill.
		{"Ctrl-C, endWithMain's kill first", syscall.SIGINT, syscall.SIGINT, false, false,
			identity.ReasonSignal, 130, int(syscall.SIGINT), true, 1},
		{"tego stop, endWithMain's kill first", syscall.SIGTERM, syscall.SIGTERM, true, false,
			identity.ReasonStopped, 137, int(syscall.SIGTERM), true, 1},
		// The other order: the handler's kill empties the cgroup, endWithMain's wait returns, it writes none.
		{"Ctrl-C, the handler's kill first", syscall.SIGINT, syscall.SIGINT, false, true,
			identity.ReasonSignal, 130, int(syscall.SIGINT), true, 1},
		{"tego stop, the handler's kill first", syscall.SIGTERM, syscall.SIGTERM, true, true,
			identity.ReasonStopped, 137, int(syscall.SIGTERM), true, 1},
		// Nobody asked it to stop: the main process died of a signal of its own (SIGTERM, say) and what it left
		// is ended by endWithMain's kill, which is not a stop: no escalation, the main process's own status.
		{"no stop, the main process died of SIGTERM", 0, syscall.SIGTERM, false, false,
			identity.ReasonExit, 143, int(syscall.SIGTERM), false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := newStopRun(t, tc.mainSig, tc.marker)
			if tc.first != 0 {
				s.h.Handle(tc.first) // arms the handler's timer (an hour: it fires only if the test says so)
			}
			if tc.handler {
				s.h.Escalate()
			}
			s.r.awaitExit(context.Background())
			reason, code, sig, escalated := s.r.ending()
			if reason != tc.reason || code != tc.wantCode || sig != tc.wantSig || escalated != tc.escal {
				t.Errorf("run_end reason=%s exit_code=%d signal=%d escalated=%v, want %s %d %d %v (detail %q)",
					reason, code, sig, escalated, tc.reason, tc.wantCode, tc.wantSig, tc.escal, s.r.detail)
			}
			if got := s.kills(); got != tc.kills {
				t.Errorf("%d cgroup.kill writes, want %d", got, tc.kills)
			}
			if tc.handler && s.r.detail != "" {
				t.Errorf("the handler's kill emptied the cgroup, yet endWithMain said %q", s.r.detail)
			}
		})
	}
}
