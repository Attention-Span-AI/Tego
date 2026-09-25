// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os/exec"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// An unmetered report under a budget that arrives once the run has quiesced — its cgroup empty, or tego's own
// teardown begun, so the report is a request that teardown aborted — records a gap with its count and leaves the
// run's end as the agent's own exit; before that it still ends the run, reason error (ADR 0037).
func TestUnmeteredAfterTheAgentExitedDoesNotChangeTheEnd(t *testing.T) {
	t.Run("before exit", func(t *testing.T) {
		r, cgroups, _, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
		source.ReportUnmetered(meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}, 1, "POST /v1/messages: no response")
		if reason, _, _, _ := r.ending(); reason != identity.ReasonError || cgroups.killed != 1 {
			t.Fatalf("before the exit: %q after %d kills, want error and one kill", reason, cgroups.killed)
		}
	})
	t.Run("after exit", func(t *testing.T) {
		r, cgroups, sink, _ := budgetRunner(t, agent.ResolvedLimits{CostUSD: 1})
		r.quiesced.Store(true)
		source.ReportUnmetered(meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}, 2, "POST /v1/messages: no response")
		r.pipe.drain()
		reason, code, _, _ := r.ending()
		if reason != identity.ReasonExit || code != 0 || cgroups.killed != 0 {
			t.Fatalf("after the exit: reason %q code %d after %d kills, want a clean exit and no kill", reason, code, cgroups.killed)
		}
		if !hasUnmeteredAfterExitGap(t, sink, 2) {
			t.Errorf("no gap what=capture why=%s count=2 in the record", GapUnmeteredAfterExit)
		}
	})
}

func hasUnmeteredAfterExitGap(t *testing.T, sink *collectSink, count int) bool {
	t.Helper()
	for _, ev := range sink.all() {
		if ev.Kind != record.KindGap {
			continue
		}
		var g record.GapPayload
		if err := ev.DecodePayload(&g); err != nil {
			t.Fatal(err)
		}
		if g.What == record.GapCapture && g.Why == GapUnmeteredAfterExit && g.Count == count {
			return true
		}
	}
	return false
}

// populatedCgroups is fakeCgroups whose cgroup stays populated until empty is closed: a descendant outliving
// the agent's main process. waiting is closed when awaitExit, having reaped the main process, waits on it.
type populatedCgroups struct {
	*fakeCgroups
	waiting chan struct{}
	empty   chan struct{}
}

func (p *populatedCgroups) WaitEmpty(ctx context.Context, _ cgroup.Cgroup) error {
	select {
	case <-p.waiting:
	default:
		close(p.waiting)
	}
	select {
	case <-p.empty:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// startTrue starts `true` as the agent's main process and returns it as a launch.Child.
func startTrue(t *testing.T) *launch.Child {
	t.Helper()
	cmd := exec.Command("true")
	if err := cmd.Start(); err != nil {
		t.Skipf("no true binary to stand in for the agent: %v", err)
	}
	fd, err := sys.PidfdOpenProcessFD(cmd.Process.Pid)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	return &launch.Child{PID: cmd.Process.Pid, PidFD: fd}
}

// A descendant that outlives the agent's main process (`sh -c 'agent & exit 0'`) can still spend: while the
// run's cgroup is populated, an unmetered report under a budget still ends the run, reason error, and kills the
// tree. Only once the cgroup is empty does a later report become a gap.
func TestUnmeteredWhileADescendantOutlivesTheMainProcessEndsTheRun(t *testing.T) {
	r, fake, sink, _ := budgetRunner(t, agent.ResolvedLimits{Tokens: 1000})
	cgroups := &populatedCgroups{fakeCgroups: fake, waiting: make(chan struct{}), empty: make(chan struct{})}
	r.cgm = cgroups
	r.child = startTrue(t)
	done := make(chan struct{})
	go func() {
		defer close(done)
		r.awaitExit(context.Background())
	}()
	<-cgroups.waiting // the main process is reaped; the cgroup is still populated
	lane := meteredLane{Sink: r.queue.Lane(LaneCapture), r: r}
	source.ReportUnmetered(lane, 1, "POST /v1/messages: no response")
	if reason, _, _, _ := r.ending(); reason != identity.ReasonError || fake.killed != 1 {
		t.Fatalf("main exited, cgroup populated: reason %q after %d kills, want error and one kill", reason, fake.killed)
	}
	close(cgroups.empty)
	<-done
	source.ReportUnmetered(lane, 3, "POST /v1/messages: no response")
	r.pipe.drain()
	if fake.killed != 1 {
		t.Errorf("a report after the cgroup emptied killed again: %d kills", fake.killed)
	}
	if !hasUnmeteredAfterExitGap(t, sink, 3) {
		t.Errorf("no gap what=capture why=%s count=3 after the cgroup emptied", GapUnmeteredAfterExit)
	}
}

// awaitExit marks the run quiesced once the whole cgroup is empty, not when it has reaped the main process.
func TestAwaitExitMarksTheRunQuiescedOnceTheCgroupIsEmpty(t *testing.T) {
	cg := &fakeCgroups{root: t.TempDir()}
	r := &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root},
		queue: NewQueue(8), child: startTrue(t)}
	if r.quiesced.Load() {
		t.Fatal("marked quiesced before the wait")
	}
	r.awaitExit(context.Background())
	if !r.quiesced.Load() {
		t.Fatal("awaitExit saw the cgroup empty and did not mark the run quiesced")
	}
}
