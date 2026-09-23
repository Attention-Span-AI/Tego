// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/launch"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// killingCgroups is emptyingCgroups whose cgroup.kill also SIGKILLs one real process, the child a test hands
// awaitExit, so the reap after the kill has something to reap. The tree still empties on emptyingCgroups'
// schedule, later than the reap, as descendants the kill signalled go on exiting after the child is gone.
type killingCgroups struct {
	*emptyingCgroups
	pid int
}

func (c *killingCgroups) Kill(cg cgroup.Cgroup) error {
	_ = unix.Kill(c.pid, unix.SIGKILL)
	return c.emptyingCgroups.Kill(cg)
}

// sleepingChild starts a process that outlives the test's own wait and wraps it as the launcher's child, by its
// pidfd, the way launch.Child.Wait reads it.
func sleepingChild(t *testing.T) (*launch.Child, int) {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("no sleep binary to stand in for the agent: %v", err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	fd, err := sys.PidfdOpenProcessFD(pid)
	if err != nil {
		t.Skipf("pidfd_open: %v", err)
	}
	t.Cleanup(func() { _ = fd.Close() })
	return &launch.Child{PID: pid, PidFD: fd}, pid
}

// TestAwaitExitWaitsForTheTreeOnCancel is step 12 on the cancellation branch, through awaitExit itself: the run's
// context has ended, so the child's Wait returns its error, awaitExit kills the tree and reaps the child, and it
// must then return only once the cgroup has emptied, so the final drains that follow read every sample of the
// run (enforce-cgroup-observe.md §4 Stop). A tree that never empties is bounded by killWait and said with gap
// what=record why=ringbuf-undrained. awaitExit used to wait on the run's own, already cancelled, context there,
// which returned at once with the tree still exiting and said nothing; TestAwaitEmptyOutlivesTheRunContext
// covers awaitEmpty alone, and nothing covered the call.
func TestAwaitExitWaitsForTheTreeOnCancel(t *testing.T) {
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	newRunner := func(t *testing.T, emptyAfter time.Duration) (*runner, *killingCgroups) {
		child, pid := sleepingChild(t)
		cg := &killingCgroups{emptyingCgroups: newEmptyingCgroups(t, emptyAfter), pid: pid}
		return &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root},
			queue: NewQueue(8), kernelRecord: &plainSource{name: "observe"}, child: child}, cg
	}

	t.Run("the tree empties after the child is reaped", func(t *testing.T) {
		r, cg := newRunner(t, 300*time.Millisecond)
		r.awaitExit(cancelled)
		if !r.wait.Status.Signaled() || r.wait.Status.Signal() != unix.SIGKILL {
			t.Fatalf("the child was not killed and reaped: %+v", r.wait)
		}
		if !cg.emptied() {
			t.Fatal("awaitExit returned with the killed tree still in the cgroup: the final drains would miss its exits")
		}
		if cg.kills != 1 {
			t.Errorf("%d kills, want awaitExit's one", cg.kills)
		}
		select {
		case ev := <-r.queue.C():
			t.Errorf("a gap %s for a tree that emptied", ev.Payload)
		default:
		}
	})
	t.Run("a tree the kill never empties is bounded and said", func(t *testing.T) {
		r, _ := newRunner(t, -1)
		r.killWait = 50 * time.Millisecond
		start := time.Now()
		r.awaitExit(cancelled)
		if d := time.Since(start); d > 5*time.Second {
			t.Errorf("awaitExit took %s", d)
		}
		select {
		case ev := <-r.queue.C():
			var p record.GapPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			if p.What != record.GapRecord || p.Why != GapRingbufUndrained || p.Count != 0 {
				t.Fatalf("gap %+v, want what=record why=ringbuf-undrained with no count", p)
			}
		default:
			t.Fatal("no ringbuf-undrained gap for a tree that outlived the kill: samples after the drain go unsaid")
		}
	})
}

// TestAwaitExitEndsWhatTheMainProcessLeftRunning (runtime-launch.md case 24): once the
// agent's main process has exited, what it left running in the run's cgroup gets stop_grace to exit, then the tree
// is killed, the run_end detail names the processes the kill ended, and the main process's own status stands. With
// keep_descendants: true the run waits for the tree as before, and no kill is written.
func TestAwaitExitEndsWhatTheMainProcessLeftRunning(t *testing.T) {
	newRunner := func(t *testing.T, keep bool) (*runner, *emptyingCgroups, int) {
		_, pid := sleepingChild(t) // stands in for a descendant the main process left in the cgroup
		cg := newEmptyingCgroups(t, 0)
		procs := strconv.Itoa(pid) + "\n"
		if err := os.WriteFile(filepath.Join(cg.root, "cgroup.procs"), []byte(procs), 0o600); err != nil {
			t.Fatal(err)
		}
		rt := &agent.RuleTable{Contract: &agent.Contract{KeepDescendants: keep}}
		return &runner{log: slog.New(slog.DiscardHandler), cgm: cg, cg: cgroup.Cgroup{Path: cg.root},
			queue: NewQueue(8), child: startTrue(t), rt: rt, stopGrace: 200 * time.Millisecond}, cg, pid
	}

	t.Run("the rest is killed after stop_grace", func(t *testing.T) {
		r, cg, pid := newRunner(t, false)
		start := time.Now()
		r.awaitExit(context.Background())
		if d := time.Since(start); d < r.stopGrace || d > 5*time.Second {
			t.Errorf("awaitExit took %s, want stop_grace (%s) and little more", d, r.stopGrace)
		}
		if !r.wait.Status.Exited() || r.wait.Status.ExitStatus() != 0 {
			t.Errorf("the main process's status was not kept: %+v", r.wait)
		}
		if cg.kills != 1 {
			t.Errorf("%d kills, want one at the end of stop_grace", cg.kills)
		}
		reason, _, _, _ := r.ending()
		if reason != identity.ReasonExit {
			t.Errorf("reason %q, want exit: the main process ended the run", reason)
		}
		want := strconv.Itoa(pid) + " sleep"
		if !strings.Contains(r.detail, "main process exited") || !strings.Contains(r.detail, want) {
			t.Errorf("run_end detail %q does not name the process the kill ended (%q)", r.detail, want)
		}
	})
	t.Run("keep_descendants waits for the tree", func(t *testing.T) {
		r, cg, _ := newRunner(t, true)
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan struct{})
		go func() { defer close(done); r.awaitExit(ctx) }()
		time.Sleep(3 * r.stopGrace)
		cg.mu.Lock()
		kills := cg.kills
		cg.mu.Unlock()
		cancel()
		<-done
		if kills != 0 {
			t.Errorf("%d kills within 3 x stop_grace under keep_descendants, want none", kills)
		}
	})
}
