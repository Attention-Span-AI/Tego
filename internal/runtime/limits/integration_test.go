// SPDX-License-Identifier: Apache-2.0

//go:build integration

// The tests here trip a budget against a real cgroup v2 scope with a real process in it, which is
// the half a fake Killer cannot prove: that a breach actually ends the run's processes. Everything
// they use is unprivileged on a 6.x kernel with a delegated cgroup v2 subtree; a machine without
// delegation skips with the reason, never a false pass.
package limits

import (
	"context"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// scopeOrSkip creates one run scope for this test, or skips when nothing is delegated to this uid.
func scopeOrSkip(t *testing.T) (*cgroup.FS, cgroup.Cgroup) {
	t.Helper()
	fs, err := cgroup.Detect(os.Getuid())
	if errors.Is(err, cgroup.ErrNotDelegated) {
		t.Skipf("no delegated cgroup v2 subtree: %v", err)
	}
	if err != nil {
		t.Fatalf("detect cgroup: %v", err)
	}
	id, err := identity.NewRunID(identity.HostID([]byte("limits-integration")), time.Now(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := fs.Create("limits-itest", string(id))
	if err != nil {
		t.Fatalf("create scope: %v", err)
	}
	t.Cleanup(func() { _ = fs.Remove(context.Background(), c) })
	return fs, c
}

// sleeperIn starts a long sleep and moves it into the scope, returning the command to wait on.
func sleeperIn(t *testing.T, c cgroup.Cgroup) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("sleep", "300")
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sleep: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
	})
	procs := filepath.Join(c.Path, "cgroup.procs")
	if err := os.WriteFile(procs, []byte(strconv.Itoa(cmd.Process.Pid)), 0o644); err != nil {
		t.Skipf("cannot move a process into %s: %v", procs, err)
	}
	return cmd
}

// TestIntegrationCostCeilingKillsTheRun is acceptance §12.4: a $25 budget stops a run. The watcher
// sees the usage, appends its limit event, and cgroup.kill ends the process for real — which the
// facade turns into run_end reason=limit and exit 124.
func TestIntegrationCostCeilingKillsTheRun(t *testing.T) {
	fs, c := scopeOrSkip(t)
	cmd := sleeperIn(t, c)

	sink := &fakeSink{}
	w := NewWatcher(agent.ResolvedLimits{CostUSD: 25}, testTable(), fs, c, &fakeClock{}, sink)
	w.Observe(runStart(1_000))
	mono := uint64(1_000)
	for range 20 {
		mono += 1_000_000
		w.Observe(response(mono, "claude-sonnet-4-5-20250929", 1_000_000, 0, 0, 0)) // $3 a turn
		if _, tripped := w.Tripped(); tripped {
			break
		}
	}
	b, tripped := w.Tripped()
	if !tripped || b.Which != record.LimitCostUSD {
		t.Fatalf("breach %+v tripped=%v, want a cost breach", b, tripped)
	}
	if n := len(sink.kinds(record.KindLimit)); n != 1 {
		t.Fatalf("%d limit events, want 1", n)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := fs.WaitEmpty(ctx, c); err != nil {
		t.Fatalf("the scope never emptied after the breach: %v", err)
	}
	state, err := cmd.Process.Wait()
	if err != nil {
		t.Fatalf("wait: %v", err)
	}
	ws, ok := state.Sys().(syscall.WaitStatus)
	if !ok || !ws.Signaled() || ws.Signal() != syscall.SIGKILL {
		t.Fatalf("the agent ended as %v, want SIGKILL from cgroup.kill", state)
	}
	if code := identity.ExitCode(identity.ReasonLimit, ws, false, identity.ExecFailureNone); code != identity.ExitLimit {
		t.Fatalf("a limit run exits %d, want 124", code)
	}
}

// TestIntegrationRepeatsKillsTheRun is acceptance §12.4's other half against a real cgroup: the
// repeat detector stops a looping agent.
func TestIntegrationRepeatsKillsTheRun(t *testing.T) {
	fs, c := scopeOrSkip(t)
	cmd := sleeperIn(t, c)

	sink := &fakeSink{}
	w := NewWatcher(agent.ResolvedLimits{Repeats: 5}, nil, fs, c, &fakeClock{}, sink)
	w.Observe(runStart(1_000))
	mono := uint64(1_000)
	for step := 1; step <= 10; step++ {
		mono += 1_000_000
		w.Observe(decision(mono, step, "bash", "same-input-hash"))
	}
	if b, tripped := w.Tripped(); !tripped || b.Which != record.LimitRepeats {
		t.Fatalf("breach %+v tripped=%v, want a repeats breach", b, tripped)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	if err := fs.WaitEmpty(ctx, c); err != nil {
		t.Fatalf("the scope never emptied after the breach: %v", err)
	}
	if _, err := cmd.Process.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}
}
