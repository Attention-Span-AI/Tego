// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// runEndOf decodes a run directory's last line, which must be run_end.
func runEndOf(t *testing.T, dir string) record.RunEndPayload {
	t.Helper()
	evs := events(t, dir)
	last := evs[len(evs)-1]
	if last.Kind != record.KindRunEnd {
		t.Fatalf("the last line is %s, not run_end", last.Kind)
	}
	var end record.RunEndPayload
	if err := last.DecodePayload(&end); err != nil {
		t.Fatal(err)
	}
	return end
}

// TestMainProcessOOMIsReasonOOM: a main process the kernel OOM-kills empties the cgroup at once, well inside
// one limitPollInterval, and shutdown cancelled the watcher before it read memory.events. The final reading
// at shutdown makes run_end say oom (R10), not exit with signal 9.
//
// It skipped in both CI jobs, and wherever the host had free swap: memory.max alone bounds the RAM a cgroup
// holds, and the kernel reclaimed the agent's pages to swap instead of OOM-killing it, so the 1 GiB bytearray of
// a 64 MiB agent was written out to swap and the run ended exit 0. A memory cap now sets memory.swap.max to 0
// beside memory.max (ADR 0038), and the kernel must OOM-kill here, with swap or without it (checked with a
// 1.3 GiB swap device in the KVM guest, where it skipped before the fix).
func TestMainProcessOOMIsReasonOOM(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, strings.Replace(contractFor("ioom", []string{python}, []string{python, resolved}),
		"  pids: 128", "  pids: 128\n  memory: 64MiB", 1))
	if _, err := Run(context.Background(), f.rt, []string{python, "-c", "b = bytearray(1024*1024*1024)"}, f.deps(t, nil)); err != nil {
		var missing *cgroup.MissingControllerError
		if errors.As(err, &missing) {
			t.Skipf("the memory controller is not delegated to this subtree: %v", err)
		}
		t.Fatalf("Run: %v", err)
	}
	end := runEndOf(t, runDirs(t, f.root)[0])
	var oomKill uint64
	if end.Resources != nil && end.Resources.MemoryEvents != nil && end.Resources.MemoryEvents.OOMKill != nil {
		oomKill = *end.Resources.MemoryEvents.OOMKill
	}
	if oomKill == 0 {
		t.Fatalf("the kernel did not OOM-kill a 1 GiB allocation under memory: 64MiB: run_end %s exit %d, resources %+v",
			end.Reason, end.ExitCode, end.Resources)
	}
	if end.Reason != record.RunEndOOM {
		t.Fatalf("run_end reason=%s beside its own memory_events oom_kill=%d, want oom", end.Reason, oomKill)
	}
}

// TestPidsCapThenPromptExitIsReasonPids: a tree that meets pids.max and then exits promptly is still
// reason pids (R11), read at shutdown when the watcher's poll did not come round in time.
func TestPidsCapThenPromptExitIsReasonPids(t *testing.T) {
	f := newFixture(t, strings.Replace(
		contractFor("ipids2", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh", "/bin/true", "/usr/bin/true"}),
		"  pids: 128", "  pids: 12", 1))
	if _, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c",
		"i=0; while [ $i -lt 60 ]; do /bin/true & i=$((i+1)); done; wait; exit 0"}, f.deps(t, nil)); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if end := runEndOf(t, runDirs(t, f.root)[0]); end.Reason != record.RunEndPids {
		t.Fatalf("pids.max refused forks, but run_end reason=%s", end.Reason)
	}
}

// TestLedgerWriteFailureEndsTheRun: once the ledger refuses a line (here RLIMIT_FSIZE, standing in for a full
// disk; the kernel accepts part of a line and refuses the rest), the run cannot record what the agent does, so
// it ends: reason error with the cause in detail, the tree killed, and a run_end the cut-back ledger still
// takes, never an agent that runs on unrecorded to its own exit 0 (record-ledger.md §7).
//
// RLIMIT_FSIZE is the process's: lowered here it would refuse every file this test binary writes
// meanwhile, the testing package's own testlog.txt among them (CI run #27). So the test re-runs itself
// in a child process and only the child lowers it.
func TestLedgerWriteFailureEndsTheRun(t *testing.T) {
	if os.Getenv(fsizeChildEnv) == "" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestLedgerWriteFailureEndsTheRun$", "-test.v", "-test.timeout=2m")
		cmd.Env = append(os.Environ(), fsizeChildEnv+"=1")
		out, err := cmd.CombinedOutput()
		switch {
		case err != nil:
			t.Fatalf("the child run failed: %v\n%s", err, out)
		case bytes.Contains(out, []byte("--- SKIP")):
			t.Skipf("the child skipped:\n%s", out)
		case !bytes.Contains(out, []byte("--- PASS: TestLedgerWriteFailureEndsTheRun")):
			t.Fatalf("the child ran no test:\n%s", out)
		}
		return
	}
	f := newFixture(t, contractFor("itorn", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh", "/bin/true", "/usr/bin/true"}))
	deps := f.deps(t, nil) // builds the binary before the limit applies to this process's writes
	var old syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &old); err != nil {
		t.Fatal(err)
	}
	lim := old
	lim.Cur = 48 << 10
	if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &lim); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c",
		"i=0; while [ $i -lt 400 ]; do /bin/true; i=$((i+1)); done; sleep 60; exit 0"}, deps)
	_ = syscall.Setrlimit(syscall.RLIMIT_FSIZE, &old)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndError {
		t.Fatalf("Run returned reason %s after the ledger refused a line, want error", res.Reason)
	}
	// The agent sleeps 60 s, ten times this bound: a run the failure did not end takes the whole sleep, and a
	// loaded runner has room to end one that it did (a 4 s bound against a 5 s sleep had neither).
	if took := time.Since(start); took > 6*time.Second {
		t.Fatalf("the run took %v: it was not ended when the ledger failed (the agent sleeps 60 s)", took)
	}
	// The run_end either landed (the cut left room) or Close's error reached the caller; never neither.
	evs := events(t, runDirs(t, f.root)[0])
	if last := evs[len(evs)-1]; last.Kind != record.KindRunEnd && res.RecordErr == nil {
		t.Fatalf("no run_end and no RecordErr: the record's end was lost with nothing to say so")
	}
}

// fsizeChildEnv marks the child process TestLedgerWriteFailureEndsTheRun runs itself in.
const fsizeChildEnv = "TEGO_TEST_FSIZE_CHILD"

// failingListenerBackend wraps the tier-1 backend so its handle owns a loop that dies mid-run, the shape of
// tier 2's fanotify listener meeting a fatal error (enforce-cgroup-observe.md §6 E15).
type failingListenerBackend struct{ enforce.Backend }

func (b failingListenerBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	h, err := b.Backend.Prepare(ctx, rt, run)
	if err != nil {
		return nil, err
	}
	return failingListener{h}, nil
}

type failingListener struct{ api.Handle }

func (failingListener) RunListener(ctx context.Context) error {
	select {
	case <-time.After(700 * time.Millisecond):
		return errors.New("fanotify read: EIO (injected)")
	case <-ctx.Done():
		return nil
	}
}

// TestWorkerFailureIsReasonError: an enforcement worker that dies ends the run through the group's
// cancellation, and run_end must name tego's failure, not read the SIGKILL that followed as the agent's own
// exit.
func TestWorkerFailureIsReasonError(t *testing.T) {
	f := newFixture(t, contractFor("iworker", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep"}))
	deps := f.deps(t, nil)
	deps.Enforce = failingListenerBackend{f.backend}
	if _, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "/bin/sleep 60; exit 0"}, deps); err != nil {
		t.Fatalf("Run: %v", err)
	}
	end := runEndOf(t, runDirs(t, f.root)[0])
	if end.Reason != record.RunEndError || !strings.Contains(end.Detail, "EIO (injected)") {
		t.Fatalf("run_end reason=%s detail=%q, want error naming the worker's failure", end.Reason, end.Detail)
	}
}

// TestABusyAgentUnderRecordOffIsNotAStall: stall_after means no activity for stall_after, and
// record: off keeps only refusals, so the supervisor dropped an agent's allowed execs at the producer, the
// budget watcher saw nothing, and an agent exec'ing every 100 ms was killed for stalling. Same agent, both
// record modes, both end with its own exit.
func TestABusyAgentUnderRecordOffIsNotAStall(t *testing.T) {
	for _, mode := range []string{"summary", "off"} {
		t.Run(mode, func(t *testing.T) {
			c := contractFor("istall"+mode, []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep"})
			c = strings.Replace(c, "  pids: 128", "  pids: 128\n  stall_after: 2s", 1)
			c = strings.Replace(c, "record: summary", "record: "+mode, 1)
			f := newFixture(t, c)
			res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c",
				"i=0; while [ $i -lt 40 ]; do /bin/sleep 0.1; i=$((i+1)); done; exit 0"}, f.deps(t, nil))
			if err != nil {
				t.Fatalf("Run: %v", err)
			}
			if res.Reason != record.RunEndExit {
				t.Errorf("record: %s: an agent exec'ing every 100 ms ended %s", mode, res.Reason)
			}
			// LCD-R4: no limit line at all, not merely a run that happened to end by exit.
			for _, ev := range events(t, runDirs(t, f.root)[0]) {
				if ev.Kind == record.KindLimit {
					t.Errorf("record: %s: a busy agent got a limit line (reason %s)", mode, ev.Reason)
				}
			}
		})
	}
}

// TestAnIdleAgentUnderRecordOffStalls is the other half of LCD-R4: under record: off the supervisor's answered
// notifications are the watcher's only feed of activity, so an agent that makes none for stall_after is killed
// for stalling. Without it the Touch hook could be satisfied by a watcher that never trips.
func TestAnIdleAgentUnderRecordOffStalls(t *testing.T) {
	c := contractFor("idlestalloff", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh", "/bin/sleep", "/usr/bin/sleep"})
	c = strings.Replace(c, "  pids: 128", "  pids: 128\n  stall_after: 1s", 1)
	c = strings.Replace(c, "record: summary", "record: off", 1)
	f := newFixture(t, c)
	start := time.Now()
	// exec replaces the shell with sleep: one exec notification, then nothing for 30 s.
	res, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "exec /bin/sleep 30"}, f.deps(t, nil))
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.Reason != record.RunEndLimit {
		t.Fatalf("an idle agent under record: off ended %s after %s, want limit (stall)", res.Reason, time.Since(start))
	}
	if el := time.Since(start); el > 15*time.Second {
		t.Errorf("the stall took %s to end a run with stall_after: 1s", el)
	}
	var limits int
	for _, ev := range events(t, runDirs(t, f.root)[0]) {
		if ev.Kind != record.KindLimit {
			continue
		}
		limits++
		if ev.Reason != record.ReasonLimitStall {
			t.Errorf("limit line reason %s, want %s", ev.Reason, record.ReasonLimitStall)
		}
	}
	if limits != 1 {
		t.Errorf("%d limit lines, want exactly one (stall)", limits)
	}
}

// instantFailingBackend gives the handle a listener that dies at once, before run_start.
type instantFailingBackend struct{ enforce.Backend }

func (b instantFailingBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	h, err := b.Backend.Prepare(ctx, rt, run)
	if err != nil {
		return nil, err
	}
	return instantFailingListener{h}, nil
}

type instantFailingListener struct{ api.Handle }

func (instantFailingListener) RunListener(context.Context) error {
	return errors.New("ROOTCAUSE listener died")
}

// TestPreStartWorkerFailureNamesItsCause: a worker that fails before run_start cancels the group, and the
// prepare step that noticed returned a bare "context canceled"; Run's error names the worker's failure.
func TestPreStartWorkerFailureNamesItsCause(t *testing.T) {
	f := newFixture(t, contractFor("ipreworker", []string{"/bin/sh"}, []string{"/bin/sh", "/usr/bin/sh"}))
	deps := f.deps(t, nil)
	deps.Enforce = instantFailingBackend{f.backend}
	_, err := Run(context.Background(), f.rt, []string{"/bin/sh", "-c", "exit 0"}, deps)
	if err == nil {
		t.Skip("prepare finished before the listener failed; the run is a post-run_start failure")
	}
	if !strings.Contains(err.Error(), "ROOTCAUSE listener died") {
		t.Fatalf("Run error %q does not name the worker's failure", err)
	}
}
