// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/enforce"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/api"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// armingBackend wraps a run's real backend so that its handle is an api.Armer whose Arm notes what this
// process's children are running at that moment, and fails with failArm when that is set.
type armingBackend struct {
	enforce.Backend
	failArm error
	before  map[int]bool // this process's children before the run (childPIDs), which are not the run's

	mu   sync.Mutex
	seen [][]string // one entry per Arm: the executable of each child of this process
}

func (b *armingBackend) Prepare(ctx context.Context, rt *agent.RuleTable, run enforce.RunRef) (api.Handle, error) {
	h, err := b.Backend.Prepare(ctx, rt, run)
	if err != nil {
		return nil, err
	}
	return &armingHandle{Handle: h, b: b}, nil
}

type armingHandle struct {
	api.Handle
	b *armingBackend
}

func (h *armingHandle) Arm() error {
	exes := childExes(h.b.before)
	h.b.mu.Lock()
	h.b.seen = append(h.b.seen, exes)
	h.b.mu.Unlock()
	return h.b.failArm
}

// childPIDs is every child of this process, from every thread's children list: the child stage is a child of the
// thread the launcher kept for it. Run makes this process a child subreaper (once, for the process's life), so the
// orphans of earlier runs in this test binary are its children too, often as zombies nobody reaps; a test that
// asks what one run left takes this set before the run and leaves it out.
func childPIDs() map[int]bool {
	pids := map[int]bool{}
	files, _ := filepath.Glob("/proc/self/task/*/children")
	for _, f := range files {
		data, _ := os.ReadFile(f)
		for _, field := range strings.Fields(string(data)) {
			if pid, err := strconv.Atoi(field); err == nil {
				pids[pid] = true
			}
		}
	}
	return pids
}

// childExes is the executable each child of this process runs, leaving out the children in before.
func childExes(before map[int]bool) []string {
	var pids []int
	for pid := range childPIDs() {
		if !before[pid] {
			pids = append(pids, pid)
		}
	}
	slices.Sort(pids)
	var out []string
	for _, pid := range pids {
		exe, err := os.Readlink("/proc/" + strconv.Itoa(pid) + "/exe")
		if err != nil {
			exe = fmt.Sprintf("pid %d: %v", pid, err)
		}
		out = append(out, exe)
	}
	return out
}

// TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck is ADR 0021 (2)'s arming point against a real child
// stage: the runtime calls the handle's Arm exactly once, when the stage has exec'd tego's own binary (its
// executable is no longer this test binary, which it was between the clone and the execve) and has not yet
// been acked (it is not yet the agent's binary). So tego's stage exec comes before anything the tier arms and
// the agent's first exec after all of it. The run then completes as usual.
func TestIntegrationArmFollowsTheStageExecAndPrecedesTheAck(t *testing.T) {
	f := newFixture(t, contractFor("iarm", []string{"/bin/true"}, []string{"/bin/true"}))
	b := &armingBackend{Backend: f.backend, before: childPIDs()}
	deps := f.deps(t, nil)
	deps.Enforce = b
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitCode != 0 || res.Reason != record.RunEndExit {
		t.Fatalf("result %+v, want exit 0", res)
	}
	stage, err := filepath.EvalSymlinks(tegoBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.seen) != 1 {
		t.Fatalf("Arm called %d times, want once", len(b.seen))
	}
	if got := b.seen[0]; len(got) != 1 || got[0] != stage {
		self, _ := os.Executable()
		t.Fatalf("children at Arm: %v; want the one child stage running %s (this test binary %s would be a stage "+
			"not yet exec'd, /bin/true an agent already acked)", got, stage, self)
	}
}

// TestIntegrationFailedArmFailsTheRunBeforeTheAgent: an Arm that fails ends the run before run_start, exit 125
// with the arm's error, and the stage it was about to ack is killed, never exec'ing the agent; the unwind
// leaves nothing behind, as any failure before run_start does.
func TestIntegrationFailedArmFailsTheRunBeforeTheAgent(t *testing.T) {
	f := newFixture(t, contractFor("iarmfail", []string{"/bin/true"}, []string{"/bin/true"}))
	boom := errors.New("arm refused")
	b := &armingBackend{Backend: f.backend, failArm: boom, before: childPIDs()}
	deps := f.deps(t, nil)
	deps.Enforce = b
	res, err := Run(context.Background(), f.rt, []string{"/bin/true"}, deps)
	if !errors.Is(err, boom) {
		t.Fatalf("Run = %+v, %v; want the arm's error", res, err)
	}
	if res.ExitCode != 125 || res.Reason != record.RunEndError {
		t.Fatalf("result %+v, want exit 125 reason error", res)
	}
	if left := childExes(b.before); len(left) != 0 {
		t.Fatalf("children after a failed arm: %v, want the stage killed and reaped", left)
	}
	if left := leftBehind(t, f.root); len(left) != 0 {
		t.Fatalf("a run whose arm failed left %v behind", left)
	}
}
