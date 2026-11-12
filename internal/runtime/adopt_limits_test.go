// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// adoptControls are the limit files of a scope whose parent enables cpu, memory and pids.
var adoptControls = []string{"cpu.max", "cpu.weight", "memory.max", "memory.swap.max", "memory.high", "pids.max"}

// limitedBoundary makes f's adoption a boundary one, decided by a plane, whose table holds limits.
func limitedBoundary(t *testing.T, f *adoptFixture, l agent.ResolvedLimits) AdoptSpec {
	t.Helper()
	f.backend.plane = record.DecisionPlaneFmodRet
	f.rt.Limits = l
	spec := f.spec(t)
	spec.Boundary = true
	return spec
}

// scopeFiles reads the scope's limit files, by name; an absent file is absent from the map.
func scopeFiles(dir string) map[string]string {
	out := map[string]string{}
	for _, name := range adoptControls {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err == nil {
			out[name] = string(b)
		}
	}
	return out
}

// adoptionScopes are the adoption scopes on the fake host.
func adoptionScopes(f *adoptFixture) []string {
	m, _ := filepath.Glob(filepath.Join(f.host.mount, "tego.slice", "*", "adopt-*.scope"))
	return m
}

// adoptRefused runs an adoption that is meant to be refused before it records: one that starts recording instead is
// asked to stop at once (its tree released), so the test fails rather than waits for an agent that never ends.
func adoptRefused(t *testing.T, f *adoptFixture, spec AdoptSpec) error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	started := false
	spec.Started = func(AdoptStarted) { started = true; cancel() }
	_, err := Adopt(ctx, f.rt, spec, f.deps)
	if started {
		t.Errorf("the adoption was not refused: it moved the tree and recorded (released again); Adopt = %v", err)
	}
	return err
}

// cpuPidsCeilings is a table with a cpu, a cpu_weight and a pids limit, as machine ceilings put them there.
func cpuPidsCeilings(pids int) agent.ResolvedLimits {
	return agent.ResolvedLimits{CPU: "0.5", CPUWeight: 20, Pids: pids,
		Set: agent.BudgetCPU | agent.BudgetCPUWeight | agent.BudgetPids}
}

// TestBoundaryAdoptionWritesItsLimitsBeforeTheMove: a boundary adoption under a cpu, cpu_weight or pids limit (a
// machine ceiling's, which every tego run gets) was refused, so a machine with a pids cap could govern no service an
// init system started. Its scope now gets cpu.max, cpu.weight and pids.max, by the writer a launched run's goes
// through, while it is empty: each is in place when the first process moves. No memory file is written, and a
// record-only adoption, which holds nothing, writes no limit at all.
func TestBoundaryAdoptionWritesItsLimitsBeforeTheMove(t *testing.T) {
	f := newAdoptFixture(t)
	f.cgroups.controls = adoptControls
	spec := limitedBoundary(t, f, cpuPidsCeilings(64))
	var mu sync.Mutex
	var atMove map[string]string
	f.host.onAdd = func(pid int) {
		mu.Lock()
		defer mu.Unlock()
		if pid == 200 && atMove == nil {
			if scopes := adoptionScopes(f); len(scopes) == 1 {
				atMove = scopeFiles(scopes[0])
			}
		}
	}
	s, done := f.adoptRunning(t, context.Background(), spec)
	mu.Lock()
	got := atMove
	mu.Unlock()
	want := map[string]string{"cpu.max": "50000 100000", "cpu.weight": "20", "pids.max": "64", "memory.max": "",
		"memory.swap.max": "", "memory.high": ""}
	if len(got) != len(want) {
		t.Fatalf("the scope's limit files when the agent moved: %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s was %q when the agent moved, want %q", k, got[k], v)
		}
	}
	f.host.end(f.host.rel(s.Scope))
	waitResult(t, done)

	// Record-only: the same table, nothing written.
	r := newAdoptFixture(t)
	r.cgroups.controls = adoptControls
	r.rt.Limits = cpuPidsCeilings(64)
	var recordOnly map[string]string
	r.host.onAdd = func(pid int) {
		mu.Lock()
		defer mu.Unlock()
		if pid == 200 && recordOnly == nil {
			if scopes := adoptionScopes(r); len(scopes) == 1 {
				recordOnly = scopeFiles(scopes[0])
			}
		}
	}
	s, done = r.adoptRunning(t, context.Background(), r.spec(t))
	mu.Lock()
	defer mu.Unlock()
	for k, v := range recordOnly {
		if v != "" {
			t.Errorf("a record-only adoption wrote %s = %q", k, v)
		}
	}
	r.host.end(r.host.rel(s.Scope))
	waitResult(t, done)
}

// TestBoundaryAdoptionRefusesAPidsCeilingBelowItsTree: pids.max counts every task in the cgroup, and a migration is
// charged whatever the limit, so a tree moved under a ceiling at or below its count could start no process or thread:
// a live service would fail its next fork at once. The adoption is refused before anything moves, with the count, the
// ceiling and the least ceiling that leaves room for one more task, and nothing of it is left. A ceiling above the
// count moves.
func TestBoundaryAdoptionRefusesAPidsCeilingBelowItsTree(t *testing.T) {
	for _, ceiling := range []int{1, 2} {
		f := newAdoptFixture(t)
		f.cgroups.controls = adoptControls
		err := adoptRefused(t, f, limitedBoundary(t, f, cpuPidsCeilings(ceiling)))
		if !errors.Is(err, ErrAdoptLimits) || !strings.Contains(err.Error(), "holds 2 tasks") ||
			!strings.Contains(err.Error(), fmt.Sprintf("pids ceiling %d", ceiling)) ||
			!strings.Contains(err.Error(), "raise limits.pids to 3 or more") {
			t.Fatalf("Adopt under pids %d of a tree of 2 = %v; want ErrAdoptLimits naming 2 tasks, the ceiling %d and "+
				"3 as the least that goes on", ceiling, err, ceiling)
		}
		if len(f.host.moves) != 0 {
			t.Errorf("pids %d: moved %v before the refusal", ceiling, f.host.moves)
		}
		if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 300}) {
			t.Errorf("pids %d: the session holds %v", ceiling, got)
		}
		if s := adoptionScopes(f); len(s) != 0 {
			t.Errorf("pids %d: a refused adoption left its scope: %v", ceiling, s)
		}
		if ents := recordsLeft(f.state); len(ents) != 0 {
			t.Errorf("pids %d: left in the records: %v", ceiling, ents)
		}
		if left := leftBehind(t, filepath.Join(f.root, "runs")); len(left) != 0 {
			t.Errorf("pids %d: a refused adoption left %v", ceiling, left)
		}
	}

	above := newAdoptFixture(t)
	above.cgroups.controls = adoptControls
	s, done := above.adoptRunning(t, context.Background(), limitedBoundary(t, above, cpuPidsCeilings(3)))
	if got := above.host.in(above.host.rel(s.Scope)); !slices.Equal(got, []int{200, 201}) {
		t.Errorf("under a pids ceiling one above its 2 tasks the scope holds %v", got)
	}
	above.host.end(above.host.rel(s.Scope))
	waitResult(t, done)
}

// TestBoundaryAdoptionReleasesATreeThatGrewPastItsPidsCeiling: the tree is counted under the move lock, but a member
// still in the session can fork until it moves, and the kernel charges the child's migration whatever pids.max says.
// A tree that grew to or past the ceiling while it moved is refused once it has moved and released where it came from,
// its new process too: it is never left where its next fork fails. Nothing of the adoption is left.
func TestBoundaryAdoptionReleasesATreeThatGrewPastItsPidsCeiling(t *testing.T) {
	for _, ceiling := range []int{3, 4} {
		f := newAdoptFixture(t)
		f.cgroups.controls = adoptControls
		spec := limitedBoundary(t, f, cpuPidsCeilings(ceiling))
		var once sync.Once
		f.host.onAdd = func(pid int) {
			if pid == 200 {
				once.Do(func() { // forks as the agent moves: the tree of 2 grows to the ceiling or past it
					f.host.add(202, 200, adoptSession, "/usr/bin/sleep")
					f.host.add(203, 200, adoptSession, "/usr/bin/sleep")
				})
			}
		}
		err := adoptRefused(t, f, spec)
		f.host.onAdd = nil
		if !errors.Is(err, ErrAdoptLimits) || !strings.Contains(err.Error(), "grew to 4 tasks") ||
			!strings.Contains(err.Error(), fmt.Sprintf("pids ceiling %d", ceiling)) {
			t.Fatalf("Adopt of a tree that grew to 4 under pids %d = %v; want ErrAdoptLimits naming 4 tasks and the "+
				"ceiling", ceiling, err)
		}
		if got := f.host.in(adoptSession); !slices.Equal(got, []int{100, 200, 201, 202, 203, 300}) {
			t.Errorf("pids %d: the session holds %v after the refusal, want the tree back with its new processes",
				ceiling, got)
		}
		if s := adoptionScopes(f); len(s) != 0 {
			t.Errorf("pids %d: a refused adoption left its scope: %v", ceiling, s)
		}
		if ents := recordsLeft(f.state); len(ents) != 0 {
			t.Errorf("pids %d: left in the records: %v", ceiling, ents)
		}
	}
}

// TestAdoptionLimitWriteFailureLeavesNothing: the limits are written one file at a time, and a scope whose parent does
// not enable a controller (pids here, cpu on a stock RHEL 9 host) refuses the write after the earlier ones landed.
// The adoption is refused with the setup that enables the controller, before anything is armed or moved, and the
// half-limited scope is removed.
func TestAdoptionLimitWriteFailureLeavesNothing(t *testing.T) {
	for _, tc := range []struct {
		name     string
		controls []string
		limit    string
		fix      string
	}{
		{"pids not enabled", []string{"cpu.max", "cpu.weight"}, "limits.pids", "Delegate=cpu memory pids"},
		{"cpu not enabled", []string{"pids.max"}, "limits.cpu", "CPUWeight=100"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newAdoptFixture(t)
			f.cgroups.controls = tc.controls
			err := adoptRefused(t, f, limitedBoundary(t, f, cpuPidsCeilings(64)))
			var mc *cgroup.MissingControllerError
			if !errors.Is(err, ErrAdoptLimits) || !errors.As(err, &mc) || !strings.Contains(err.Error(), tc.limit) ||
				!strings.Contains(err.Error(), tc.fix) {
				t.Fatalf("Adopt = %v; want ErrAdoptLimits, the missing controller naming %s and a fix with %q", err,
					tc.limit, tc.fix)
			}
			if len(f.host.moves) != 0 {
				t.Errorf("moved %v", f.host.moves)
			}
			if f.backend.handle != nil {
				t.Error("tier 2 was prepared before the limits were written")
			}
			if s := adoptionScopes(f); len(s) != 0 {
				t.Errorf("the half-limited scope was left: %v", s)
			}
			if f.cgroups.created != 1 || f.cgroups.removed != 1 {
				t.Errorf("scopes created %d, removed %d; want the one made removed", f.cgroups.created, f.cgroups.removed)
			}
			if ents := recordsLeft(f.state); len(ents) != 0 {
				t.Errorf("left in the records: %v", ents)
			}
		})
	}
}

// TestAdoptionLiftsItsLimitsFromProcessesLeftInTheScope: a release can leave processes in the adoption's scope when no
// cgroup takes them back; they are released, governed by nothing, so they keep no limit the adoption wrote. The
// adopter lifts them as it releases, and so does a later release of the orphaned record (the reaper's, `tego adopt
// --release`, the sweep's).
func TestAdoptionLiftsItsLimitsFromProcessesLeftInTheScope(t *testing.T) {
	f := newAdoptFixture(t)
	f.cgroups.controls = adoptControls
	prevEnv := adoptReleaseEnv
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	t.Cleanup(func() { adoptReleaseEnv = prevEnv })
	ctx, cancel := context.WithCancel(context.Background())
	s, done := f.adoptRunning(t, ctx, limitedBoundary(t, f, cpuPidsCeilings(64)))
	if got := scopeFiles(s.Scope)["pids.max"]; got != "64" {
		t.Fatalf("pids.max = %q while adopted", got)
	}
	if err := os.RemoveAll(filepath.Join(f.host.mount, "user.slice")); err != nil {
		t.Fatal(err)
	}
	cancel()
	waitResult(t, done)
	if got := f.host.in(f.host.rel(s.Scope)); !slices.Equal(got, []int{200, 201}) {
		t.Fatalf("the scope holds %v, want the tree left in it", got)
	}
	lifted := map[string]string{"cpu.max": "max 100000", "cpu.weight": "100", "pids.max": "max"}
	for k, v := range lifted {
		if got := scopeFiles(s.Scope)[k]; got != v {
			t.Errorf("%s = %q on processes left in the scope, want %q", k, got, v)
		}
	}

	// The orphaned record's release lifts them too (a limit written again here stands for one the adopter could not
	// lift).
	for _, name := range []string{"cpu.max", "cpu.weight", "pids.max"} {
		_ = os.Truncate(filepath.Join(s.Scope, name), 0)
	}
	if err := os.WriteFile(filepath.Join(s.Scope, "pids.max"), []byte("64"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReleaseAdoption(context.Background(), f.state, s.RunID, "tego adopt --release", nil); err == nil ||
		!strings.Contains(err.Error(), "still stay in") {
		t.Fatalf("a release that moved nothing out: %v", err)
	}
	if got := scopeFiles(s.Scope)["pids.max"]; got != "max" {
		t.Errorf("pids.max = %q after the orphan's release, want max", got)
	}
}

// TestAdoptionRefusesATableItCannotHold: the caller refuses a boundary table with a memory, memory_high, wall or
// stall_after limit before an adoption starts (a machine ceiling's or the contract's); one that reaches Adopt anyway is
// a caller bug and is refused before anything exists, never adopted with the limit held by nothing. Budgets go on:
// nothing meters them, and the run records it (budget-unmetered).
func TestAdoptionRefusesATableItCannotHold(t *testing.T) {
	for _, l := range []agent.ResolvedLimits{
		{MemoryB: 1 << 30, Set: agent.BudgetMemory},
		{MemoryHigh: 1 << 30, Set: agent.BudgetMemoryHigh},
		{Wall: 3600e9, Set: agent.BudgetWall},
		{StallAfter: 60e9, Set: agent.BudgetStallAfter},
	} {
		f := newAdoptFixture(t)
		err := adoptRefused(t, f, limitedBoundary(t, f, l))
		if !errors.Is(err, ErrAdoptDeps) || f.cgroups.created != 0 {
			t.Errorf("a boundary table with %+v: %v, %d scopes made; want ErrAdoptDeps before anything", l, err, f.cgroups.created)
		}
	}
	got, err := adoptionLimits(agent.ResolvedLimits{CPU: "2", CPUWeight: 50, Pids: 0, Tokens: 5, CostUSD: 1, Repeats: 3,
		Set: agent.BudgetCPU | agent.BudgetCPUWeight | agent.BudgetPids | agent.BudgetTokens | agent.BudgetCostUSD | agent.BudgetRepeats})
	if err != nil {
		t.Fatal(err)
	}
	if want := (cgroup.Limits{CPUMax: "200000 100000", CPUWeight: 50, PidsMaxSet: true}); got != want {
		t.Errorf("adoptionLimits = %+v, want %+v: cpu.max, cpu.weight and a pids.max of 0, nothing else", got, want)
	}
	for _, key := range []string{"cpu", "limits.cpu", "cpu_weight", "pids", "limits.pids"} {
		if !AdoptionApplies(key) {
			t.Errorf("AdoptionApplies(%q) = false", key)
		}
	}
	for _, key := range []string{"memory", "memory_high", "wall", "stall_after", "tokens", "cost_usd", "repeats", "limits.memory", "x"} {
		if AdoptionApplies(key) {
			t.Errorf("AdoptionApplies(%q) = true", key)
		}
	}
}

// TestAdoptionSaysALiftThatFailed: a release that leaves processes in the scope lifts the limits there, and a lift the
// kernel refuses leaves those processes, which tego no longer governs, under a pids.max or a cpu.max it wrote. A
// refused adoption's error said so, but a run that ended with a release only logged it: its run_end said "released"
// and nothing more. run_end's detail now says the limits were not all lifted, and why.
func TestAdoptionSaysALiftThatFailed(t *testing.T) {
	f := newAdoptFixture(t)
	f.cgroups.controls = adoptControls
	prevEnv := adoptReleaseEnv
	adoptReleaseEnv = func() adopt.Env { return f.host.env() }
	t.Cleanup(func() { adoptReleaseEnv = prevEnv })
	ctx, cancel := context.WithCancel(context.Background())
	s, done := f.adoptRunning(t, ctx, limitedBoundary(t, f, cpuPidsCeilings(64)))
	// pids.max refuses the lift's write (a directory stands for a control file the kernel will not take a value in).
	if err := os.Remove(filepath.Join(s.Scope, "pids.max")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(s.Scope, "pids.max"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Join(f.host.mount, "user.slice")); err != nil { // no cgroup takes the tree back
		t.Fatal(err)
	}
	cancel()
	waitResult(t, done)
	if got := f.host.in(f.host.rel(s.Scope)); !slices.Equal(got, []int{200, 201}) {
		t.Fatalf("the scope holds %v, want the tree left in it", got)
	}
	end := runEnd(t, s.Dir)
	if end.Reason != record.RunEndStopped || !strings.Contains(end.Detail, "2 left in") ||
		!strings.Contains(end.Detail, "could not all be lifted") || !strings.Contains(end.Detail, "pids.max") {
		t.Errorf("run_end %s %q; want it stopped, saying the 2 left in the scope and that their limits could not all "+
			"be lifted (pids.max)", end.Reason, end.Detail)
	}
}
