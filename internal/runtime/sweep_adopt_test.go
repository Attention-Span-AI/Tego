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
	"testing"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/watch/adopt"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

const sweptAdoption = "r-00000000-000000000000a-adopt1"

// adoptScopeUnder makes an adoption's scope directory for the run under base and returns its path.
func adoptScopeUnder(t *testing.T, base, id string) string {
	t.Helper()
	p := filepath.Join(base, identity.TopSlice, identity.AgentSlice(identity.AgentID("tester")), adopt.ScopeName(id))
	if err := os.MkdirAll(p, 0o755); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestSweepKeepsALostAdoptionWhileItsScopeHolds: an adoption whose adopter and reaper both died reads lost. A sweep
// that cannot release it (not root) used to end it `orphaned` while the agent stayed in its scope, held by the plane
// with nothing recording: it now kills nothing, writes no run_end and keeps the run lost while an adopt-<id>.scope
// with run_start's cgroup id is there. A same-named scope of another id is not the run's, and once the scope is gone
// the run is ended as any orphan is.
func TestSweepKeepsALostAdoptionWhileItsScopeHolds(t *testing.T) {
	root, own, other := t.TempDir(), t.TempDir(), t.TempDir()
	lostRunIn(t, root, sweptAdoption, 77)
	scope := adoptScopeUnder(t, other, sweptAdoption)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: own}, ids: map[string]uint64{scope: 77}}
	prevBases, prevUID := adoptScopeBases, sweeperUID
	adoptScopeBases = func([]string) []string { return []string{other} }
	sweeperUID = func() int { return 1000 }
	t.Cleanup(func() { adoptScopeBases, sweeperUID = prevBases, prevUID })

	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m))
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if st := runState(t, root, sweptAdoption); st != ledger.StateLost || res.Orphaned != 0 {
		t.Fatalf("state %s, orphaned %d, after a sweep over a lost adoption whose scope holds; want lost", st, res.Orphaned)
	}
	if len(m.killed) != 0 {
		t.Fatalf("an adoption's scope was killed: %v", m.killed)
	}
	if !strings.Contains(fmt.Sprint(res.Errs), "only root can release it") {
		t.Errorf("the sweep does not say who can release it: %v", res.Errs)
	}

	m.ids[scope] = 99 // a scope of the same name made since, not the run's
	if res, _ := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); res.Orphaned != 1 {
		t.Fatalf("a same-named scope of another id kept the run lost: %+v", res)
	}
}

// adoptionLeftLost is what an adoption whose adopter and reaper both died leaves, for a root sweep: a lost run in
// root, its record in a store of the test's own (naming a dead adopter), its scope on the fake host with the agent (200)
// in it. The agent came from the session scope, which exists only when present is true.
func adoptionLeftLost(t *testing.T, present bool) (h *adoptHost, root, state string, rec adoptRecord) {
	t.Helper()
	prevOwner, prevUID, prevEnv, prevState := adoptStateOwner, sweeperUID, adoptReleaseEnv, sweepAdoptStateDir
	t.Cleanup(func() {
		adoptStateOwner, sweeperUID, adoptReleaseEnv, sweepAdoptStateDir = prevOwner, prevUID, prevEnv, prevState
	})
	adoptStateOwner = os.Geteuid()
	sweeperUID = func() int { return 0 }
	h = newAdoptHost(t)
	adoptReleaseEnv = func() adopt.Env { return h.env() }
	root = t.TempDir()
	lostRunIn(t, root, sweptAdoption, 777)
	state = filepath.Join(t.TempDir(), "adopted")
	sweepAdoptStateDir = state
	store, err := openAdoptStore(state)
	if err != nil {
		t.Fatal(err)
	}
	scope := adoptScopeUnder(t, h.mount, sweptAdoption)
	if present {
		if err := os.MkdirAll(filepath.Join(h.mount, adoptSession), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	h.add(200, 100, h.rel(scope), "/usr/bin/node")
	rec = adoptRecord{Run: sweptAdoption, Agent: "tester", Dir: filepath.Join(root, sweptAdoption), Mount: h.mount,
		Scope: scope, ScopeID: 777, From: adoptSession, Root: adopt.Identity{PID: 200, Start: 5200},
		Adopter: adopt.Identity{PID: os.Getpid(), Start: 1}} // this pid with another start time: a dead adopter
	if err := store.write(rec); err != nil {
		t.Fatal(err)
	}
	return h, root, state, rec
}

// TestRootSweepReleasesALostAdoptionBeforeItEndsIt: a root sweep releases a lost adoption from its record, as its
// reaper would, and writes run_end only once the tree is out and the scope removed. While a process stays in the
// scope (no cgroup takes it back) the run stays lost and the record stays, for the next sweep or a release; the agent
// is never killed.
func TestRootSweepReleasesALostAdoptionBeforeItEndsIt(t *testing.T) {
	h, root, state, rec := adoptionLeftLost(t, false)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: t.TempDir()}}

	res, err := Sweep(context.Background(), root, KeepForever, WithSweepManager(m))
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if st := runState(t, root, sweptAdoption); st != ledger.StateLost {
		t.Fatalf("state %s while the agent stays in the adoption's scope (errs %v); want lost", st, res.Errs)
	}
	if got := h.in(h.rel(rec.Scope)); !slices.Equal(got, []int{200}) {
		t.Fatalf("the scope holds %v, want the agent, never killed", got)
	}
	if left := recordsLeft(state); !slices.Contains(left, sweptAdoption+".json") {
		t.Fatalf("the record went while the scope holds: %v", left)
	}
	if len(m.killed) != 0 {
		t.Fatalf("killed %v", m.killed)
	}

	// The cgroup it came from is back: the next sweep releases it, then ends the run.
	if err := os.MkdirAll(filepath.Join(h.mount, adoptSession), 0o755); err != nil {
		t.Fatal(err)
	}
	res, err = Sweep(context.Background(), root, KeepForever, WithSweepManager(m))
	if err != nil || res.Orphaned != 1 {
		t.Fatalf("orphaned %d err %v errs %v, want the released adoption ended", res.Orphaned, err, res.Errs)
	}
	if st := runState(t, root, sweptAdoption); st != ledger.StateEnded {
		t.Fatalf("state %s", st)
	}
	if got := h.in(adoptSession); !slices.Equal(got, []int{200}) {
		t.Fatalf("the agent was not given back: the session holds %v", got)
	}
	if _, err := os.Stat(rec.Scope); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the scope is still there: %v", err)
	}
	if left := recordsLeft(state); len(left) != 0 {
		t.Errorf("left in the records: %v", left)
	}
}

// TestRootSweepReleasesOnlyItsOwnDirectorysAdoption: the record decides what a root sweep moves, and only for the run
// directory it names: a directory planted under the adoption's run id elsewhere releases nothing and stays lost. A
// live adopter's adoption is never the sweep's.
func TestRootSweepReleasesOnlyItsOwnDirectorysAdoption(t *testing.T) {
	h, _, state, rec := adoptionLeftLost(t, true)
	planted := t.TempDir()
	lostRunIn(t, planted, sweptAdoption, 777)
	m := &scopeCgroups{fakeCgroups: fakeCgroups{root: t.TempDir()}}
	res, _ := Sweep(context.Background(), planted, KeepForever, WithSweepManager(m))
	if st := runState(t, planted, sweptAdoption); st != ledger.StateLost || res.Orphaned != 0 {
		t.Fatalf("a planted directory was ended: state %s, %+v", st, res)
	}
	if got := h.in(h.rel(rec.Scope)); !slices.Equal(got, []int{200}) {
		t.Fatalf("a planted directory released the adoption: the scope holds %v", got)
	}

	// The adopter alive: not the sweep's.
	rec.Adopter = adopt.Identity{PID: os.Getpid(), Start: selfStart(t)}
	if err := (&adoptStore{dir: state}).write(rec); err != nil {
		t.Fatal(err)
	}
	root := filepath.Dir(rec.Dir)
	if res, _ := Sweep(context.Background(), root, KeepForever, WithSweepManager(m)); res.Orphaned != 0 {
		t.Fatalf("a live adopter's adoption was swept: %+v", res)
	}
	if got := h.in(h.rel(rec.Scope)); !slices.Equal(got, []int{200}) {
		t.Fatalf("a live adopter's agent was released by a sweep: the scope holds %v", got)
	}
}

// selfStart is this process's start time in clock ticks, as an adoption record names its adopter.
func selfStart(t *testing.T) uint64 {
	t.Helper()
	b, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		t.Fatal(err)
	}
	f := strings.Fields(string(b[strings.LastIndexByte(string(b), ')')+2:]))
	var start uint64
	if _, err := fmt.Sscan(f[19], &start); err != nil {
		t.Fatal(err)
	}
	return start
}
