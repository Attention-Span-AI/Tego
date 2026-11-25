// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf && tegotesthooks

package doctor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/config"
)

// TestIntegrationPlaneProbeRetryOnARealKernel is the retry (planeretry.go, ADR 0024's amendment of 2026-11-24)
// on a real kernel, as root, built with tegotesthooks: one probe row is made to fail on its outside leg
// (PlaneRowForceForTest) while the mode's programs are really loaded, attached and run, so the second probe of one
// mode inside one probePlane meets the shared exec image, a second scratch cgroup and fixture directory and the first
// probe's link teardown, which no unit test with a fake prober reaches.
//
//	(a) a mode that always fails the same row is a failed mode, not a fault, with no second answer in it; the
//	    run-probe cache keeps it and a second run of the boot does not probe it again;
//	(b) a mode that fails only its first probe is Faulted, carries both probes' rows (plane.modes[].probes) and
//	    says so in the text, is not selected and not cached, and the other mode (or fanotify) is selected;
//	(c) after each case no program, link, pin, descriptor, scratch cgroup or fixture directory is left;
//	(d) an unforced run selects what the first one did and probes each mode once.
//
// Not run by the unprivileged suites or by root-suites.sh (no tegotesthooks there): test/vm's guest wrapper
// (the guest wrapper) builds it with -tags 'integration tegobpf tegotesthooks'.
func TestIntegrationPlaneProbeRetryOnARealKernel(t *testing.T) {
	requirePlaneRoot(t)
	ctx := context.Background()
	force := func(m bpfobj.PlaneMode, how PlaneRowForce) func(bpfobj.PlaneMode) int {
		calls, restore := PlaneRowForceForTest(m, planeRetryHook, how)
		t.Cleanup(restore)
		return calls
	}

	// The unforced run first: what every case is held to, and the mode to force.
	calls := force("", PlaneRowForceNever)
	base := runDoctorForRetry(t, ctx)
	var target bpfobj.PlaneMode
	for _, m := range base.Plane.Modes {
		if m.OK {
			target = m.Mode
			break
		}
	}
	if target == "" {
		t.Fatalf("no plane mode passes on this kernel (selected %q), so none can be forced: %+v", base.Plane.Selected, base.Plane.Modes)
	}
	wantOther := PlaneFanotify
	for _, m := range base.Plane.Modes {
		if m.OK && m.Mode != target {
			wantOther = string(m.Mode)
			break
		}
	}
	t.Logf("kernel %s, selected %s, forcing %s's %s row, the plane is %s without it", base.Kernel, base.Plane.Selected, target,
		planeRetryHook, wantOther)
	for _, m := range base.Plane.Modes {
		if n := calls(m.Mode); m.OK && n != 1 {
			t.Errorf("(d) the first unforced run probed mode %s %d times, want once", m.Mode, n)
		}
	}
	uid, _ := config.InvokingUID()
	cache := defaultRunCache()
	key, ok := cache.key(base.Kernel, uid)
	if !ok {
		t.Fatal("the run-probe cache's key cannot be read")
	}
	cache.drop(key)
	t.Cleanup(func() { cache.drop(key) })

	// (a) always the same row.
	t.Run("a_always_fails_the_same_row", func(t *testing.T) {
		state := snapshotKernelState(t)
		calls := force(target, PlaneRowForceAlways)
		first, err := ForRun(ctx, nil, backend.TierCgroup)
		if err != nil {
			t.Fatal(err)
		}
		m, _ := first.Plane.mode(target)
		if !m.Tested || m.OK || m.Faulted || len(m.Probes) != 0 {
			t.Errorf("(a) mode %s: tested %v ok %v faulted %v with %d probe row sets, want a failed mode that was not Faulted: %s",
				target, m.Tested, m.OK, m.Faulted, len(m.Probes), m.Detail)
		}
		if first.Plane.Source != planeSourceProbed || first.FromCache() {
			t.Errorf("(a) the first run's plane came from %q (cache %v), want a probe", first.Plane.Source, first.FromCache())
		}
		if n := calls(target); n != 2 {
			t.Errorf("(a) the first run probed mode %s %d times, want twice (the retry, then the same failure)", target, n)
		}
		if first.Plane.Selected != wantOther {
			t.Errorf("(a) selected %q, want %q", first.Plane.Selected, wantOther)
		}
		entry := readRunCacheEntry(t, cache, key)
		if em, ok := entry.Plane.mode(target); entry.Plane == nil || !ok || em.OK || em.Faulted || len(em.Probes) != 0 {
			t.Errorf("(a) the run-probe cache holds %+v for mode %s, want it cached as failed", entry.Plane, target)
		}
		second, err := ForRun(ctx, nil, backend.TierCgroup)
		if err != nil {
			t.Fatal(err)
		}
		if !second.FromCache() || second.Plane.Source != planeSourceRunCache {
			t.Errorf("(a) the second run's plane came from %q (cache %v), want the run cache", second.Plane.Source, second.FromCache())
		}
		if n := calls(target); n != 2 {
			t.Errorf("(a) after the second run mode %s was probed %d times in all, want still 2: it probed a cached failure", target, n)
		}
		if sm, _ := second.Plane.mode(target); sm.OK || sm.Faulted {
			t.Errorf("(a) the second run reads mode %s as ok %v faulted %v", target, sm.OK, sm.Faulted)
		}
		second.DiscardCache()
		checkNothingLeft(t, state)
	})

	// (b) fails the first probe only.
	t.Run("b_fails_only_its_first_probe", func(t *testing.T) {
		state := snapshotKernelState(t)
		calls := force(target, PlaneRowForceFirst)
		rep := runDoctorForRetry(t, ctx)
		m, _ := rep.Plane.mode(target)
		if !m.Tested || m.OK || !m.Faulted || len(m.Probes) != 2 || m.Fix == "" {
			t.Fatalf("(b) mode %s: tested %v ok %v faulted %v with %d probe row sets, want a Faulted mode with both: %s",
				target, m.Tested, m.OK, m.Faulted, len(m.Probes), m.Detail)
		}
		for i, p := range m.Probes {
			row := planeRetryRow(p.Programs)
			if row == nil || len(p.Programs) != len(m.Probes[0].Programs) {
				t.Fatalf("(b) probe %d has %d rows and no %s row", i+1, len(p.Programs), planeRetryHook)
			}
			if i == 0 && (row.OK() || row.Outside != planeRefused) {
				t.Errorf("(b) probe 1: %s row outside %q ok %v, want it forced to fail on outside refused", row.Hook, row.Outside, row.OK())
			}
			if i == 1 && !row.OK() {
				t.Errorf("(b) probe 2: %s row outside %q ok %v, want it to pass as the kernel answers", row.Hook, row.Outside, row.OK())
			}
		}
		if rep.Plane.Selected != wantOther {
			t.Errorf("(b) selected %q, want %q (the mode is not selected on its second probe)", rep.Plane.Selected, wantOther)
		}
		if n := calls(target); n != 2 {
			t.Errorf("(b) mode %s was probed %d times, want 2", target, n)
		}
		for _, o := range rep.Plane.Modes {
			if o.Mode != target && o.OK && calls(o.Mode) != 1 {
				t.Errorf("(b) the other mode %s was probed %d times, want once", o.Mode, calls(o.Mode))
			}
		}
		// doctor --json: the plane's modes[].probes, both probes' rows.
		js, err := json.Marshal(rep)
		if err != nil {
			t.Fatal(err)
		}
		var decoded struct {
			Plane struct {
				Modes []struct {
					Mode    string
					Faulted bool
					Probes  []struct {
						Probe    int
						Programs []HookResult
					}
				}
			}
		}
		if err := json.Unmarshal(js, &decoded); err != nil {
			t.Fatal(err)
		}
		var found bool
		for _, dm := range decoded.Plane.Modes {
			if dm.Mode == string(target) {
				found = dm.Faulted && len(dm.Probes) == 2 && dm.Probes[0].Probe == 1 && dm.Probes[1].Probe == 2 &&
					planeRetryRow(dm.Probes[0].Programs) != nil && planeRetryRow(dm.Probes[1].Programs) != nil
			}
		}
		if !found {
			t.Errorf("(b) --json has no plane.modes[%s].probes with both probes' rows: %s", target, js)
		}
		// The text, and the log line tego.log receives (the cli writes it from these notes).
		var text bytes.Buffer
		if err := rep.WriteText(&text); err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"probed twice with different answers", "first probe", "second probe", planeRetryHook} {
			if !strings.Contains(text.String(), want) {
				t.Errorf("(b) the text lacks %q:\n%s", want, text.String())
			}
		}
		if notes := rep.PlaneNotes(); len(notes) != 1 || !strings.Contains(notes[0], "decision plane, "+string(target)+" mode: probed twice") {
			t.Errorf("(b) plane notes %q, want one for mode %s", notes, target)
		}
		// Not cached: a run keeps no plane answer, and the next run probes the mode again.
		for run := 1; run <= 2; run++ {
			again := force(target, PlaneRowForceFirst)
			r, err := ForRun(ctx, nil, backend.TierCgroup)
			if err != nil {
				t.Fatal(err)
			}
			if rm, _ := r.Plane.mode(target); !rm.Faulted || r.Plane.Source != planeSourceProbed {
				t.Errorf("(b) run %d of the cache check: mode %s faulted %v, plane from %q", run, target, rm.Faulted, r.Plane.Source)
			}
			if n := again(target); n != 2 {
				t.Errorf("(b) run %d of the cache check probed mode %s %d times, want 2 (a faulted mode is probed again)", run, target, n)
			}
			if entry := readRunCacheEntry(t, cache, key); entry.Plane != nil {
				t.Errorf("(b) run %d: the run-probe cache holds a plane answer %+v", run, entry.Plane)
			}
		}
		cache.drop(key)
		checkNothingLeft(t, state)
	})

	// (d) and (c) once more, unforced, after both cases.
	t.Run("d_unforced_run_is_as_before", func(t *testing.T) {
		state := snapshotKernelState(t)
		calls := force(target, PlaneRowForceNever)
		rep := runDoctorForRetry(t, ctx)
		if rep.Plane.Selected != base.Plane.Selected {
			t.Errorf("(d) selected %q, the first unforced run selected %q", rep.Plane.Selected, base.Plane.Selected)
		}
		for i, m := range rep.Plane.Modes {
			if m.OK != base.Plane.Modes[i].OK || m.Faulted || len(m.Probes) != 0 {
				t.Errorf("(d) mode %s: ok %v faulted %v probes %d, the first run had ok %v: %s", m.Mode, m.OK, m.Faulted, len(m.Probes),
					base.Plane.Modes[i].OK, m.Detail)
			}
			if n := calls(m.Mode); n > 1 || (m.OK && n != 1) {
				t.Errorf("(d) mode %s was probed %d times, want once", m.Mode, n)
			}
		}
		if len(rep.PlaneNotes()) != 0 {
			t.Errorf("(d) plane notes %q on an unforced run", rep.PlaneNotes())
		}
		checkNothingLeft(t, state)
	})
}

// runDoctorForRetry is doctor's own scope, as `tego doctor` runs it: every check, the plane probed once for each mode.
func runDoctorForRetry(t *testing.T, ctx context.Context) *Report {
	t.Helper()
	rep, err := Run(ctx, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if rep.Plane == nil || rep.Plane.Skipped || len(rep.Plane.Modes) == 0 {
		t.Fatalf("doctor made no plane answer: %+v", rep.Plane)
	}
	return rep
}

// planeRetryRow is the forced hook's row among a mode's rows, found by the hook's own name in the mode of the rows
// (planeRowOfHook), as the probe's forcing finds it: a row is "lsm/socket_create" in LSM mode and
// "fmod_ret/security_socket_create" in fmod_ret mode.
func planeRetryRow(rows []HookResult) *HookResult { return planeRowOfHook(rows, planeRetryHook) }

// readRunCacheEntry is the run-probe cache's entry under key as the file holds it, an empty one when there is none.
func readRunCacheEntry(t *testing.T, c *runCache, k runCacheKey) runCacheEntry {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("/run", "tego", c.name(k)))
	if errors.Is(err, os.ErrNotExist) {
		return runCacheEntry{}
	}
	if err != nil {
		t.Fatal(err)
	}
	var e runCacheEntry
	if err := json.Unmarshal(b, &e); err != nil {
		t.Fatalf("the run-probe cache's entry does not parse: %v: %s", err, b)
	}
	return e
}

// kernelState is what a probe must leave as it found it: the leftovers the other plane tests read (bpffs entries, this
// process's BPF descriptors, scratch cgroups, fixture directories) and the machine's program and link ids, so a
// program a probe's child or a closed link kept alive shows too.
type kernelState struct {
	local         [][]string
	progs, linkID []uint32
}

func snapshotKernelState(t *testing.T) kernelState {
	t.Helper()
	p, l := bpfObjectIDs(t)
	return kernelState{local: leftovers(t), progs: p, linkID: l}
}

// checkNothingLeft waits up to 20 s for the kernel to free what a closed link or a dead child held (a program is freed
// when its last reference goes, a moment after the close), then holds the state to what snapshotKernelState read.
func checkNothingLeft(t *testing.T, before kernelState) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for {
		p, l := bpfObjectIDs(t)
		extraProgs, extraLinks := newIDs(before.progs, p), newIDs(before.linkID, l)
		local := leftovers(t)
		if len(extraProgs) == 0 && len(extraLinks) == 0 && sameLeftovers(local, before.local) {
			return
		}
		if time.Now().After(deadline) {
			t.Errorf("(c) state left behind: new programs %v, new links %v; before %v, after %v", extraProgs, extraLinks, before.local, local)
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}

func newIDs(before, after []uint32) []uint32 {
	var out []uint32
	for _, id := range after {
		if !slices.Contains(before, id) {
			out = append(out, id)
		}
	}
	return out
}

// bpfObjectIDs lists every program id and link id the kernel holds, sorted.
func bpfObjectIDs(t *testing.T) (progs, links []uint32) {
	t.Helper()
	for id := ebpf.ProgramID(0); ; {
		next, err := ebpf.ProgramGetNextID(id)
		if errors.Is(err, os.ErrNotExist) {
			break
		}
		if err != nil {
			t.Fatalf("list programs: %v", err)
		}
		progs, id = append(progs, uint32(next)), next
	}
	it := new(link.Iterator)
	for it.Next() {
		links = append(links, uint32(it.ID))
	}
	if err := it.Err(); err != nil {
		t.Fatalf("list links: %v", err)
	}
	it.Close()
	slices.Sort(progs)
	slices.Sort(links)
	return progs, links
}
