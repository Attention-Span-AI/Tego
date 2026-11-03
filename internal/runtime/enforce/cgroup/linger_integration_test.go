// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestALingeringBuildIsAdoptedAndSweptOnlyWhenIdle is ADR 0022 against the running kernel, as root. With a
// linger, the last launcher out leaves the build's programs, maps and host-wide links pinned, and the next run
// adopts them: it runs the same programs and loads nothing. A sweep then keeps the build while it lingers,
// while a launcher holds it, and while its run set names a cgroup that exists (an orphaned run's), deletes the
// row of a cgroup that is gone, and removes the build once none of these holds.
//
// Before ADR 0022 the last launcher out removed the build, so every run that was alone on the machine loaded,
// verified, attached and later detached all of it: 1.1 s of a root run of `true` at tier cgroup on 6.17 in the
// KVM guest, against 45 ms with the build adopted, which is why kill test 4's npm and go kinds failed there.
func TestALingeringBuildIsAdoptedAndSweptOnlyWhenIdle(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	// A hash of its own: the pins are this test's, and no other build's timer or sweep is the one tested.
	hash := fmt.Sprintf("linger-it-%d", os.Getpid())
	var timers []string
	b := New(Options{Machine: machineLinger(time.Hour), StateDir: state, Hash: hash, Events: &sink{},
		startTimer: func(h string) error { timers = append(timers, h); return nil }})
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	pins, err := newPinLayout(DefaultBPFFS, hash)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })

	progIDs := func(h *Handle) map[string]ebpf.ProgramID {
		out := map[string]ebpf.ProgramID{}
		for name, p := range h.kern.(*bpfKernel).progs {
			info, err := p.Info()
			if err != nil {
				t.Fatalf("program %s: %v", name, err)
			}
			id, _ := info.ID()
			out[name] = id
		}
		return out
	}
	run := func(name string) map[string]ebpf.ProgramID {
		t.Helper()
		rel, id := runCgroup(t, "linger-"+name)
		start := time.Now()
		h, err := b.Prepare(context.Background(), table, Run{ID: name, Agent: "a", CgroupID: id, CgroupPath: rel})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		prepared := time.Since(start)
		ids := progIDs(h)
		start = time.Now()
		if err := h.Close(); err != nil {
			t.Fatalf("Close %s: %v", name, err)
		}
		t.Logf("%s: Prepare %v, Close %v", name, prepared, time.Since(start))
		return ids
	}

	first := run("first")
	if _, err := os.Stat(pins.Root); err != nil {
		t.Fatalf("the last launcher out removed a build that should linger: %v", err)
	}
	links, err := os.ReadDir(pins.Links)
	if err != nil || len(links) == 0 {
		t.Fatalf("the lingering build holds no pinned host-wide link (%v)", err)
	}
	if len(timers) != 1 || timers[0] != hash {
		t.Fatalf("timers started: %v, want one for %s", timers, hash)
	}
	second := run("second")
	if len(first) == 0 || len(first) != len(second) {
		t.Fatalf("programs: first %d, second %d", len(first), len(second))
	}
	for name, id := range first {
		if second[name] != id {
			t.Errorf("%s: the second run runs program %d, the first %d: it loaded the build again", name, second[name], id)
		}
	}

	sweep := func(force bool) BuildState {
		t.Helper()
		states, err := SweepBuilds(SweepOptions{StateDir: state, Linger: time.Hour, Force: force})
		if err != nil {
			t.Logf("SweepBuilds: %v", err) // other builds' pins on this machine are not this test's
		}
		for _, s := range states {
			if s.Hash == hash {
				return s
			}
		}
		t.Fatalf("the sweep did not report build %s: %+v", hash, states)
		return BuildState{}
	}
	if s := sweep(false); s.Removed || s.Why != whyLingering {
		t.Fatalf("a build idle for less than its linger: removed %v (%s)", s.Removed, s.Why)
	}

	// A launcher of the build keeps it, whatever its idle time.
	held, err := acquireBuildLock(state, hash)
	if err != nil {
		t.Fatal(err)
	}
	if s := sweep(true); s.Removed || s.Why != whyBusy {
		t.Fatalf("a build a launcher holds: removed %v (%s)", s.Removed, s.Why)
	}
	if err := held.Close(); err != nil {
		t.Fatal(err)
	}

	// So does a run it enforces whose launcher died: a run-set row for a cgroup that exists.
	runSet, err := ebpf.LoadPinnedMap(filepath.Join(pins.Maps, ebpfbindings.MapRunSet), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer runSet.Close()
	_, orphan := runCgroup(t, "linger-orphan")
	if err := runSet.Put(&orphan, &ebpfbindings.Run{RunIdx: 1, Descendants: 1, Tier: 2}); err != nil {
		t.Fatal(err)
	}
	if s := sweep(true); s.Removed || s.Why != whyLive {
		t.Fatalf("a build an orphaned run still runs under: removed %v (%s)", s.Removed, s.Why)
	}
	if err := runSet.Delete(&orphan); err != nil {
		t.Fatal(err)
	}

	// A row whose cgroup is gone keeps nothing, and the sweep deletes it before it removes the build.
	gone := uint64(1) << 62
	if err := runSet.Put(&gone, &ebpfbindings.Run{RunIdx: 1, Descendants: 1, Tier: 2}); err != nil {
		t.Fatal(err)
	}
	if s := sweep(true); !s.Removed {
		t.Fatalf("an idle build with no live run was kept: %s", s.Why)
	}
	if _, err := os.Stat(pins.Root); !os.IsNotExist(err) {
		t.Fatalf("the swept build left %s (%v)", pins.Root, err)
	}
}

// TestIntegrationABuildWhoseTimerDiedIsRemovedAtTheNextPrepare is round 7's M4 (b) against the running kernel, as
// root, in the form ADR 0022's 2026-10-06 note gives it: the last launcher out of a build leaves it lingering and
// hands it to a timer, and the timer is gone (killed with the launcher's cgroup, or by anyone). Once the linger has
// passed, the next run's Prepare, of any build, starts that build's timer again, a real `tego __bpf-linger` in
// tego's helper cgroup, and the timer removes it within 3 s: its pins, and with them the programs and host-wide
// links it held. The removal is not on the run's path: Prepare's lock-slot step, where the re-arm runs, stays under
// 50 ms, where removing the build there took 1 to 3.7 s on 6.1 and 5.14, which detach synchronously in the unpinning
// process. With the kernel's lock table read there the slot took 48 ms of its 50 on 6.1 (note 2026-10-16), so Prepare
// reads a timer's pid instead; the test logs what a lock-table read costs on the kernel it runs on.
func TestIntegrationABuildWhoseTimerDiedIsRemovedAtTheNextPrepare(t *testing.T) {
	requireRealPrepare(t)
	state := pinState(t)
	bin := t.TempDir()
	if err := os.Chmod(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	exe := buildTaggedTego(t, bin)
	table := &agent.RuleTable{Net: []agent.NetRule{}, Tier: backend.TierCgroup, Record: agent.RecordSummary}
	const linger = time.Second
	phases := map[string]map[string]time.Duration{}
	prepare := func(hash, name string, o Options) *Handle {
		t.Helper()
		o.Machine, o.StateDir, o.Hash, o.Events = machineLinger(linger), state, hash, &sink{}
		phases[name] = map[string]time.Duration{}
		o.Phase = func(phase string, d time.Duration) {
			if strings.HasPrefix(phase, "prepare.lock-slot") || strings.HasPrefix(phase, "prepare.rearm") {
				phases[name][phase] += d
			}
		}
		rel, id := runCgroup(t, "timer-"+name)
		h, err := New(o).Prepare(context.Background(), table,
			Run{ID: name, Agent: "a", CgroupID: id, CgroupPath: rel, StageExe: exe})
		if err != nil {
			t.Fatalf("Prepare %s: %v", name, err)
		}
		return h
	}
	orphan := fmt.Sprintf("timer-died-%d", os.Getpid())
	pins, err := newPinLayout(DefaultBPFFS, orphan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pins.remove() })
	h := prepare(orphan, "first", Options{startTimer: func(string) error { return nil }}) // the timer dies at once
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, err := os.Stat(pins.Links); err != nil {
		t.Fatalf("the build did not linger: %v", err)
	}
	time.Sleep(linger + 1500*time.Millisecond) // past the linger by more than the lock mtime's second

	next := fmt.Sprintf("timer-next-%d", os.Getpid())
	nextPins, err := newPinLayout(DefaultBPFFS, next)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = nextPins.remove() })
	h = prepare(next, "second", Options{})
	prepared := time.Now()
	defer func() { _ = h.Close() }()
	_, err = os.Stat(pins.Root)
	t.Logf("phases: first Prepare (nothing to re-arm) %v; second %v; the build whose timer died was there when the "+
		"second returned: %v", phases["first"], phases["second"], err == nil)
	if slot := phases["second"]["prepare.lock-slot"]; slot >= 50*time.Millisecond {
		t.Errorf("prepare.lock-slot took %v, over its 50 ms (re-arm %v, of which the timer's start %v)", slot,
			phases["second"]["prepare.rearm"], phases["second"]["prepare.rearm.start"])
	}
	for {
		if _, err := os.Stat(pins.Root); os.IsNotExist(err) {
			t.Logf("the re-armed timer removed the build %v after Prepare returned", time.Since(prepared).Round(time.Millisecond))
			// What Prepare no longer reads (ADR 0022, note 2026-10-16): the kernel's lock table, whose read waits for
			// an RCU grace period (fs/locks.c locks_start). Informational; `tego stop`'s pass reads it.
			var reads []time.Duration
			for range 3 {
				time.Sleep(100 * time.Millisecond)
				start := time.Now()
				if _, err := procLocksTable(0); err != nil {
					t.Fatalf("read /proc/locks: %v", err)
				}
				reads = append(reads, time.Since(start).Round(10*time.Microsecond))
			}
			t.Logf("a /proc/locks read took %v", reads)
			return
		}
		if time.Since(prepared) > 3*time.Second {
			t.Fatalf("the build whose timer died is still pinned at %s 3 s after the next Prepare", pins.Root)
		}
		time.Sleep(20 * time.Millisecond)
	}
}
