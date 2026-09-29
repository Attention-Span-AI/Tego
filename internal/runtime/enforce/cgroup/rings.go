// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Per-run rings (ADR 0026 (1)-(6)). Each run gets its own record ring in tego_events, and its own capture ring in
// tego_capture_events when its capture is uprobe, both at its slot, so each run's recorder and capture source
// read rings no other run writes. The rings are the one per-run allocation of kernel memory that scales with
// concurrent runs, so their total is capped host-wide by bpf.ring_budget, over every build: a Prepare that has to
// create a ring counts what every live ring charges now, under one host-wide lock, and a run whose record ring
// does not fit is refused with ErrRingBudget.
//
// A slot keeps its rings after its run (ADR 0026 (6) as amended). Every update or delete of a map-in-map outer
// waits for an RCU grace period in the kernel (maybe_wait_bpf_programs), 7-15 ms each on 6.17 in the KVM guest,
// and a run that placed two rings and removed them paid four: about 30 ms of kill test 4's go build. So the rings
// of a build's slots below ringPoolSlots stay in the outers when the run ends, still counted in the budget, and
// the slot's next run reuses them: it drains them first, and its readers drop any record of another generation
// (Run.Gen, stamped on every record), so a run never reads what the slot's previous run left. Only a ring of
// another size, or a capture ring a run does not want, is replaced or removed on the run's path. The rings of the
// slots above the pool are removed after the run by a process of their own (RingTrimCommand), and the rings no
// run holds, of any build, are reclaimed when a placement needs their room, and by `tego gc --builds`.
const (
	// recordOffRing is the record ring of a record: off run, which carries only execs and exits (the recorder
	// keeps them for its process cache and the budget's activity, and records nothing): a small fixed ring
	// rather than record.ringbuf (ADR 0026 (2)).
	recordOffRing = 256 << 10
	// ringsLockName is the host-wide lock in /run/tego: a launcher that creates a ring, and anything that
	// removes one it does not hold, holds it exclusively, so two launchers never both fit into the same room and
	// no ring is removed from under a run about to reuse it; a launcher that only reuses its slot's rings holds it
	// shared.
	ringsLockName = "rings.lock"
	// ringPoolSlots is how many of a build's slots keep their rings after their run: the lowest ones, which the
	// slot table hands out first, so back-to-back and lightly concurrent runs reuse rings, and a burst of runs
	// leaves no more than this many rings of the build behind it (about 34 MB at the default record.ringbuf).
	ringPoolSlots = 8
	// RingTrimCommand is the hidden first argument cmd/tego dispatches to RingTrimMain: the removal of a run's
	// rings above the pool, off the run's path.
	RingTrimCommand = "__ring-trim"
)

// ringKinds are the two kinds of a slot's rings, the record ring first.
var ringKinds = []string{ebpfbindings.RingRecord, ebpfbindings.RingCapture}

// wantRings is the size of each ring this run needs, by kind: a record ring always, of record.ringbuf or the
// small record: off one, and a capture ring of record.ringbuf when its capture is uprobe.
func (h *Handle) wantRings() map[string]uint32 {
	size := h.ringbuf
	if h.recordMode == ebpfbindings.RecordOff {
		size = recordOffRing
	}
	want := map[string]uint32{ebpfbindings.RingRecord: size}
	if h.wantCapture {
		want[ebpfbindings.RingCapture] = h.ringbuf
	}
	return want
}

// placeRings is Prepare's ring step. When the run's slot already holds the rings the run needs, it reuses them
// under the shared rings lock: no ring is created or inserted, so nothing new is charged and no grace period is
// waited for. Otherwise, under the exclusive lock, it reclaims the rings of builds no launcher runs, counts what
// every build's live rings charge and places what is missing, reclaiming every ring no run holds when the room
// is short. A record ring that does not fit the budget refuses the run (ErrRingBudget). A capture ring that does
// not fit is left out, and the run goes on without one: its uprobe source then finds no ring and says why, and
// the runtime refuses the run only when a token, cost or repeats budget needed that capture
// (limits-check-doctor-cli R32).
func (h *Handle) placeRings() error {
	want := h.wantRings()
	unlock, err := h.lockRings(unix.LOCK_SH)
	if err != nil {
		return err
	}
	missing, err := h.reuseRings(want)
	unlock()
	if err != nil || len(missing) == 0 {
		return err
	}

	unlock, err = h.lockRings(unix.LOCK_EX)
	if err != nil {
		return err
	}
	defer unlock()
	if missing, err = h.reuseRings(want); err != nil || len(missing) == 0 {
		return err
	}
	base := h.pins.Base
	// Best effort, and off the reuse path: the rings of builds no launcher runs, and the files of builds that are
	// gone, go before this run counts.
	_, _, _ = h.kern.reclaimRings(base, h.noOnes(true))
	_, _ = removeStaleState(h.slots.dir, base)
	used, rings, err := h.kern.ringUse(base)
	if err != nil {
		return err
	}
	budget := h.ringBudget
	room := func() uint64 {
		if used >= budget {
			return 0
		}
		return budget - used
	}
	reclaimed := false
	for _, kind := range missing {
		size := want[kind]
		memlock, placed, err := h.kern.placeRing(kind, h.slot, size, room())
		if err != nil {
			return err
		}
		if !placed && !reclaimed {
			// Short of room: every ring no run holds, this build's pool included, gives its room back first.
			// Best effort too: an error here is another build's state that could not be read, after reclaim freed
			// what it could. ringUse, which fails closed, and the placement decide whether this run fits.
			reclaimed = true
			_, _, _ = h.kern.reclaimRings(base, h.noOnes(false))
			if used, rings, err = h.kern.ringUse(base); err != nil {
				return err
			}
			if memlock, placed, err = h.kern.placeRing(kind, h.slot, size, room()); err != nil {
				return err
			}
		}
		if !placed {
			if kind == ebpfbindings.RingRecord {
				return fmt.Errorf("%w: this run's %d-byte record ring charges %d B, and the %d live rings on this "+
					"host already charge %d B of bpf.ring_budget's %d B; wait for other runs to end, or raise "+
					"bpf.ring_budget in /etc/tego/config.yaml (`tego doctor` shows each build's rings)",
					ErrRingBudget, size, memlock, rings, used, budget)
			}
			h.captureRefused = fmt.Errorf("%w: this run's %d-byte capture ring charges %d B, and %d B of "+
				"bpf.ring_budget's %d B is in use", ErrRingBudget, size, memlock, used, budget)
			continue
		}
		used += memlock
		rings++
	}
	return nil
}

// reuseRings makes the run's slot hold only rings this run may use, and says which it still needs, the record
// ring first. It runs under the rings lock, shared or exclusive: no one else touches a slot this run holds. A
// ring of a kind the run does not want (a capture ring, when its capture is not uprobe: the shared probes would
// write its TLS plaintext there) or of another size is removed; each ring it keeps is drained, so the run starts
// reading at an empty ring, and a ring that cannot be drained is removed and placed afresh.
func (h *Handle) reuseRings(want map[string]uint32) ([]string, error) {
	have, err := h.kern.slotRings(h.slot)
	if err != nil {
		return nil, err
	}
	var missing []string
	for _, kind := range ringKinds {
		size, ok := have[kind]
		if ok && size == want[kind] {
			if err := h.kern.drainRing(kind, h.slot); err == nil {
				continue
			}
		}
		if ok {
			if err := h.kern.removeRing(kind, h.slot); err != nil {
				return nil, err
			}
		}
		if want[kind] != 0 {
			missing = append(missing, kind)
		}
	}
	return missing, nil
}

// CaptureRefused is why Prepare left this run's capture ring out, nil when it placed one or the run does not
// capture with uprobes: the host's ring budget had no room for it (ErrRingBudget).
func (h *Handle) CaptureRefused() error { return h.captureRefused }

// parkRings is Detach's ring step, once the slot is released: the rings stay at a pool slot for its next run,
// and a slot above the pool has them removed off the run's path (trimRings), where the grace period each removal
// waits for costs no run anything. The trimmer is one of tego's helpers (startHelperProcess), as the linger timer
// is: in the launcher's cgroup, stopping the unit or CI job the launcher ran in killed it with the launcher, and
// the rings stayed charged to bpf.ring_budget until a later placement's reclaim or gc.
func (h *Handle) parkRings() error {
	if h.slot < ringPoolSlots || h.kern == nil {
		return nil
	}
	if h.opts.trimRings != nil {
		return h.opts.trimRings(h.hash)
	}
	state := h.opts.StateDir
	if state == "" {
		state = hoststate.Path
	}
	bpffs := h.opts.BPFFS
	if bpffs == "" {
		bpffs = DefaultBPFFS
	}
	exe := h.run.StageExe
	if exe == "" {
		// A Go test binary is never tego: it trims in place, as `tego gc --builds` would.
		if self, err := os.Executable(); err == nil && strings.HasSuffix(self, ".test") {
			_, _, err := TrimRings(SweepOptions{BPFFS: bpffs, StateDir: state}, h.hash)
			return err
		}
		exe = "/proc/self/exe"
	}
	if err := startHelperProcess(exe, RingTrimCommand, h.hash, bpffs, state); err != nil {
		return fmt.Errorf("cgroup: start the removal of slot %d's rings: %w", h.slot, err)
	}
	return nil
}

// noOnes is the reclaim's test of a ring's slot: no live launcher holds it (its run-set rows, checked by the
// reclaim itself, carry it neither). With idleBuilds, only the rings of other builds none of whose launchers is
// running are no one's: this build's pool and a running build's are kept, since a run of theirs would pay to
// place them again.
func (h *Handle) noOnes(idleBuilds bool) func(hash string, slot uint32) (bool, error) {
	return func(hash string, slot uint32) (bool, error) {
		if hash == h.hash {
			if idleBuilds {
				return false, nil
			}
			held, err := h.slots.heldBy(slot)
			return !held, err
		}
		if idleBuilds && buildRunning(h.slots.dir, hash) {
			return false, nil
		}
		held, err := peekHeld(h.slots.dir, hash, slot, h.slots.alive)
		return !held, err
	}
}

// buildRunning reports whether a launcher of the build holds its lock: one is preparing, running or leaving.
func buildRunning(d *hoststate.Dir, hash string) bool {
	f, busy, err := lockBuildExclusiveNB(d, hash, false)
	if err != nil {
		return errors.Is(err, ErrBuildLock) // a lock that cannot be taken is held, as before; one with no file is not
	}
	if busy {
		return true
	}
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
	return false
}

// peekHeld reports whether a live launcher holds slot idx of build hash, reading that build's slot table without
// creating it: a build with none has no slot held.
func peekHeld(d *hoststate.Dir, hash string, idx uint32, alive func(owner) bool) (bool, error) {
	name := slotTableName + "-" + hash
	s := &slotTable{dir: d, name: name, path: filepath.Join(d.Path(), name), alive: alive, peek: true}
	held, err := s.heldBy(idx)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return held, err
}

// lockRings takes the host-wide rings lock, shared or exclusive, blocking: an exclusive holder holds it only
// while it counts, reclaims and places, a grace period or a few.
func (h *Handle) lockRings(how int) (func(), error) { return lockRingsIn(h.slots.dir, how) }

// lockRingsIn takes the rings lock in the state directory d.
func lockRingsIn(d *hoststate.Dir, how int) (func(), error) {
	f, err := d.OpenFile(ringsLockName, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, fmt.Errorf("cgroup: open the rings lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), how); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("cgroup: lock the rings lock: %w", err)
	}
	return func() {
		_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
		_ = f.Close()
	}, nil
}

// ringUse sums what every ring of every build under base charges: the memlock of each inner ring of each build's
// two outers (ADR 0026 (2)). A build whose outers cannot be read is skipped with its error joined, so one
// unreadable build does not hide the rest; the caller treats any error as fatal, which fails closed.
func ringUse(base string) (uint64, int, error) {
	var (
		total uint64
		count int
	)
	err := eachBuild(base, func(_, maps string) error {
		bytes, n, err := buildRings(maps)
		total += bytes
		count += n
		return err
	})
	return total, count, err
}

// eachBuild calls fn with every build's hash and maps directory under base, and joins what it returns.
func eachBuild(base string, fn func(hash, maps string) error) error {
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cgroup: list builds under %s: %w", base, err)
	}
	var errs []error
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, _, plane := planeDirOf(e.Name()); plane {
			continue // a build's plane holds no ring and no run set of its own (plane.go)
		}
		if err := fn(e.Name(), filepath.Join(base, e.Name(), pinMaps)); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// openOuter opens one of a build's pinned ring outers; ok is false when the build has none of that name, or an
// older build's single ring there (the budget covers per-run rings only).
func openOuter(maps, name string, readOnly bool) (*ebpf.Map, bool, error) {
	path := filepath.Join(maps, name)
	outer, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: readOnly})
	if errors.Is(err, os.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("cgroup: open %s: %w", path, err)
	}
	if outer.Type() != ebpf.HashOfMaps && outer.Type() != ebpf.ArrayOfMaps {
		_ = outer.Close()
		return nil, false, nil
	}
	return outer, true, nil
}

// buildRings sums the memlock of one build's rings, and counts them. A build with no outers pinned (one that
// predates per-run rings, or is still being created) has none. A ring removed while the walk runs is simply not
// counted; a ring whose charge cannot be read is an error, never a ring counted as free.
func buildRings(maps string) (uint64, int, error) {
	var (
		total uint64
		count int
	)
	for _, name := range ebpfbindings.RingMaps {
		outer, ok, err := openOuter(maps, name, true)
		if err != nil {
			return total, count, err
		}
		if !ok {
			continue
		}
		ids, err := ebpfbindings.RingIDs(outer)
		_ = outer.Close()
		if err != nil {
			return total, count, fmt.Errorf("cgroup: walk %s: %w", filepath.Join(maps, name), err)
		}
		for _, id := range ids {
			ring, ok, err := ebpfbindings.OpenRing(id)
			if err != nil {
				return total, count, err
			}
			if !ok {
				continue
			}
			n, err := ebpfbindings.Memlock(ring)
			_ = ring.Close()
			if err != nil {
				return total, count, err
			}
			total += n
			count++
		}
	}
	return total, count, nil
}

// reclaimRings removes, from every build under base, each ring at a slot the build's run set does not carry and
// noOne says no launcher holds, and reports what those rings charged and how many they were. The caller holds
// the rings lock exclusively, so no launcher is between taking such a slot and reusing its rings. A build whose
// run set or outers cannot be read keeps its rings, with the error joined. A non-empty only limits it to that
// build: no other build's run set or outers are opened, and none of their errors is joined.
//
// Only this binary's own build has its run set's values read (a row's run_idx, this binary's Run layout). Of any
// other build the keys alone are read, the one layout every build shares (ADR 0022 (5)): one whose run set has a
// key keeps every ring, since which slots its rows carry cannot be told, and one whose run set is empty carries
// none. Read with this build's layout, a later build's rows could name the wrong slots and an orphaned run's ring
// be deleted under it, or fail every lookup and keep the build's rings forever.
func reclaimRings(base, only string, noOne func(hash string, slot uint32) (bool, error)) (uint64, int, error) {
	var (
		freed uint64
		count int
	)
	own, ownErr := reclaimOwnHash()
	if ownErr != nil {
		own = "" // every build is another's: keys only
	}
	err := eachBuild(base, func(hash, maps string) error {
		if only != "" && hash != only {
			return nil
		}
		var carried map[uint32]bool
		if hash == own {
			var err error
			if carried, err = pinnedRunSetSlots(maps); err != nil {
				return err
			}
		} else {
			rows, err := pinnedRunSetHasKeys(maps)
			if err != nil {
				return err
			}
			if rows {
				return nil // another build's rows carry slots this binary cannot name: every ring stays
			}
			carried = map[uint32]bool{}
		}
		var errs []error
		for _, name := range ebpfbindings.RingMaps {
			outer, ok, err := openOuter(maps, name, false)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if !ok {
				continue
			}
			ids, err := ebpfbindings.RingIDs(outer)
			if err != nil {
				_ = outer.Close()
				errs = append(errs, err)
				continue
			}
			for slot, id := range ids {
				if carried[slot] {
					continue
				}
				if free, err := noOne(hash, slot); err != nil || !free {
					errs = append(errs, err)
					continue
				}
				var charged uint64
				if ring, ok, err := ebpfbindings.OpenRing(id); err == nil && ok {
					charged, _ = ebpfbindings.Memlock(ring)
					_ = ring.Close()
				}
				if err := ebpfbindings.DeleteRing(outer, slot); err != nil {
					errs = append(errs, err)
					continue
				}
				freed += charged
				count++
			}
			_ = outer.Close()
		}
		return errors.Join(errs...)
	})
	return freed, count, err
}

// runSetSlots lists the slots a run set's rows carry.
func runSetSlots(m *ebpf.Map) (map[uint32]bool, error) {
	if m == nil {
		return map[uint32]bool{}, nil
	}
	return runSetSlotsIn(m)
}

// runSetMap is the part of *ebpf.Map runSetSlots reads.
type runSetMap interface {
	keyWalker
	Lookup(key, valueOut any) error
}

// runSetSlotsIn is runSetSlots over any map. The run set is shared by every run of the build and cgroup_rmdir
// deletes its rows at any time, so the walk steps through restarts (mapKeys) and a row gone before its lookup
// is skipped: it carries no slot any more.
func runSetSlotsIn(m runSetMap) (map[uint32]bool, error) {
	keys, err := mapKeys[uint64](m)
	if err != nil {
		return nil, fmt.Errorf("cgroup: walk the run set: %w", err)
	}
	out := map[uint32]bool{}
	for _, k := range keys {
		var row ebpfbindings.Run
		err := m.Lookup(&k, &row)
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("cgroup: look up run set row %d: %w", k, err)
		}
		out[row.RunIdx] = true
	}
	return out, nil
}

// reclaimOwnHash names this binary's build for reclaimRings; a variable, so a test names one.
var reclaimOwnHash = bpfHash

// pinnedRunSetHasKeys reports whether a build's pinned run set holds any row, reading its keys only (ADR 0022
// (5)): what reclaimRings reads of a build other than this binary's. A build with no run set pinned has none.
var pinnedRunSetHasKeys = func(maps string) (bool, error) {
	path := filepath.Join(maps, ebpfbindings.MapRunSet)
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("cgroup: open %s: %w", path, err)
	}
	defer func() { _ = m.Close() }()
	keys, err := mapKeys[uint64](m)
	if err != nil {
		return false, fmt.Errorf("cgroup: walk the run set %s: %w", path, err)
	}
	return len(keys) > 0, nil
}

// pinnedRunSetSlots is runSetSlots over a build's pinned run set, before this launcher has loaded anything: the
// slots the slot table must not hand out, since a run-set row still carries them (ADR 0026 (6)). A build with no
// run set pinned yet carries none.
var pinnedRunSetSlots = func(maps string) (map[uint32]bool, error) {
	path := filepath.Join(maps, ebpfbindings.MapRunSet)
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if errors.Is(err, os.ErrNotExist) {
		return map[uint32]bool{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: open %s: %w", path, err)
	}
	defer func() { _ = m.Close() }()
	return runSetSlots(m)
}

// RingUse is the host's ring budget and what every build's live rings charge against it now, for `tego doctor`
// (ADR 0026 (2)). It needs root, as reading the pins does.
type RingUse struct {
	Budget uint64 `json:"budget"`
	Used   uint64 `json:"used"`
	Rings  int    `json:"rings"`
}

// ReclaimRings removes every ring no run holds, of every build under the bpf filesystem opts names: at a slot
// no live launcher of its build holds and no run-set row of its build carries (of another binary's build, whose
// rows it reads by key only, none at all: reclaimRings). `tego gc --builds` calls it, so
// the rings a crashed launcher, an idle build's pool or an old build left stop counting against bpf.ring_budget.
// It returns how many it removed and what they charged.
func ReclaimRings(opts SweepOptions) (int, uint64, error) {
	return reclaimWhere(opts, "", func(string, uint32) bool { return true })
}

// TrimRings removes the rings of build hash above its pool (ringPoolSlots) that no run holds, what a run whose
// slot is above the pool leaves when it ends (RingTrimCommand). It reads no other build's run set or rings, so
// another build it cannot read neither holds the rings lock longer nor fails the trim.
func TrimRings(opts SweepOptions, hash string) (int, uint64, error) {
	return reclaimWhere(opts, hash, func(_ string, slot uint32) bool { return slot >= ringPoolSlots })
}

// reclaimWhere is ReclaimRings over the rings which pick selects, of build only (every build when it is empty),
// under the exclusive rings lock.
func reclaimWhere(opts SweepOptions, only string, pick func(hash string, slot uint32) bool) (int, uint64, error) {
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	d, err := openState(opts.BPFFS, opts.StateDir)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = d.Close() }()
	unlock, err := lockRingsIn(d, unix.LOCK_EX)
	if err != nil {
		return 0, 0, err
	}
	defer unlock()
	freed, n, err := reclaimRings(filepath.Join(opts.BPFFS, pinRoot), only, func(hash string, slot uint32) (bool, error) {
		if !pick(hash, slot) {
			return false, nil
		}
		held, err := peekHeld(d, hash, slot, owner.alive)
		return !held, err
	})
	return n, freed, err
}

// RingTrimMain is `tego __ring-trim <hash> <bpffs> <state dir>`, which a run whose slot is above its build's pool
// starts once its slot is released (parkRings): it removes the build's rings above the pool that no run holds.
// It touches nothing but the ring outers of that build under the bpf filesystem's tego tree and the rings lock
// in the verified state directory. It returns the process's exit code.
func RingTrimMain(args []string) int {
	if len(args) != 3 {
		fmt.Fprintf(os.Stderr, "usage: tego %s <hash> <bpffs> <state dir>\n", RingTrimCommand)
		return identity.ExitUsage
	}
	hash := args[0]
	if !IsBuildHash(hash) {
		fmt.Fprintf(os.Stderr, "tego %s: %q is not a build hash\n", RingTrimCommand, hash)
		return identity.ExitUsage
	}
	if _, _, err := TrimRings(SweepOptions{BPFFS: args[1], StateDir: args[2]}, hash); err != nil {
		fmt.Fprintf(os.Stderr, "tego %s: %v\n", RingTrimCommand, err)
		return identity.ExitError
	}
	return identity.ExitOK
}
