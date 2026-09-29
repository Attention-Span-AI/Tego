// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/cilium/ebpf"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// ADR 0020: a launcher's death changes nothing the kernel enforces, and a reaper ends the orphaned run at once.
// The run's cgroup links are pinned (kernel.go's pinRunLink), so they outlive a SIGKILLed launcher; what then
// stays behind once the run's processes are gone is removed here, by the run's reaper (internal/runtime's
// ReapMain) and by every sweep that removes an orphan's cgroup (internal/runtime's killOrphan):
//
//   - the run's links, links/run-<id> under the build its run_start names (ADR 0020 (6)), unpinned only once
//     the run's cgroup is gone, which PurgeRun checks itself;
//   - the run-set rows of cgroups that no longer exist (keys only, the one cross-build contract, ADR 0022 (5));
//   - the verdict rows, plane rows, network controls' rows, one-connect grants and counters of every slot whose
//     launcher is dead and that no run-set row carries, which
//     the slot's next Prepare would otherwise scrub (purgeSlot), so a dead run's allow rows stop counting
//     against every other run's budget at once; the slot is claimed for the purge, so no launcher can be handed
//     it meanwhile, and freed after;
//   - the rings above the build's pool that no run holds (ADR 0026 (6) as amended): the pool's stay at their
//     slot for its next run, drained and generation-checked there, as a run that ended normally leaves them.
//
// A run whose cgroup cannot be removed keeps all of it: its links, its rows (carried, so its slot stays held)
// and its rings.

// ReapTarget is what a run's reaper needs of the tier-2 state its launcher prepared, fixed before the child
// stage exists (ADR 0020 (2)).
type ReapTarget struct {
	// Hash is the build the run's programs and pins live in.
	Hash string
	// BPFFS is the bpf filesystem the pins are under.
	BPFFS string
	// StateDir holds the build lock and the slot table; "" is the verified /run/tego.
	StateDir string
	// Linger is the machine's bpf.linger, for the build's duties once the run is purged (ADR 0022 (2)-(3)).
	Linger time.Duration
	// Slot is the run_idx the run holds, and PlaneMode the decision plane's mode it decides in ("" on the fanotify
	// fallback): the reaper reads the slot's plane counters before the run's run_end (ReadPlaneCounters).
	Slot      uint32
	PlaneMode string
}

// ReapTarget reports the handle's build, pins and machine settings for the run's reaper.
func (h *Handle) ReapTarget() ReapTarget {
	return ReapTarget{Hash: h.hash, BPFFS: h.opts.BPFFS, StateDir: h.opts.StateDir, Linger: h.opts.linger(),
		Slot: h.slot, PlaneMode: string(h.planeMode)}
}

// ReadPlaneCounters reads the plane counters of t's slot from the build's pinned map of t's mode (enforce-plane
// §2.8), named as Handle.PlaneCounters names them. The reaper calls it for an orphaned run once the run's cgroup has
// emptied and before it removes it: the run-set rows still carry the slot then, so no launcher has been handed it and
// no Prepare has zeroed it. A target with no plane mode has no counters.
func ReadPlaneCounters(t ReapTarget) ([]PlaneCount, error) {
	if t.PlaneMode == "" {
		return nil, nil
	}
	mode := ebpfbindings.PlaneMode(t.PlaneMode)
	if !slices.Contains(planeModes, mode) {
		return nil, fmt.Errorf("cgroup: %q is no plane mode", t.PlaneMode)
	}
	pins, err := newPinLayout(t.BPFFS, t.Hash)
	if err != nil {
		return nil, err
	}
	lay := newPlaneLayout(pins, t.Hash, mode)
	m, err := loadPinnedMap(lay.Maps, ebpfbindings.MapPlaneCounters)
	if err != nil {
		return nil, err
	}
	if m == nil {
		return nil, fmt.Errorf("cgroup: no %s plane counters are pinned under %s", mode, lay.Maps)
	}
	defer func() { _ = m.Close() }()
	p := &bpfPlane{mode: mode, counters: m}
	c, err := p.counts(t.Slot)
	if err != nil {
		return nil, err
	}
	return planeCounts(c), nil
}

// PurgeOptions name the run PurgeRun purges.
type PurgeOptions struct {
	// BPFFS is the bpf filesystem; "" is DefaultBPFFS.
	BPFFS string
	// StateDir holds the slot table and the rings lock; "" is the verified /run/tego.
	StateDir string
	// CgroupMount is the cgroup2 mount the run's cgroup was under; "" is the system's.
	CgroupMount string
	// Hash is the build run_start names (never the purging binary's own, ADR 0020 (6)).
	Hash string
	// RunID names the run's link directory.
	RunID string
	// CgroupID is the run's own cgroup; while a cgroup of that id exists nothing is purged. 0 skips the check,
	// for a run that recorded none: its launcher died before run_start, before any process of it existed.
	CgroupID uint64
}

// PurgeResult is what one PurgeRun removed.
type PurgeResult struct {
	// Links says the run's link directory was there and is gone.
	Links bool
	// Slots are the dead launchers' slots whose rows were purged and which are free again.
	Slots []uint32
	// Rings is how many rings above the pool were removed.
	Rings int
}

// ErrRunAlive is a purge refused because the run's cgroup still exists: its processes may be alive, and its
// links and rows are what enforces them (ADR 0020 (3)).
var ErrRunAlive = errors.New("cgroup: the run's cgroup still exists; its kernel state is kept")

// PurgeRun removes the kernel state a run whose cgroup is gone left behind (the list at the top of this file).
// It is idempotent: a second pass, or one over a run its launcher tore down itself, finds nothing and changes
// nothing. It needs root. A build that is gone took the run's pins with it, and there is nothing to purge.
func PurgeRun(opts PurgeOptions) (PurgeResult, error) {
	var res PurgeResult
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	if opts.CgroupMount == "" {
		opts.CgroupMount = identity.SystemCgroupRoot
	}
	// Asked first: the run's links go before the state directory is opened, and a refused pairing removes nothing.
	if _, err := lockRootOf(opts.BPFFS, opts.StateDir); err != nil {
		return res, err
	}
	pins, err := newPinLayout(opts.BPFFS, opts.Hash)
	if err != nil {
		return res, err
	}
	if _, err := os.Lstat(pins.Root); errors.Is(err, os.ErrNotExist) {
		return res, nil
	}
	ids, err := cgroupIDs(opts.CgroupMount)
	if err != nil {
		return res, err
	}
	if opts.CgroupID != 0 && ids[opts.CgroupID] {
		return res, fmt.Errorf("%w: cgroup %d, run %s", ErrRunAlive, opts.CgroupID, opts.RunID)
	}
	var errs []error
	if dir := pins.runLinks(opts.RunID); dir != "" {
		if _, err := os.Lstat(dir); err == nil {
			res.Links = true
		}
		if err := removeRunLinks(dir, nil); err != nil {
			res.Links = false
			errs = append(errs, err)
		}
	}
	d, err := openState(opts.BPFFS, opts.StateDir)
	if err != nil {
		return res, errors.Join(append(errs, err)...)
	}
	defer func() { _ = d.Close() }()
	runSet, err := loadPinnedMap(pins.Maps, ebpfbindings.MapRunSet)
	if err != nil {
		return res, errors.Join(append(errs, err)...)
	}
	if runSet != nil {
		defer func() { _ = runSet.Close() }()
		if _, err := runSetLive(runSet, opts.CgroupMount); err != nil {
			errs = append(errs, err)
		}
	}
	// Verdict rows are laid out by this binary's build: another build's are left to its own next Prepare, since
	// only the run set's key is a contract across builds (ADR 0022 (5)).
	// A binary that cannot name its own build cannot tell whose rows these are, and the slots are left, said.
	if runSet != nil {
		switch own, err := bpfHash(); {
		case err != nil:
			errs = append(errs, fmt.Errorf("cgroup: the dead slots are not purged: this binary's build hash: %w", err))
		case own == opts.Hash:
			slots, err := purgeDeadSlots(d, pins, opts.Hash, runSet)
			res.Slots = slots
			if err != nil {
				errs = append(errs, err)
			}
		}
	}
	n, _, err := TrimRings(SweepOptions{BPFFS: opts.BPFFS, StateDir: opts.StateDir}, opts.Hash)
	res.Rings = n
	if err != nil {
		errs = append(errs, err)
	}
	return res, errors.Join(errs...)
}

// loadPinnedMap opens one of a build's pinned maps; one not pinned is nil with no error.
func loadPinnedMap(maps, name string) (*ebpf.Map, error) {
	path := filepath.Join(maps, name)
	m, err := ebpf.LoadPinnedMap(path, nil)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: open %s: %w", path, err)
	}
	return m, nil
}

// purgeDeadSlots purges the verdict rows and counters of every slot of build hash whose launcher is dead and that
// no row of runSet carries, then frees it. Each such slot is first claimed, under the table's lock, in this
// process's name, so the slot table hands it to no launcher while its rows are deleted; the run set is read
// under the same lock, so a row inserted by a launcher that died just before counts. A process that dies
// mid-purge leaves its claims dead, and the slot's next Prepare purges it as before.
func purgeDeadSlots(d *hoststate.Dir, pins pinLayout, hash string, runSet *ebpf.Map) ([]uint32, error) {
	maps := pins.Maps
	st, err := openPurgeTable(d, hash)
	if err != nil {
		return nil, err
	}
	defer func() { _ = st.close() }()
	claimed, err := claimDeadSlots(st, func() (map[uint32]bool, error) { return runSetSlots(runSet) }, writeRecord)
	if err != nil || len(claimed) == 0 {
		return nil, err
	}
	k := &bpfKernel{maps: map[string]*ebpf.Map{}}
	defer func() {
		for _, m := range k.maps {
			_ = m.Close()
		}
		for _, p := range k.pinnedPlanes {
			_ = p.closePinned()
		}
	}()
	var loadErrs []error
	// The build's decision planes, each mode's row maps and pinned clear (plane.go): purgeSlot clears the slot's
	// plane rows too (enforce-plane R6, ADR 0020 (3)).
	planes, planeErr := openPinnedPlanes(pins.Base, hash, d)
	k.pinnedPlanes = planes
	// Every pinned map purgeSlot purges: the verdict rows, the net timeline, the slot counters and the network
	// controls' maps with both one-connect grant maps (tego_connect_approvals, tego_unix_approvals: supervisor R11c),
	// so a dead launcher's rows go with its slot. A build that predates a map pins none (loadPinnedMap's nil), and
	// purgeSlot skips a map it was not handed.
	names := []string{ebpfbindings.MapNetExact, ebpfbindings.MapNetCIDR, ebpfbindings.MapUnixNames, ebpfbindings.MapUnixApprovals,
		ebpfbindings.MapNetTimeline}
	names = append(append(names, ebpfbindings.NetControlMaps...), ebpfbindings.SlotCounters...)
	for _, name := range names {
		m, err := loadPinnedMap(maps, name)
		if err != nil {
			loadErrs = append(loadErrs, err)
			continue
		}
		if m != nil {
			k.maps[name] = m
		}
	}
	freed, errs := purgeAndRelease(claimed, len(loadErrs) == 0, k.purgeSlot, st.release)
	return freed, errors.Join(append(append(loadErrs, errs...), planeErr)...)
}

// claimDeadSlots holds the table lock while selecting dead, uncarried slots.
// The reader and writer are explicit local dependencies; production uses the run-set reader and writeRecord.
func claimDeadSlots(st *slotTable, carriedOf func() (map[uint32]bool, error), write func(*os.File, int, []byte) error) ([]uint32, error) {
	var claimed []uint32
	tableEntered := false
	err := st.withTable(func(f *os.File, records []byte) error {
		tableEntered = true
		carried, err := carriedOf()
		if err != nil {
			return err
		}
		for i := 0; i < ebpfbindings.MaxSlots; i++ {
			rec := records[i*slotRecordSize : (i+1)*slotRecordSize]
			if binary.LittleEndian.Uint32(rec[4:8])&slotFlagInUse == 0 || carried[uint32(i)] {
				continue
			}
			o := owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])}
			if st.alive(o) {
				continue
			}
			binary.LittleEndian.PutUint32(rec[0:4], st.self.PID)
			binary.LittleEndian.PutUint64(rec[8:16], st.self.StartTicks)
			// A failed write may still publish this owner. Include the attempt in
			// rollback; release verifies ownership before changing a record.
			claimed = append(claimed, uint32(i))
			if err := write(f, i, rec); err != nil {
				return err
			}
		}
		return nil
	})
	if errors.Is(err, os.ErrNotExist) && !tableEntered {
		return nil, nil
	}
	if err != nil {
		// No map purge follows a failed claim stage. Release every attempted
		// claim independently, preserving the original and all rollback errors.
		_, releaseErrs := purgeAndRelease(claimed, false, nil, st.release)
		return nil, errors.Join(append([]error{err}, releaseErrs...)...)
	}
	return claimed, nil
}

// openPurgeTable is purgeDeadSlots' view of build hash's slot table, without creating it (a build with no table
// yet has no slot to purge). The table takes over and closes its directory, so it is given a duplicate of d's
// descriptor: a reopen of d.Path() re-resolved the name and, through OpenAt, skipped ADR 0034's verification that
// d had passed, so the purge read and wrote claims through a directory checked less than the one it was handed.
func openPurgeTable(d *hoststate.Dir, hash string) (*slotTable, error) {
	sd, err := d.Dup()
	if err != nil {
		return nil, err
	}
	st, err := openSlotTableIn(sd, hash)
	if err != nil {
		return nil, err
	}
	st.peek = true
	return st, nil
}

// purgeAndRelease is purgeDeadSlots' last step over the slots it claimed: each is purged when the build's maps
// all loaded (mapsLoaded), on its own, so one slot's failed purge leaves the next ones' rows to no one, and each
// is then freed. A slot is freed whether or not its purge went through: its next Prepare purges it again before
// it writes a row (attachKernel), as it did before there were reapers. It returns the slots freed and every
// error met.
func purgeAndRelease(claimed []uint32, mapsLoaded bool, purge, release func(uint32) error) ([]uint32, []error) {
	var freed []uint32
	var errs []error
	for _, idx := range claimed {
		if mapsLoaded {
			if err := purge(idx); err != nil {
				errs = append(errs, err)
			}
		}
		if err := release(idx); err != nil {
			errs = append(errs, err)
			continue
		}
		freed = append(freed, idx)
	}
	return freed, errs
}

// ReapBuild is the build duty of a reaper whose run is purged (ADR 0022 (2)-(3)): when no launcher of the build
// holds its lock, the run was the build's last, so the build's idle time starts now (the lock's mtime) and the
// reaper removes the build at once when linger is 0, or starts the build's timer otherwise, as the last launcher
// out does (startTimerProcess; a timer already running keeps the timer lock and the new one exits). A launcher
// that holds the lock does both itself when it leaves. A build that is gone, lock and all, needs nothing; any
// other failure is returned for the reaper to log.
//
// The lock is also held exclusively, for a moment, by processes that are not launchers (another build's sweep,
// doctor's ListBuilds, a ring reclaim's buildRunning), and a reaper that asked inside one of those moments would
// read a launcher that is not there and leave the build attached with no timer. So a busy lock is asked again,
// reapBuildTries times in all, lastOutRetry apart, as leaveBuild does, before the reaper concludes a launcher
// holds it.
func ReapBuild(t ReapTarget, cgroupMount string, now func() time.Time) error {
	if now == nil {
		now = time.Now
	}
	d, err := openState(t.BPFFS, t.StateDir)
	if err != nil {
		return fmt.Errorf("cgroup: the build's duties: %w", err)
	}
	f, busy, err := lockBuildExclusiveNB(d, t.Hash, false)
	for try := 1; err == nil && busy && try < reapBuildTries; try++ {
		reapBuildPause()
		f, busy, err = lockBuildExclusiveNB(d, t.Hash, false)
	}
	_ = d.Close()
	switch {
	case errors.Is(err, os.ErrNotExist):
		return nil // the build is gone, and its lock with it
	case err != nil:
		return fmt.Errorf("cgroup: the build's duties: %w", err)
	case busy:
		return nil // a launcher holds the build: it leaves last, and does this itself
	}
	l := &buildLock{path: f.Name(), f: f}
	err = l.touch(now())
	_ = l.Close()
	if err != nil {
		return err
	}
	if t.Linger <= 0 {
		if _, err := SweepBuilds(SweepOptions{BPFFS: t.BPFFS, StateDir: t.StateDir, CgroupMount: cgroupMount,
			Now: now}); err != nil {
			return fmt.Errorf("cgroup: remove the build its last run left: %w", err)
		}
		return nil
	}
	return startTimer(t)
}

// reapBuildTries is how many times ReapBuild asks for a busy build lock before it concludes a launcher holds it.
const reapBuildTries = 4

// reapBuildPause runs between those asks; a variable for the tests.
var reapBuildPause = func() { time.Sleep(lastOutRetry) }

// startTimer starts the build's timer from a reaper, which is tego; a variable for the tests.
var startTimer = func(t ReapTarget) error {
	return startTimerProcess("/proc/self/exe", t.Hash, t.Linger, t.BPFFS, t.StateDir)
}
