// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"encoding/binary"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// reapBuild makes a build's pin directory on a plain directory standing in for the bpf filesystem, with one
// host-wide link pin and run id's cgroup links pinned under links/run-<id> (ADR 0020 (1)), and the build's lock in
// state. It returns the run's link directory.
func reapBuild(t *testing.T, bpffs, state, hash, id string) string {
	t.Helper()
	p, err := newPinLayout(bpffs, hash)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(p.Links, "tego_cgroup_mkdir"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	dir := p.runLinks(id)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"tego_connect4", "tego_connect6"} {
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(state, "bpf-"+hash+".lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestARunsLinksAreNamedByItsID is ADR 0020 (1)'s layout: a run's cgroup links go under its build's
// links/run-<id>, and an id that is not one path component pins nothing rather than anywhere else.
func TestARunsLinksAreNamedByItsID(t *testing.T) {
	t.Parallel()
	p, err := newPinLayout("/sys/fs/bpf", "abc")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := p.runLinks("r1"), "/sys/fs/bpf/tego/abc/links/run-r1"; got != want {
		t.Errorf("runLinks(r1) = %q, want %q", got, want)
	}
	for _, bad := range []string{"", ".", "..", "a/b", "a\x00b"} {
		if got := p.runLinks(bad); got != "" {
			t.Errorf("runLinks(%q) = %q, want none", bad, got)
		}
	}
	if err := pinRunLink("", nil, "x"); err != nil {
		t.Errorf("pinRunLink with no directory: %v, want nothing pinned and no error", err)
	}
	if err := removeRunLinks(filepath.Join(t.TempDir(), "run-gone"), nil); err != nil {
		t.Errorf("removeRunLinks of a directory already gone: %v", err)
	}
}

// TestPurgeRunKeepsEverythingWhileTheRunsCgroupExists is ADR 0020 (3)'s order, fail-closed: while a cgroup of the
// run's id exists, PurgeRun removes nothing, since its links and rows are what enforce the run's processes; once
// it is gone, the run's link directory goes and nothing else of the build does, and a second pass finds nothing.
func TestPurgeRunKeepsEverythingWhileTheRunsCgroupExists(t *testing.T) {
	t.Parallel()
	bpffs, state, mount := t.TempDir(), t.TempDir(), t.TempDir()
	links := reapBuild(t, bpffs, state, "h1", "r1")
	scope := filepath.Join(mount, "tego.slice", "run-r1.scope")
	if err := os.MkdirAll(scope, 0o755); err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	if err := unix.Stat(scope, &st); err != nil {
		t.Fatal(err)
	}
	opts := PurgeOptions{BPFFS: bpffs, StateDir: state, CgroupMount: mount, Hash: "h1", RunID: "r1", CgroupID: st.Ino}

	res, err := PurgeRun(opts)
	if !errors.Is(err, ErrRunAlive) {
		t.Fatalf("PurgeRun with the run's cgroup alive: %+v, %v; want ErrRunAlive", res, err)
	}
	if _, err := os.Stat(links); err != nil {
		t.Fatalf("the live run's links were removed: %v", err)
	}

	if err := os.Remove(scope); err != nil {
		t.Fatal(err)
	}
	res, err = PurgeRun(opts)
	if err != nil {
		t.Fatalf("PurgeRun: %v", err)
	}
	if !res.Links {
		t.Error("PurgeRun reported no links removed")
	}
	if _, err := os.Stat(links); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the run's link directory is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h1", pinLinks, "tego_cgroup_mkdir")); err != nil {
		t.Errorf("the build's own link was removed with the run's: %v", err)
	}
	again, err := PurgeRun(opts)
	if err != nil || again.Links || len(again.Slots) != 0 || again.Rings != 0 {
		t.Errorf("a second PurgeRun: %+v, %v; want nothing done", again, err)
	}
}

// TestPurgeRunOfAGoneBuildDoesNothing: a build removed since took the run's pins with it.
func TestPurgeRunOfAGoneBuildDoesNothing(t *testing.T) {
	t.Parallel()
	res, err := PurgeRun(PurgeOptions{BPFFS: t.TempDir(), StateDir: t.TempDir(), CgroupMount: t.TempDir(),
		Hash: "gone", RunID: "r1", CgroupID: 1})
	if err != nil || res.Links {
		t.Fatalf("PurgeRun of a gone build: %+v, %v", res, err)
	}
	if _, err := PurgeRun(PurgeOptions{BPFFS: t.TempDir(), Hash: "a/b", RunID: "r1"}); err == nil {
		t.Error("PurgeRun accepted a hash that is not one path component")
	}
}

// TestPurgeRunRefusesADotHash: run_start's bpf_hash reaches a root sweep's PurgeRun from a ledger its owner
// writes; "." or ".." would make the pin root the tego base or the bpf filesystem itself, and ".." would remove a
// run-<id> directory under links/ outside the tego tree. Both are refused before anything is touched.
func TestPurgeRunRefusesADotHash(t *testing.T) {
	t.Parallel()
	for _, hash := range []string{".", ".."} {
		bpffs := t.TempDir()
		outside := filepath.Join(bpffs, "links", "run-r1")
		inside := filepath.Join(bpffs, pinRoot, "links", "run-r1")
		for _, dir := range []string{outside, inside} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		res, err := PurgeRun(PurgeOptions{BPFFS: bpffs, StateDir: t.TempDir(), CgroupMount: t.TempDir(),
			Hash: hash, RunID: "r1"})
		if !errors.Is(err, ErrProgramLoad) || res.Links {
			t.Errorf("PurgeRun(hash %q) = %+v, %v; want refused", hash, res, err)
		}
		for _, dir := range []string{outside, inside} {
			if _, err := os.Stat(dir); err != nil {
				t.Errorf("hash %q: %s was removed: %v", hash, dir, err)
			}
		}
	}
}

// TestABuildsRemovalTakesItsRunsLinks: a build is removed only once its run set names no live cgroup (ADR 0022
// (1)), and the link directories of runs that ended without a purge go with it; ListBuilds names them apart from
// the build's own links, which is how root sees them in `tego doctor`.
func TestABuildsRemovalTakesItsRunsLinks(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h2", "r2")
	builds, err := ListBuilds(SweepOptions{BPFFS: bpffs, StateDir: state}, nil)
	if err != nil || len(builds) != 1 {
		t.Fatalf("ListBuilds: %+v, %v", builds, err)
	}
	if b := builds[0]; b.Links != 1 || len(b.Runs) != 1 || b.Runs[0] != "r2" {
		t.Errorf("ListBuilds: links %d runs %v, want 1 link and run r2", b.Links, b.Runs)
	}
	p, err := newPinLayout(bpffs, "h2")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.remove(); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if _, err := os.Stat(p.Root); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("the build's directory is still there: %v", err)
	}
}

// TestAReaperLeavesABuildALauncherHolds is ADR 0022 (2)-(3) as a reaper does it: with a launcher of the build
// still holding its lock the reaper touches nothing, since that launcher leaves last and does the build's duties
// itself; with none, the reaper's run was the build's last, the lock's mtime becomes the start of its idle time,
// and at bpf.linger 0 the build is removed at once.
func TestAReaperLeavesABuildALauncherHolds(t *testing.T) {
	t.Parallel()
	bpffs, state, mount := t.TempDir(), t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h3", "r3")
	lock := filepath.Join(state, "bpf-h3.lock")
	then := time.Unix(1_600_000_000, 0)
	if err := os.Chtimes(lock, then, then); err != nil {
		t.Fatal(err)
	}
	held, err := os.Open(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_700_000_000, 0)
	target := ReapTarget{Hash: "h3", BPFFS: bpffs, StateDir: state}
	if err := ReapBuild(target, mount, func() time.Time { return now }); err != nil {
		t.Fatalf("ReapBuild with a launcher holding the build: %v", err)
	}
	var st unix.Stat_t
	if err := unix.Stat(lock, &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Mtim.Unix()); !got.Equal(then) {
		t.Errorf("the build lock's mtime moved to %v with a launcher holding it", got)
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h3")); err != nil {
		t.Fatalf("the build was removed under a launcher: %v", err)
	}
	// The launcher leaves: its lock is released before its descriptor is closed. A close alone releases a flock only
	// with the open file's last reference, and this test runs in parallel with tests that start processes: a child
	// forked while held was open shares it until its exec closes it, and a reaper that asked inside that moment read
	// a launcher still holding the build (0.03 s, once, under load).
	if err := unix.Flock(int(held.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	_ = held.Close()

	if err := ReapBuild(target, mount, func() time.Time { return now }); err != nil {
		t.Fatalf("ReapBuild as the last out: %v", err)
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h3")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("at bpf.linger 0 the build of the reaper's run, the last, stays: %v", err)
	}
}

// TestAReaperOutlastsAProbeOfTheBuildLock: a sweep, doctor's ListBuilds or a ring reclaim's buildRunning holds
// the build lock exclusively for a moment. A reaper that asks inside that moment must not read it as a launcher
// and leave the build its run left idle attached: it asks again, and at bpf.linger 0 removes the build.
func TestAReaperOutlastsAProbeOfTheBuildLock(t *testing.T) {
	bpffs, state, mount := t.TempDir(), t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h9", "r9")
	probe, err := os.Open(filepath.Join(state, "bpf-h9.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	pauses := 0
	saved := reapBuildPause
	reapBuildPause = func() {
		pauses++
		if err := unix.Flock(int(probe.Fd()), unix.LOCK_UN); err != nil {
			t.Error(err)
		}
	}
	t.Cleanup(func() { reapBuildPause = saved })
	if err := ReapBuild(ReapTarget{Hash: "h9", BPFFS: bpffs, StateDir: state}, mount, nil); err != nil {
		t.Fatalf("ReapBuild: %v", err)
	}
	if pauses == 0 {
		t.Errorf("the reaper never asked again after a probe held the build lock")
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h9")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("a probe's momentary hold left the build of the reaper's last run attached: %v", err)
	}
}

// TestAReaperStartsTheTimerOfTheBuildItsRunLeftIdle is ADR 0022 (3) from a reaper: with a linger, the reaper whose
// run was its build's last stamps the build's idle start and starts the build's timer, as the last launcher out
// does, and removes nothing itself.
func TestAReaperStartsTheTimerOfTheBuildItsRunLeftIdle(t *testing.T) {
	bpffs, state, mount := t.TempDir(), t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h4", "r4")
	var started []ReapTarget
	saved := startTimer
	startTimer = func(tg ReapTarget) error { started = append(started, tg); return nil }
	t.Cleanup(func() { startTimer = saved })
	now := time.Unix(1_700_000_000, 0)
	target := ReapTarget{Hash: "h4", BPFFS: bpffs, StateDir: state, Linger: time.Hour}
	if err := ReapBuild(target, mount, func() time.Time { return now }); err != nil {
		t.Fatalf("ReapBuild: %v", err)
	}
	if len(started) != 1 || started[0] != target {
		t.Fatalf("timers started: %+v, want one for %+v", started, target)
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(state, "bpf-h4.lock"), &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Mtim.Unix()); !got.Equal(now) {
		t.Errorf("the build lock's mtime is %v, want the reaper's %v", got, now)
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h4")); err != nil {
		t.Errorf("a lingering build was removed by the reaper: %v", err)
	}
}

// TestOneSlotsFailedPurgeLeavesTheOthersPurged: the slots a reaper claims are each a dead launcher's, and
// independent. A purge that fails on the first (a map delete that errs) still purges the rest, so their allow rows
// stop counting against every other run's row budget at once (ADR 0020 (3)); every slot is freed, and the
// failure is returned. Maps that did not load purge none, as before.
func TestOneSlotsFailedPurgeLeavesTheOthersPurged(t *testing.T) {
	t.Parallel()
	var purged, released []uint32
	purge := func(i uint32) error {
		purged = append(purged, i)
		if i == 3 {
			return errors.New("delete failed")
		}
		return nil
	}
	release := func(i uint32) error { released = append(released, i); return nil }
	freed, errs := purgeAndRelease([]uint32{3, 4, 5}, true, purge, release)
	if len(purged) != 3 {
		t.Errorf("purged %v, want 3, 4 and 5: slot 3's failure must not skip the others", purged)
	}
	if len(freed) != 3 || len(released) != 3 {
		t.Errorf("freed %v, released %v, want all three", freed, released)
	}
	if len(errs) != 1 {
		t.Errorf("errors %v, want slot 3's", errs)
	}
	purged, released = nil, nil
	freed, errs = purgeAndRelease([]uint32{3, 4}, false, purge, release)
	if len(purged) != 0 || len(freed) != 2 || len(errs) != 0 {
		t.Errorf("maps not loaded: purged %v, freed %v, errors %v, want none purged and both freed", purged, freed, errs)
	}
}

// These tests use actual held slot-table files. Only the second claim write is
// faulted; successful writes and every release use the production file methods.
func TestDeadSlotClaimFailureReleasesOwnWrites(t *testing.T) {
	for _, completesWrite := range []bool{false, true} {
		name := "before-second-write"
		if completesWrite {
			name = "after-second-write"
		}
		t.Run(name, func(t *testing.T) {
			st := deadClaimTable(t)
			fault := errors.New("injected second slot write failure")
			writes := 0
			claimed, err := claimDeadSlots(st, emptyCarried, func(f *os.File, idx int, rec []byte) error {
				writes++
				if idx == 1 {
					if completesWrite {
						if err := writeRecord(f, idx, rec); err != nil {
							return err
						}
					}
					return fault
				}
				return writeRecord(f, idx, rec)
			})
			if !errors.Is(err, fault) || len(claimed) != 0 || writes != 2 {
				t.Fatalf("failed claim: claimed=%v writes=%d error=%v", claimed, writes, err)
			}
			for _, idx := range []uint32{0, 1} {
				held, err := st.heldBy(idx)
				if err != nil || held {
					t.Errorf("slot %d remains held by live purger: held=%v error=%v", idx, held, err)
				}
			}
			idx, gen, err := st.acquireGen(nil)
			if err != nil || idx != 0 || gen != 8 {
				t.Errorf("next acquire=(%d,gen=%d,%v), want released slot 0 at preserved epoch 8", idx, gen, err)
			}
		})
	}
}

func TestDeadSlotClaimFailureKeepsReleaseError(t *testing.T) {
	st := deadClaimTable(t)
	fault := errors.New("injected second slot write failure")
	_, err := claimDeadSlots(st, emptyCarried, func(f *os.File, idx int, rec []byte) error {
		if idx == 1 {
			if err := st.dir.Unlink(st.name); err != nil {
				t.Fatal(err)
			}
			return fault
		}
		return writeRecord(f, idx, rec)
	})
	if !errors.Is(err, fault) || !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("claim and release errors must both survive: %v", err)
	}
}

func TestDeadSlotClaimDoesNotHideReaderOrWriterNotExist(t *testing.T) {
	for _, reader := range []bool{false, true} {
		name := "writer"
		if reader {
			name = "reader"
		}
		t.Run(name, func(t *testing.T) {
			st := deadClaimTable(t)
			read := emptyCarried
			write := writeRecord
			if reader {
				read = func() (map[uint32]bool, error) { return nil, os.ErrNotExist }
			} else {
				write = func(*os.File, int, []byte) error { return os.ErrNotExist }
			}
			_, err := claimDeadSlots(st, read, write)
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("callback not-exist failure was hidden (reader=%v): %v", reader, err)
			}
		})
	}
}

func TestDeadSlotClaimRollbackPreservesAnotherOwner(t *testing.T) {
	st := deadClaimTable(t)
	other := owner{PID: st.self.PID, StartTicks: st.self.StartTicks + 1}
	fault := errors.New("injected write failure after another owner appeared")
	_, err := claimDeadSlots(st, emptyCarried, func(f *os.File, idx int, rec []byte) error {
		if idx == 1 {
			binary.LittleEndian.PutUint32(rec[0:4], other.PID)
			binary.LittleEndian.PutUint64(rec[8:16], other.StartTicks)
			if err := writeRecord(f, idx, rec); err != nil {
				return err
			}
			return fault
		}
		return writeRecord(f, idx, rec)
	})
	if !errors.Is(err, fault) {
		t.Fatalf("write failure was lost: %v", err)
	}
	if err := st.withTable(func(_ *os.File, records []byte) error {
		rec := records[slotRecordSize : 2*slotRecordSize]
		got := owner{PID: binary.LittleEndian.Uint32(rec[0:4]), StartTicks: binary.LittleEndian.Uint64(rec[8:16])}
		if got != other || binary.LittleEndian.Uint32(rec[4:8])&slotFlagInUse == 0 {
			t.Errorf("rollback touched another owner: owner=%+v flags=%d", got, binary.LittleEndian.Uint32(rec[4:8]))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestDeadSlotClaimSuccessfulSelectionAndAbsentTable(t *testing.T) {
	st := deadClaimTable(t)
	claimed, err := claimDeadSlots(st, func() (map[uint32]bool, error) { return map[uint32]bool{1: true}, nil }, writeRecord)
	if err != nil || !slices.Equal(claimed, []uint32{0}) {
		t.Fatalf("successful selection=%v error=%v", claimed, err)
	}
	if held, err := st.heldBy(0); err != nil || !held {
		t.Fatalf("successful claim must remain held until map purge: held=%v error=%v", held, err)
	}
	if err := st.release(0); err != nil {
		t.Fatal(err)
	}
	if err := st.dir.Unlink(st.name); err != nil {
		t.Fatal(err)
	}
	called := false
	claimed, err = claimDeadSlots(st, func() (map[uint32]bool, error) { called = true; return nil, nil }, writeRecord)
	if err != nil || len(claimed) != 0 || called {
		t.Fatalf("absent build table changed: claimed=%v called=%v error=%v", claimed, called, err)
	}
}

func deadClaimTable(t *testing.T) *slotTable {
	t.Helper()
	st := newTestTable(t, t.TempDir(), nil)
	t.Cleanup(func() { _ = st.close() })
	dead := owner{PID: ^uint32(0), StartTicks: 1}
	if err := st.withTable(func(f *os.File, _ []byte) error {
		for i := 0; i < 2; i++ {
			rec := make([]byte, slotRecordSize)
			binary.LittleEndian.PutUint32(rec[0:4], dead.PID)
			binary.LittleEndian.PutUint32(rec[4:8], slotFlagInUse|7<<slotEpochShift)
			binary.LittleEndian.PutUint64(rec[8:16], dead.StartTicks)
			if err := writeRecord(f, i, rec); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	st.peek = true
	return st
}

func emptyCarried() (map[uint32]bool, error) { return nil, nil }
