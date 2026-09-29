// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestALastLauncherOutWithALingerLeavesTheBuild is ADR 0022 (2): with a linger the last launcher out removes
// nothing, stamps the build lock's mtime as the start of the build's idle time, and starts the build's timer
// once it has let the lock go, so the next run within the linger adopts the build instead of loading it again.
func TestALastLauncherOutWithALingerLeavesTheBuild(t *testing.T) {
	t.Parallel()
	var timers []string
	now := time.Unix(1_700_000_000, 0)
	f := newFixture(t, func(o *Options) {
		o.Machine = machineLinger(time.Hour)
		o.Now = func() time.Time { return now }
		o.startTimer = func(hash string) error { timers = append(timers, hash); return nil }
	})
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Attach(f.run.CgroupID); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	if f.kernel.unpinned {
		t.Fatal("the last launcher out removed a build that should linger")
	}
	if len(timers) != 0 {
		t.Fatalf("a timer started while the launcher still held the build lock: %v", timers)
	}
	var st unix.Stat_t
	if err := unix.Stat(filepath.Join(f.dir, "bpf-testhash.lock"), &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Mtim.Unix()); !got.Equal(now) {
		t.Errorf("the build lock's mtime is %v, want the departure time %v", got, now)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(timers) != 1 || timers[0] != "testhash" {
		t.Fatalf("timers started: %v, want one for testhash", timers)
	}
}

// TestALastLauncherOutKeepsABuildARunStillNeeds is ADR 0022 (1) at bpf.linger 0: the last launcher out removes
// the build only when its run set names no live cgroup. An orphaned run, whose launcher died, still runs under
// the build's record and decisions, and removing them under it was the fail-open the ADR closes.
func TestALastLauncherOutKeepsABuildARunStillNeeds(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	f.kernel.live = true
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f.kernel.unpinned {
		t.Fatal("the build was removed while a run it enforces was alive")
	}
}

// TestSweepBuildsRemovesOnlyIdleUnheldBuilds is ADR 0022 (4) on plain directories standing in for the bpf
// filesystem (a build without a run set has no run to keep it): a build idle past the linger goes, one idle for
// less stays, one a launcher holds stays, and beyond two lingering builds the ones idle longest go.
func TestSweepBuildsRemovesOnlyIdleUnheldBuilds(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	build := func(hash string, idle time.Duration) {
		t.Helper()
		p, err := newPinLayout(bpffs, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.create(); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(p.Links, "prog"), nil, 0o600); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(state, "bpf-"+hash+".lock")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-idle)
		if err := os.Chtimes(lock, at, at); err != nil {
			t.Fatal(err)
		}
	}
	build("old", 2*time.Hour)
	build("new1", time.Minute)
	build("new2", 2*time.Minute)
	build("new3", 3*time.Minute)
	build("held", 3*time.Hour)
	held, err := os.Open(filepath.Join(state, "bpf-held.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}

	states, err := SweepBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, CgroupMount: t.TempDir(), Linger: time.Hour,
		Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("SweepBuilds: %v", err)
	}
	got := map[string]BuildState{}
	for _, s := range states {
		got[s.Hash] = s
	}
	want := map[string]bool{"old": true, "new1": false, "new2": false, "new3": true, "held": false}
	for hash, removed := range want {
		s, ok := got[hash]
		if !ok {
			t.Errorf("%s: not reported", hash)
			continue
		}
		if s.Removed != removed {
			t.Errorf("%s: removed %v (%s), want %v", hash, s.Removed, s.Why, removed)
		}
		_, statErr := os.Stat(filepath.Join(bpffs, pinRoot, hash))
		if gone := os.IsNotExist(statErr); gone != removed {
			t.Errorf("%s: pin directory gone %v, want %v", hash, gone, removed)
		}
	}
	if got["held"].Why != whyBusy {
		t.Errorf("held: kept because %q, want %q", got["held"].Why, whyBusy)
	}

	states, err = SweepBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, CgroupMount: t.TempDir(), Linger: time.Hour,
		Force: true, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatalf("SweepBuilds --builds: %v", err)
	}
	for _, s := range states {
		if s.Removed == (s.Hash == "held") {
			t.Errorf("gc --builds: %s removed %v (%s)", s.Hash, s.Removed, s.Why)
		}
	}
}

// TestASweepThatKeepsALiveBuildLooksAgainOnlyALingerLater: a build kept because a run it enforces is alive (an
// orphan its reaper could not end) had its run set checked, a walk of the whole cgroup tree, by every later sweep,
// each Prepare's on a run's start path among them, for as long as the run lived. The sweep now stamps the build
// lock: the build is not idle, and the next sweep looks again only once a linger has passed.
func TestASweepThatKeepsALiveBuildLooksAgainOnlyALingerLater(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	now := time.Unix(1_700_000_000, 0)
	p, err := newPinLayout(bpffs, "orphaned")
	if err != nil {
		t.Fatal(err)
	}
	if err := p.create(); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(state, "bpf-orphaned.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	at := now.Add(-2 * time.Hour)
	if err := os.Chtimes(lock, at, at); err != nil {
		t.Fatal(err)
	}
	checks := 0
	sweep := func() BuildState {
		t.Helper()
		states, err := SweepBuilds(SweepOptions{BPFFS: bpffs, StateDir: state, CgroupMount: t.TempDir(),
			Linger: time.Hour, Now: func() time.Time { return now },
			runSetLive: func(string, string) (bool, error) { checks++; return true, nil }})
		if err != nil || len(states) != 1 {
			t.Fatalf("SweepBuilds: %+v, %v", states, err)
		}
		return states[0]
	}
	if s := sweep(); s.Removed || s.Why != whyLive || checks != 1 {
		t.Fatalf("first sweep: removed %v (%s), %d run-set checks", s.Removed, s.Why, checks)
	}
	var st unix.Stat_t
	if err := unix.Stat(lock, &st); err != nil {
		t.Fatal(err)
	}
	if got := time.Unix(st.Mtim.Unix()); !got.Equal(now) {
		t.Errorf("the build lock's mtime is %v, want the sweep's now %v", got, now)
	}
	now = now.Add(time.Minute)
	if s := sweep(); s.Removed || s.Why != whyLingering || checks != 1 {
		t.Fatalf("a sweep a minute later: removed %v (%s), %d run-set checks, want 1", s.Removed, s.Why, checks)
	}
	now = now.Add(time.Hour)
	if s := sweep(); s.Removed || s.Why != whyLive || checks != 2 {
		t.Fatalf("a sweep a linger later: removed %v (%s), %d run-set checks, want 2", s.Removed, s.Why, checks)
	}
}

// liveTimerPid is the pid prepareTimerFixture's Prepare reads as a live timer of whichever build's timer file names it.
const liveTimerPid = 4242

// prepareTimerFixture is a fixture with bpf.linger at linger whose timer starts are recorded in started and fail with
// startErr, and plant, which makes another build's pins and its lock, idle for idle, and returns its pin directory.
func prepareTimerFixture(t *testing.T, linger time.Duration, now time.Time, started *[]string, startErr error) (*fixture, func(string, time.Duration) string) {
	t.Helper()
	f := newFixture(t, func(o *Options) {
		o.Machine = machineLinger(linger)
		o.Now = func() time.Time { return now }
		o.startTimer = func(hash string) error {
			*started = append(*started, hash)
			return startErr
		}
		o.timerProcess = func(pid int, _ string) bool { return pid == liveTimerPid }
	})
	plant := func(hash string, idle time.Duration) string {
		t.Helper()
		p, err := newPinLayout(f.dir, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.create(); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(f.dir, "bpf-"+hash+".lock")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-idle)
		if err := os.Chtimes(lock, at, at); err != nil {
			t.Fatal(err)
		}
		return p.Root
	}
	return f, plant
}

// TestPrepareRearmsTheTimerOfABuildWhoseTimerDied is ADR 0022 (4) as its 2026-10-06 note restores it: a build's timer
// can be killed (with its launcher's cgroup, by an operator, by the OOM killer), and Prepare makes up for it once it
// holds its own build's lock. It no longer removes the build itself, which put 2.8 to 3.7 s on the run's start on
// 6.1 and 5.14, where an unpin detaches synchronously: it starts that build's timer again, once, and leaves the pins
// to it; a build still inside its linger, and the run's own, it leaves alone.
func TestPrepareRearmsTheTimerOfABuildWhoseTimerDied(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var started []string
	f, plant := prepareTimerFixture(t, time.Hour, now, &started, nil)
	expired, lingering := plant("expired", 2*time.Hour), plant("lingering", time.Minute)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	if len(started) != 1 || started[0] != "expired" {
		t.Errorf("timers Prepare started: %v, want one, the expired build's", started)
	}
	if _, err := os.Stat(expired); err != nil {
		t.Errorf("Prepare removed the expired build itself, on the run's start path: %v", err)
	}
	if _, err := os.Stat(lingering); err != nil {
		t.Errorf("a build inside its linger was removed: %v", err)
	}
}

// TestPrepareLeavesAnExpiredBuildToItsLiveTimer is ADR 0022 (4) and the plan's D3: a timer sleeps a second past its
// build's deadline, so for that second every other build's Prepare found the build expired and removed it on its own
// start path, though no helper had died. A build whose timer lives gets no second timer and keeps its pins. Liveness
// is read from the pid the timer wrote into its timer file (note 2026-10-16), never by taking the lock (a probe that
// took the timer lock for a moment would make a timer starting in that moment exit, as a probe of the build lock did
// to a last launcher out), and not from the kernel's lock table, whose read waits for an RCU grace
// period on the run's start path. A build a launcher holds that shows no timer gets one, which waits for its launcher;
// neither build is removed.
func TestPrepareLeavesAnExpiredBuildToItsLiveTimer(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var started []string
	f, plant := prepareTimerFixture(t, time.Hour, now, &started, nil)
	timed, held := plant("timed", 2*time.Hour), plant("held", 2*time.Hour)
	if err := os.WriteFile(filepath.Join(f.dir, "bpf-timed.timer"), []byte(strconv.Itoa(liveTimerPid)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	launcher, err := os.Open(filepath.Join(f.dir, "bpf-held.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	if err := unix.Flock(int(launcher.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	if !slices.Equal(started, []string{"held"}) {
		t.Errorf("timers Prepare started: %v, want only the held build's, which shows none", started)
	}
	for _, root := range []string{timed, held} {
		if _, err := os.Stat(root); err != nil {
			t.Errorf("Prepare removed %s: %v", filepath.Base(root), err)
		}
	}
}

// TestPrepareRemovesAnExpiredBuildWhoseTimerCannotStart: a Prepare that cannot start the timer (its exec failed, or
// the process is a test binary with no stage binary to exec) removes the expired build itself, as before the re-arm,
// rather than leave its programs attached host-wide until a gc. A build inside its linger stays.
func TestPrepareRemovesAnExpiredBuildWhoseTimerCannotStart(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var started []string
	f, plant := prepareTimerFixture(t, time.Hour, now, &started, errors.New("exec: no tego"))
	expired, lingering := plant("expired", 2*time.Hour), plant("lingering", time.Minute)
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	if len(started) != 1 || started[0] != "expired" {
		t.Errorf("timers Prepare tried: %v, want one, the expired build's", started)
	}
	if _, err := os.Stat(expired); !os.IsNotExist(err) {
		t.Errorf("a build idle past bpf.linger whose timer could not start is still pinned after Prepare: %v", err)
	}
	if _, err := os.Stat(lingering); err != nil {
		t.Errorf("a build inside its linger was removed: %v", err)
	}
}

// TestPrepareAtLingerZeroStartsNoTimer: a bpf.linger of 0 keeps the old rule (ADR 0022: the last launcher out removes
// the build itself), so no timer ever runs at it, and Prepare's pass starts none either. It
// had given every other build in use one, since its pass reads no lock table and every build is past a linger of 0:
// each such timer took its build's lock every second for as long as the build's runs lasted. A build a launcher holds
// is left to that launcher; one no launcher holds is removed, as the sweep before the re-arm removed it.
func TestPrepareAtLingerZeroStartsNoTimer(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	var started []string
	f, plant := prepareTimerFixture(t, 0, now, &started, nil)
	held, dead := plant("held", time.Minute), plant("dead", time.Minute)
	launcher, err := os.Open(filepath.Join(f.dir, "bpf-held.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer launcher.Close()
	if err := unix.Flock(int(launcher.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	if len(started) != 0 {
		t.Errorf("Prepare at a linger of 0 started the timers of %v", started)
	}
	if _, err := os.Stat(held); err != nil {
		t.Errorf("the build a launcher holds was removed: %v", err)
	}
	if _, err := os.Stat(dead); !os.IsNotExist(err) {
		t.Errorf("the build no launcher holds is still pinned after Prepare: %v", err)
	}
}

// TestPrepareLeavesBuildsInsideTheirLingerAlone is ADR 0022 (4) on a launcher's path: Prepare's sweep removes only
// a build idle past the linger, never one inside it, so three lingering builds (one past the cap) all stay; the cap
// is the timer's, the reaper's and gc's, and a removal on a run's start path costs seconds of ftrace locks on 6.1.
func TestPrepareLeavesBuildsInsideTheirLingerAlone(t *testing.T) {
	t.Parallel()
	now := time.Unix(1_700_000_000, 0)
	f := newFixture(t, func(o *Options) {
		o.Machine = machineLinger(time.Hour)
		o.Now = func() time.Time { return now }
		o.startTimer = func(string) error { return nil }
	})
	var roots []string
	for i, hash := range []string{"idle3m", "idle2m", "idle1m"} {
		p, err := newPinLayout(f.dir, hash)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.create(); err != nil {
			t.Fatal(err)
		}
		lock := filepath.Join(f.dir, "bpf-"+hash+".lock")
		if err := os.WriteFile(lock, nil, 0o600); err != nil {
			t.Fatal(err)
		}
		at := now.Add(-time.Duration(3-i) * time.Minute)
		if err := os.Chtimes(lock, at, at); err != nil {
			t.Fatal(err)
		}
		roots = append(roots, p.Root)
	}
	h, err := f.backend.Prepare(context.Background(), f.table, f.run)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	defer func() { _ = h.Close() }()
	for _, root := range roots {
		if _, err := os.Stat(root); err != nil {
			t.Errorf("Prepare removed %s, a build inside its linger: %v", filepath.Base(root), err)
		}
	}
}

// walkingRunSet is a run-set map in key order whose onNext runs as each NextKey starts, so a test can make a cgroup
// and insert its row while runSetLiveIn walks the keys, as a live run of the build can.
type walkingRunSet struct {
	keys    []uint64
	deleted []uint64
	onNext  func(calls int)
	calls   int
}

func (m *walkingRunSet) MaxEntries() uint32 { return 64 }

func (m *walkingRunSet) NextKey(key, next any) error {
	m.calls++
	if m.onNext != nil {
		m.onNext(m.calls)
	}
	i := 0
	if k, ok := key.(*uint64); ok && k != nil {
		i = -1
		for j, v := range m.keys {
			if v == *k {
				i = j + 1
			}
		}
		if i < 0 {
			i = 0
		}
	}
	if i >= len(m.keys) {
		return ebpf.ErrKeyNotExist
	}
	*next.(*uint64) = m.keys[i]
	return nil
}

func (m *walkingRunSet) Delete(key any) error {
	id := *key.(*uint64)
	for j, v := range m.keys {
		if v == id {
			m.keys = append(m.keys[:j], m.keys[j+1:]...)
			m.deleted = append(m.deleted, id)
			return nil
		}
	}
	return ebpf.ErrKeyNotExist
}

func dirIno(t *testing.T, dir string) uint64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		t.Fatal(err)
	}
	return st.Ino
}

// TestRunSetLiveKeepsARowWhoseCgroupIsNotVisibleYet is cgroup_track's order for a descendant: its row goes in at
// tp_btf/cgroup_mkdir, before kernfs_activate() shows the directory, so the first listing after the key walk can
// miss a cgroup whose row is there. The row is kept: the id is deleted only when a second listing, taken after
// the directory appeared, misses it too. The directory appears right after the first listing of the mount
// (cgroupIDs, as runSetLiveIn lists it) returns, and the scrub must wait runSetSettle before the second, as
// runSetLiveIn does: the test holds the gap between the two listings to at least that, a bound a busy machine can
// only lengthen, so a scrub that lists again at once fails it (with the wait removed it did, 2026-10-17). The
// activation used to be a goroutine that slept 5 ms after the key walk, which had to run within the 50 ms settle: in
// a 4-vCPU KVM guest with four busy loops a CPU it once did not, and the test failed for the machine's sake (one run
// of 28 of the package, 2026-10-17; with the goroutine woken 60 ms late it fails every run).
func TestRunSetLiveKeepsARowWhoseCgroupIsNotVisibleYet(t *testing.T) {
	t.Parallel()
	mount := t.TempDir()
	parked := t.TempDir() // the new cgroup, made but not yet in the mount's listing
	fresh := filepath.Join(parked, "fresh")
	if err := os.Mkdir(fresh, 0o755); err != nil {
		t.Fatal(err)
	}
	newID := dirIno(t, fresh)
	m := &walkingRunSet{keys: []uint64{newID}}
	listings := 0
	var firstDone, secondStart time.Time
	list := func() (map[uint64]bool, error) {
		listings++
		if listings == 2 {
			secondStart = time.Now()
		}
		ids, err := cgroupIDs(mount)
		if listings == 1 {
			defer func() { firstDone = time.Now() }()
			if ids[newID] {
				t.Errorf("the first listing saw cgroup %d before its directory was activated", newID)
			}
			// The activation, just after the first listing.
			if err := os.Rename(fresh, filepath.Join(mount, "fresh")); err != nil {
				t.Error(err)
			}
		}
		return ids, err
	}
	live, err := scrubRunSet(m, list, runSetSettle)
	if err != nil {
		t.Fatal(err)
	}
	if listings != 2 {
		t.Fatalf("%d listings of the mount, want 2: a cgroup missing from the first must be listed again", listings)
	}
	if gap := secondStart.Sub(firstDone); gap < runSetSettle {
		t.Errorf("the second listing began %v after the first returned: want at least runSetSettle (%v), the time a "+
			"mkdir in flight during the first has to activate its directory", gap, runSetSettle)
	}
	if len(m.deleted) != 0 {
		t.Fatalf("deleted %v: the row of a cgroup being made was dropped", m.deleted)
	}
	if !live {
		t.Fatal("runSetLiveIn reported no live cgroup")
	}
}

// TestRunSetLiveKeepsARowWhoseCgroupWasMadeDuringTheWalk is the run-set scrub's ordering: a live run that makes a
// cgroup and inserts its row while PurgeRun (no build lock) walks the keys keeps that row. Only the row of a
// cgroup that is really gone is deleted. It calls runSetLiveIn, the wrapper PurgeRun's runSetLive runs, with a key
// missing from the first listing, so the scrub lists the cgroups again before it deletes that row: the call must
// take at least runSetSettle, the wait the wrapper passes, a bound a busy machine can only lengthen. With the
// wrapper passing 0 the test failed every run (2026-10-17). TestRunSetLiveKeepsARowWhoseCgroupIsNotVisibleYet
// checks that scrubRunSet waits the settle it is given between the two listings.
func TestRunSetLiveKeepsARowWhoseCgroupWasMadeDuringTheWalk(t *testing.T) {
	t.Parallel()
	mount := t.TempDir()
	old := filepath.Join(mount, "old")
	if err := os.Mkdir(old, 0o755); err != nil {
		t.Fatal(err)
	}
	oldID, goneID := dirIno(t, old), uint64(1)<<62 // no directory has that inode
	m := &walkingRunSet{keys: []uint64{oldID, goneID}}
	var newID uint64
	m.onNext = func(calls int) {
		if calls != 2 { // after the first key was read
			return
		}
		fresh := filepath.Join(mount, "fresh")
		if err := os.Mkdir(fresh, 0o755); err != nil {
			t.Error(err)
			return
		}
		newID = dirIno(t, fresh)
		m.keys = append(m.keys, newID) // the row goes in after its cgroup exists
	}
	start := time.Now()
	live, err := runSetLiveIn(m, mount)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if !live {
		t.Fatal("runSetLiveIn reported no live cgroup")
	}
	if took < runSetSettle {
		t.Errorf("runSetLiveIn returned %v after it began, having deleted the row of a cgroup missing from its first "+
			"listing: want at least runSetSettle (%v), the wait before the second listing that confirms it is gone",
			took, runSetSettle)
	}
	if len(m.deleted) != 1 || m.deleted[0] != goneID {
		t.Fatalf("deleted %v, want only the vanished cgroup %d (kept %d made during the walk)", m.deleted, goneID, newID)
	}
}

// TestRunSetScrubWalkIsBoundedUnderChurn: the scrub runs without the build lock while cgroup_rmdir and other
// launchers' Detach delete rows, and a deleted cursor key restarts the kernel's walk at the first key. Its own
// NextKey loop had no bound, so a stream of rmdirs kept it walking; it reads the keys with mapKeys, which fails
// after walkStepsPerEntry steps per entry, and then deletes nothing and lists no cgroup.
func TestRunSetScrubWalkIsBoundedUnderChurn(t *testing.T) {
	t.Parallel()
	const churnFor = 10_000 // the churn stops at last, so an unbounded walk ends and the test can fail
	m := &churnMap[uint64]{keys: []uint64{1, 2, 3, 4}, max: 8}
	m.afterNext = func(m *churnMap[uint64], handed uint64) {
		if m.steps >= churnFor {
			return
		}
		// The cursor's cgroup is removed and another is made: its row goes, a new row is added at the end.
		m.keys = append(m.keys[1:], handed+1000)
	}
	listed := false
	_, err := scrubRunSet(m, func() (map[uint64]bool, error) { listed = true; return map[uint64]bool{}, nil }, 0)
	if limit := walkStepsPerEntry * (int(m.max) + 1); m.steps > limit {
		t.Fatalf("the key walk took %d steps under churn, past the %d mapKeys allows", m.steps, limit)
	}
	if err == nil {
		t.Error("a walk that could not finish returned no error")
	}
	if listed || len(m.deleted) != 0 {
		t.Errorf("listed %v, deleted %v: a partial key list was scrubbed", listed, m.deleted)
	}
}
