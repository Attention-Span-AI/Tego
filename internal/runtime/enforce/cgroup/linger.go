// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/platform/startphase"
	rcgroup "github.com/attention-span-ai/tego/internal/runtime/cgroup"
	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// Build lifetime (ADR 0022). A build's pinned programs, maps and host-wide links are not removed by the last
// launcher out. They linger for the machine's bpf.linger after its last run ended, so a run that starts within
// it adopts them (adoptObject, attachShared) and pays no load, verify, attach or detach. Removal is off every
// run's path: a timer process the last launcher out starts (LingerCommand), and `tego gc`, remove a build once
// all three of these hold, and only then:
//
//   - its build lock can be taken exclusively, so no launcher of it is running or preparing;
//   - its run set holds no row for a cgroup that exists, so no run it enforces, one whose launcher died
//     included, loses the record or the decisions it runs under (rows of vanished cgroups are deleted first);
//   - it has been idle for bpf.linger: the build lock's mtime, which the last launcher out sets, is that long
//     ago (gc --builds skips this one).
//
// At most maxLingering builds linger per host; a sweep removes the ones idle longest beyond that, so two builds
// used alternately do not thrash and an upgrade's old build does not stay. A bpf.linger of 0 keeps the old
// rule: the last launcher out removes the build itself, under the same run-set condition.
//
// What it saves was measured in the KVM guest on 6.17 (test/vm/README.md, kill test 4): a root run of `true` at
// tier cgroup under kill test 4's kind of contract took 1.1 s with the build loaded, attached and detached per
// run, and 45 ms with the build adopted.

// LingerCommand is the hidden first argument cmd/tego dispatches to LingerMain: the build's timer.
const LingerCommand = "__bpf-linger"

// maxLingering is how many idle builds a sweep leaves attached (ADR 0022 (4)).
const maxLingering = 2

// linger is the machine's bpf.linger. A backend built without a machine config (this package's tests) removes
// its build at last out, as before ADR 0022.
func (o Options) linger() time.Duration {
	if o.Machine == nil || o.Machine.BPF.Linger.Value < 0 {
		return 0
	}
	return o.Machine.BPF.Linger.Value
}

// leaveBuild is what a departing launcher does to the build's pins, from Detach and from a failed Prepare's
// release: nothing unless it is the last launcher out; then, with a linger, it stamps the build lock's mtime
// as the start of the idle time and leaves the pins for the timer Close starts; with none, it removes them,
// unless a run the build enforces is still alive (an orphan whose launcher died): that build stays until the
// orphan is swept and a later sweep finds its run set empty.
//
// The build lock is also taken exclusively, for a moment, by probes of other processes: a sweep of the build
// (every other build's Prepare runs one), a ring reclaim's buildRunning, a reaper's ReapBuild. A last launcher out
// that asks inside one of those moments reads itself not last. So, with a linger, it stamps the idle start before
// it asks, which is harmless when another launcher is still running (that one stamps it again when it leaves): a
// stamp left hours old made the next sweep remove at once a build whose last run had just ended. And it asks once
// more, lastOutRetry later, before it concludes it is not last and starts no timer.
func (h *Handle) leaveBuild(k kernel) error {
	if h.lock == nil || k == nil {
		return nil
	}
	var stamped error
	if h.opts.linger() > 0 {
		stamped = h.lock.touch(h.opts.Now())
	}
	last, err := h.lock.lastOut()
	if err == nil && !last {
		if h.opts.lastOutPause != nil {
			h.opts.lastOutPause()
		} else {
			time.Sleep(lastOutRetry)
		}
		last, err = h.lock.lastOut()
	}
	if err != nil || !last {
		return err
	}
	if h.opts.linger() > 0 {
		h.lingering = true
		return stamped
	}
	live, err := k.runSetLive(h.run.mount())
	if err != nil {
		return fmt.Errorf("cgroup: the build is kept: its run set cannot be read: %w", err)
	}
	if live {
		return nil
	}
	return k.unpin()
}

// lastOutRetry is how long leaveBuild waits before it asks lastOut again: longer than a probe holds the lock
// (a stat and a run-set read), and short enough that a launcher that is not last pays little for it.
const lastOutRetry = 5 * time.Millisecond

// startTimer starts the build's timer once this launcher, the last out, has let the build lock go. It execs
// the child stage's binary, which is this tego, as LingerCommand in a session of its own with its standard
// streams on /dev/null, and does not wait for it: the timer outlives the launcher. It starts it in tego's
// helper cgroup (internal/runtime/cgroup.StartHelper), not the launcher's, so stopping the unit, the CI job or
// the scope the launcher ran in does not kill it; one that cannot be put there starts in the launcher's cgroup
// with the reason in its environment, and a timer killed all the same is started again by the next run's
// Prepare (rearmExpired) or a `tego stop`, or its build is removed by doctor or gc. A timer already running for
// the build keeps the timer lock, and the new one exits at once. A timer that cannot start leaves the build to
// those as well, which the error says.
func (h *Handle) startTimer() error {
	if err := h.startTimerFor(h.hash); !errors.Is(err, errNoTimer) {
		return err
	}
	return nil
}

// errNoTimer says no timer is started, which is no failure: startTimerFor's answer in a process that has no tego
// binary to start one with, and Prepare's pass's at a bpf.linger of 0, where no build has a timer (rearmExpired). A
// re-arm pass given it removes the build itself, as its timer would have.
var errNoTimer = errors.New("cgroup: no timer to start")

// startTimerFor starts build hash's timer from this launcher: its own build's at last out (startTimer), another
// build's whose timer died (rearmExpired). A run that names no stage binary execs its own image, which is then
// tego, as the child stage is: a process that is not tego (a test binary) cannot be a run's stage, so it names
// the tego binary it uses, and one that names none starts no timer (errNoTimer).
func (h *Handle) startTimerFor(hash string) error {
	if h.opts.startTimer != nil {
		return h.opts.startTimer(hash)
	}
	exe, err := timerExe(h.run.StageExe)
	if err != nil {
		return err
	}
	return startTimerProcess(exe, hash, h.opts.linger(), h.opts.BPFFS, h.opts.StateDir)
}

// selfExe names this process's own image as a timer's binary.
const selfExe = "/proc/self/exe"

// timerExe is the binary a timer is started with: exe, or this process's own image when exe is empty or names it.
// Its own image is tego in every process but a Go test binary, which is never tego: re-executed with LingerCommand
// it would run its whole suite, detached (as root in the KVM guest), so it starts no timer (errNoTimer).
func timerExe(exe string) (string, error) {
	if exe != "" && exe != selfExe {
		return exe, nil
	}
	if self, err := os.Executable(); err == nil && strings.HasSuffix(self, ".test") {
		return "", errNoTimer
	}
	return selfExe, nil
}

// startTimerProcess execs exe as build hash's timer (LingerCommand) in tego's helper cgroup, in a session of its
// own, and does not wait for it: the last launcher out's startTimer, Prepare's re-arm pass (rearmExpired), a reaper
// whose run was its build's last (ReapBuild) and `tego stop` (RearmTimers). None runs while this process holds a
// mark (internal/platform/proc's start-site table).
func startTimerProcess(exe, hash string, linger time.Duration, bpffs, state string) error {
	if state == "" {
		state = hoststate.Path
	}
	if bpffs == "" {
		bpffs = DefaultBPFFS
	}
	err := startHelperProcess(exe, LingerCommand, hash, linger.String(), bpffs, state)
	if err != nil {
		return fmt.Errorf("cgroup: start the build's linger timer: %w", err)
	}
	return nil
}

// startHelperProcess starts exe with args as one of tego's detached helpers (rcgroup.StartHelperExec): in
// tego's helper cgroup, so stopping the unit, the CI job or the scope the launcher ran in does not kill it, and
// in the launcher's cgroup, with the reason in its environment, when it cannot be put there. A variable, so a test
// sees what would be started.
var startHelperProcess = func(exe string, args ...string) error {
	_, err := rcgroup.StartHelperExec(exe, args...)
	return err
}

// rearmExpired is Prepare's pass over the other builds on the host, once this launcher holds its own build's lock
// (ADR 0022 (4), note 2026-10-06). A timer is a process, and a process can be killed: with its launcher's cgroup
// before it had a cgroup of its own, by an operator, by an OOM kill; without this its build stayed loaded, its
// programs attached host-wide, until someone ran gc. A build idle past bpf.linger whose timer it does not show
// running gets its timer started again, and the timer removes it, off this run's path: removing it
// here cost the run's start 2.8 to 3.7 s on 6.1 and 5.14, where an unpin detaches synchronously, and for the second
// of slack a live timer sleeps past the deadline, the removal ran here though no helper had died. Only a build
// whose timer cannot be started is removed here, as the timer would have. A build still inside its linger is left
// alone, the lingering cap included (ExpiredOnly): that is the timer's, the reaper's, stop's and gc's. Best effort.
//
// It reads a timer's liveness from the pid in its timer file only (timerRunning), never the kernel's lock table:
// that read waits for an RCU grace period, and so does every flock on the host while it lasts (note 2026-10-16). A
// build a launcher holds is therefore not told from one whose launchers are gone: one with no timer shown gets one,
// which waits for its launcher as a timer does (runTimer) and is shown alive to the next Prepare.
//
// A bpf.linger of 0 keeps the old rule, under which no build has a timer: the pass starts none (errNoTimer) and
// removes each build that no launcher holds itself (sweepBuild, which skips a held one), as the sweep before the
// re-arm did (note 2026-10-17). A timer there would find every build in use busy, every build being past a linger of
// 0, and take its lock every second for as long as its runs last.
func (h *Handle) rearmExpired() {
	defer startphase.Begin(h.opts.Phase, "prepare.rearm")()
	linger := h.opts.linger()
	_, _ = rearmTimers(SweepOptions{BPFFS: h.opts.BPFFS, StateDir: h.opts.StateDir, CgroupMount: h.run.mount(),
		Linger: linger, Now: h.opts.Now, ExpiredOnly: true, timerProcess: h.opts.timerProcess}, h.hash, nil,
		func(hash string) error {
			if linger == 0 {
				return errNoTimer
			}
			defer startphase.Begin(h.opts.Phase, "prepare.rearm.start")()
			return h.startTimerFor(hash)
		})
}

// RearmTimers is `tego stop`'s pass over the builds (ADR 0022 (4), (8)): every build that no launcher holds and
// whose timer is not running gets one, exe (a tego binary) run as LingerCommand in tego's helper cgroup, which
// removes it at its deadline and applies the lingering cap; with opts.ExpiredOnly only builds idle past the linger
// do. A build inside its linger is re-armed too otherwise: (8) bounds its stay only while its timer lives. A build
// whose timer cannot be started is swept as the timer would (sweepBuild), so a build past its linger still goes.
// Stop's own latency stays an exec per timerless build, not a removal's 1.7 to 3.7 s of ftrace locks. A build its
// timer file shows no live timer for is looked up in the kernel's lock table as well, read at most twice
// (lockHolders), so a build a launcher holds, or whose timer is an older tego's that wrote no pid, gets none. It
// needs root: the pins and the state directory are root's. An exe that is this process's own image starts no timer
// in a Go test binary (timerExe), and the pass sweeps instead.
func RearmTimers(opts SweepOptions, exe string) ([]BuildState, error) {
	table := procLocksTable
	if opts.lockTable != nil {
		table = opts.lockTable
	}
	return rearmTimers(opts, "", table, func(hash string) error {
		bin, err := timerExe(exe)
		if err != nil {
			return err
		}
		return startTimerProcess(bin, hash, max(opts.Linger, 0), opts.BPFFS, opts.StateDir)
	})
}

// rearmTimers starts, with start, the timer of every build but own (and of every build gone with its plane
// directories left, which the timer's sweep removes) whose timer is not running, idle past opts.Linger when
// opts.ExpiredOnly. Neither lock is taken (proclocks.go): a timer runs when its timer file names a live timer process
// (timerRunning); for a build that shows none, a table, when given, reads the kernel's lock table, at most twice
// (lockHolders: once, and again when the first read shows a build no holder), and a build whose lock a launcher holds
// or whose timer lock is held gets no timer. A table that cannot be read shows no holder. A timer started beside a
// live one exits on the timer lock. A build whose timer start fails is swept here.
func rearmTimers(opts SweepOptions, own string, table func(first int) ([]byte, error), start func(hash string) error) ([]BuildState, error) {
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	if opts.CgroupMount == "" {
		opts.CgroupMount = identity.SystemCgroupRoot
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	opts.Linger = max(opts.Linger, 0)
	if _, err := lockRootOf(opts.BPFFS, opts.StateDir); err != nil {
		return nil, err
	}
	base := filepath.Join(opts.BPFFS, pinRoot)
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: list builds under %s: %w", base, err)
	}
	d, err := openState(opts.BPFFS, opts.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()

	type candidate struct {
		st     BuildState
		lock   unix.Stat_t
		locked bool // its build lock exists
		plane  bool // the build is gone and only its plane directories are left
	}
	var out []BuildState
	var cands []candidate
	var errs []error
	seen := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || !e.Type().IsDir() {
			continue
		}
		hash, plane := e.Name(), false
		if h, _, ok := planeDirOf(hash); ok {
			if _, err := os.Stat(filepath.Join(base, h)); !errors.Is(err, os.ErrNotExist) {
				continue // a plane directory goes with its build, which is a candidate of its own
			}
			hash, plane = h, true
		}
		if hash == own || seen[hash] || !IsBuildHash(hash) {
			continue
		}
		seen[hash] = true
		c := candidate{st: BuildState{Hash: hash}, plane: plane}
		switch lock, err := d.Stat("bpf-" + hash + ".lock"); {
		case err == nil:
			c.lock, c.locked = lock, true
			c.st.Idle = opts.Now().Sub(time.Unix(lock.Mtim.Unix()))
			if opts.ExpiredOnly && c.st.Idle < opts.Linger {
				c.st.Why = whyLingering
				out = append(out, c.st)
				continue
			}
		case !errors.Is(err, os.ErrNotExist):
			c.st.Why = err.Error()
			out = append(out, c.st)
			errs = append(errs, fmt.Errorf("cgroup: stat the build lock of %s: %w", hash, err))
			continue
		}
		// A build with no lock file has no idle stamp, so it counts as expired; its timer gives it a linger from its
		// first look. A gone build's plane directories are removed at the timer's first sweep.
		cands = append(cands, c)
	}
	holders := lockHolders{read: table} // unreadable: no holder is shown, and each candidate gets a timer
	for _, c := range cands {
		hash := c.st.Hash
		if timerRunning(d, hash, opts.timerProcess) {
			c.st.Why = whyTimed
			out = append(out, c.st)
			continue
		}
		if table != nil {
			if c.locked && holders.held(c.lock, false) {
				c.st.Why, c.st.Idle = whyBusy, 0 // its launcher starts its timer when it leaves, its reaper if it dies
				out = append(out, c.st)
				continue
			}
			if timer, err := d.Stat("bpf-" + hash + ".timer"); err == nil && holders.held(timer, true) {
				c.st.Why = whyTimed // a timer that wrote no pid: an older tego's
				out = append(out, c.st)
				continue
			}
		}
		err := start(hash)
		if err == nil {
			c.st.Why, c.st.Rearmed = whyRearmed, true
			out = append(out, c.st)
			continue
		}
		if !errors.Is(err, errNoTimer) {
			errs = append(errs, err)
		}
		// No timer: the build is removed here, as its timer would remove it, past its linger only.
		if c.plane {
			if err := sweepOrphanPlanes(d, base, hash); err != nil {
				errs = append(errs, err)
			}
			c.st.Why = whyGone
			out = append(out, c.st)
			continue
		}
		st, err := sweepBuild(d, opts, hash, false)
		if err != nil {
			errs = append(errs, err)
		}
		out = append(out, st)
	}
	return out, errors.Join(errs...)
}

// touch sets the lock file's mtime, the start of the build's idle time.
func (l *buildLock) touch(now time.Time) error {
	if l == nil || l.f == nil {
		return nil
	}
	tv := unix.NsecToTimeval(now.UnixNano())
	if err := unix.Futimes(int(l.f.Fd()), []unix.Timeval{tv, tv}); err != nil {
		return fmt.Errorf("cgroup: stamp the build lock %s: %w", l.path, err)
	}
	return nil
}

// runSetLive reads the run set's keys and reports whether one names a cgroup that exists. Keys only: the key, a
// u64 cgroup id, is the one part of the map every build agrees on (ADR 0022 (5)), so this reads another build's
// run set as well as this one's. The rows of cgroups that no longer exist are deleted on the way.
func runSetLive(m *ebpf.Map, mount string) (bool, error) {
	if m == nil {
		return false, nil
	}
	return runSetLiveIn(m, mount)
}

// pinnedRunSetLive is runSetLive over the run set pinned at path; an error wraps os.ErrNotExist when none is.
func pinnedRunSetLive(path, mount string) (bool, error) {
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return false, fmt.Errorf("open its run set: %w", err)
	}
	defer func() { _ = m.Close() }()
	return runSetLive(m, mount)
}

// pinnedRunSetLiveReadOnly is pinnedRunSetLive that changes nothing, ListBuilds': the map is opened read-only and
// the rows of cgroups that are gone stay for a sweep to delete.
func pinnedRunSetLiveReadOnly(path, mount string) (bool, error) {
	m, err := ebpf.LoadPinnedMap(path, &ebpf.LoadPinOptions{ReadOnly: true})
	if err != nil {
		return false, fmt.Errorf("open its run set: %w", err)
	}
	defer func() { _ = m.Close() }()
	return scrubRunSet(runSetNoDelete{m}, func() (map[uint64]bool, error) { return cgroupIDs(mount) }, runSetSettle)
}

// runSetNoDelete is a run-set map whose Delete deletes nothing.
type runSetNoDelete struct{ *ebpf.Map }

func (runSetNoDelete) Delete(any) error { return nil }

// runSetKeys is the part of a run-set map runSetLiveIn uses; *ebpf.Map is one.
type runSetKeys interface {
	keyWalker
	Delete(key any) error
}

// runSetSettle is how long runSetLiveIn waits before it lists the cgroups a second time, to confirm that the
// ids missing from its first listing are really gone.
const runSetSettle = 50 * time.Millisecond

// runSetLiveIn is runSetLive over any run-set map, listing the cgroups under mount.
func runSetLiveIn(m runSetKeys, mount string) (bool, error) {
	return scrubRunSet(m, func() (map[uint64]bool, error) { return cgroupIDs(mount) }, runSetSettle)
}

// scrubRunSet reads every key first and lists the cgroups only after, so a row Prepare's insertRun put in after
// its cgroup existed is never missed. A descendant's row is not like that: cgroup_track's tp_btf/cgroup_mkdir
// inserts it before kernfs_activate() makes the directory visible in cgroupfs (ARCHITECTURE §4.1, §5 R11), so a
// listing can miss a cgroup whose row is already there. Deleting on one listing would then drop a live run's new
// child from every run-set keyed hook for the rest of the run, fail-open, and PurgeRun calls this without the
// build lock, while other runs of the build may be making cgroups. So an id missing from the first listing is
// deleted only when it is still missing from a second one taken settle later, by when a mkdir in flight during
// the first has activated its directory (it runs under cgroup_mutex between the hook and the activation, a
// window of microseconds). A row kept by mistake costs only a place in the run set's budget: nothing reads a
// row of a cgroup that is gone, and cgroup ids are not reused.
//
// The keys are read with mapKeys: cgroup_rmdir and other launchers' Detach delete rows while it walks, and a
// deleted cursor key restarts the kernel's walk at the first key.
func scrubRunSet(m runSetKeys, list func() (map[uint64]bool, error), settle time.Duration) (bool, error) {
	keys, err := mapKeys[uint64](m)
	if err != nil {
		return false, fmt.Errorf("cgroup: read the run set's keys: %w", err)
	}
	if len(keys) == 0 {
		return false, nil
	}
	existing, err := list()
	if err != nil {
		return false, err
	}
	live := false
	var missing []uint64
	for _, id := range keys {
		if existing[id] {
			live = true
			continue
		}
		missing = append(missing, id)
	}
	if len(missing) == 0 {
		return live, nil
	}
	time.Sleep(settle)
	if existing, err = list(); err != nil {
		return live, err
	}
	var stale []uint64
	for _, id := range missing {
		if existing[id] {
			live = true
			continue
		}
		stale = append(stale, id)
	}
	for _, id := range stale {
		if err := m.Delete(&id); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return live, fmt.Errorf("cgroup: delete the run-set row of vanished cgroup %d: %w", id, err)
		}
	}
	return live, nil
}

// cgroupIDs is the id of every cgroup under the cgroup2 mount: each directory's inode number (cgroupIDOfPath).
//
// It fails closed on a mount it cannot show to be cgroup2 (cgroupMountCheck), and on a walk whose root cannot be
// read: its callers delete the run-set rows of every id it does not list and remove a build none of whose ids it
// lists, so an empty listing of a mount that is missing, or of a directory that is not the cgroup tree, would
// make every live run's cgroup look gone and drop its rows and its build under it, fail-open. Only a directory
// below the root that vanishes during the walk is skipped: that cgroup was removed while it was being listed. Any
// other failure to stat a listed directory (ENOMEM, EIO, EACCES) is an error, not a missing id.
func cgroupIDs(mount string) (map[uint64]bool, error) {
	return cgroupIDsWith(mount, unix.Lstat)
}

// cgroupIDsWith is cgroupIDs with the stat of each directory given, so a test can fail it.
func cgroupIDsWith(mount string, lstat func(string, *unix.Stat_t) error) (map[uint64]bool, error) {
	if err := cgroupMountCheck(mount); err != nil {
		return nil, fmt.Errorf("cgroup: list the cgroups under %s: %w", mount, err)
	}
	ids := map[uint64]bool{}
	err := filepath.WalkDir(mount, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			if path != mount && errors.Is(err, os.ErrNotExist) {
				return nil // removed while walking
			}
			return err
		}
		if !d.IsDir() {
			return nil
		}
		var st unix.Stat_t
		if err := lstat(path, &st); err != nil {
			if path != mount && errors.Is(err, os.ErrNotExist) {
				return nil // removed between its listing and its stat
			}
			return err
		}
		ids[st.Ino] = true
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("cgroup: list the cgroups under %s: %w", mount, err)
	}
	return ids, nil
}

// cgroupMountCheck is what cgroupIDs asks of a mount before it lists it: checkCgroup2Mount. A unit test's mount is
// a plain directory, so the package's tests replace it (cgroupmount_test.go) with a check that the directory
// exists; the real one is tested on its own.
var cgroupMountCheck = checkCgroup2Mount

// checkCgroup2Mount refuses a mount whose filesystem is not cgroup2 (statfs magic CGROUP2_SUPER_MAGIC), or that
// cannot be statted at all.
func checkCgroup2Mount(mount string) error {
	var st unix.Statfs_t
	if err := unix.Statfs(mount, &st); err != nil {
		return fmt.Errorf("statfs: %w", err)
	}
	if uint64(st.Type) != unix.CGROUP2_SUPER_MAGIC { //nolint:unconvert // Type is int64 on some arches
		return fmt.Errorf("not a cgroup2 filesystem (magic %#x)", st.Type)
	}
	return nil
}

// SweepOptions says where builds live and which of them a sweep may remove.
type SweepOptions struct {
	// BPFFS is the bpf filesystem the pins live under; empty means DefaultBPFFS.
	BPFFS string
	// StateDir holds the build locks; empty means the verified /run/tego (ADR 0034).
	StateDir string
	// CgroupMount is the cgroup2 mount the run sets' cgroup ids are looked up under; empty means the system's.
	CgroupMount string
	// Linger is how long a build must have been idle to be removed; with Force it is not asked.
	Linger time.Duration
	Force  bool
	// ExpiredOnly skips the lingering cap: only builds idle past Linger go. Prepare's pass sets it, since a
	// removal on a launcher's path is allowed only for a build whose timer should already have removed it and
	// cannot be started again (ADR 0022 (4)); the cap is left to the timer, the reaper, stop and gc. In a re-arm
	// pass (RearmTimers) it re-arms only the builds idle past Linger.
	ExpiredOnly bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
	// runSetLive answers whether the run set pinned at path names a cgroup that exists under mount, an error
	// wrapping os.ErrNotExist when there is none; nil means loading the pinned map (a test's seam).
	runSetLive func(path, mount string) (bool, error)
	// lockTable reads the kernel's lock table for RearmTimers, its first read(2) asking for first bytes when first
	// is not 0; nil means /proc/locks (procLocksTable).
	lockTable func(first int) ([]byte, error)
	// timerProcess tells whether a pid is build hash's timer for a re-arm pass; nil means isTimerProcess under /proc
	// as uid 0 (timerRunning).
	timerProcess func(pid int, hash string) bool
	// objects reads the kernel's view of the objects pinned under a build for ListBuilds' memlock; nil means
	// opening each pin (kernelObjects).
	objects *bpfObjects
}

// BuildState is what a sweep found for one build.
type BuildState struct {
	Hash string
	// Removed says the sweep removed the build's pins; otherwise Why says why it was kept, and Cause, for a run set
	// that could not be read (whyUnread), what the read met.
	Removed bool
	Why     string
	Cause   string
	// Idle is how long the build had been idle, zero when a launcher of it holds its lock.
	Idle time.Duration
	// Rearmed says a re-arm pass (RearmTimers) started the build's timer, which had died.
	Rearmed bool
}

// SweepBuilds removes every build under the bpf filesystem that no launcher holds, whose run set is empty and
// that has been idle for opts.Linger (any idle time with Force), and past that the builds idle longest beyond
// maxLingering (not with ExpiredOnly). It is `tego gc`'s, doctor's and the timer's pass; a launcher's Prepare
// re-arms a dead timer instead (rearmExpired) and removes a build itself only when it cannot (ADR 0022 (4)). It
// needs root; an unprivileged caller finds nothing it may remove and reports the errors it met.
func SweepBuilds(opts SweepOptions) ([]BuildState, error) {
	if opts.BPFFS == "" {
		opts.BPFFS = DefaultBPFFS
	}
	if opts.CgroupMount == "" {
		opts.CgroupMount = identity.SystemCgroupRoot
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if _, err := lockRootOf(opts.BPFFS, opts.StateDir); err != nil {
		return nil, err
	}
	base := filepath.Join(opts.BPFFS, pinRoot)
	entries, err := os.ReadDir(base)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cgroup: list builds under %s: %w", base, err)
	}
	d, err := openState(opts.BPFFS, opts.StateDir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = d.Close() }()

	var out []BuildState
	var idle []BuildState
	var errs []error
	orphans := map[string]bool{}
	for _, e := range entries {
		if !e.IsDir() || !e.Type().IsDir() {
			continue
		}
		if hash, _, ok := planeDirOf(e.Name()); ok {
			// A build's plane directory goes with the build (pins.remove); one whose build is gone is an orphan.
			if _, err := os.Stat(filepath.Join(base, hash)); errors.Is(err, os.ErrNotExist) {
				orphans[hash] = true
			}
			continue
		}
		st, err := sweepBuild(d, opts, e.Name(), opts.Force)
		if err != nil {
			errs = append(errs, err)
		}
		if st.Why == whyLingering {
			idle = append(idle, st)
			continue
		}
		out = append(out, st)
	}
	// The cap: the builds still inside their linger, newest first; those past maxLingering go, unless the pass
	// removes expired builds only.
	sort.Slice(idle, func(i, j int) bool { return idle[i].Idle < idle[j].Idle })
	for i, st := range idle {
		if i >= maxLingering && !opts.ExpiredOnly {
			again, err := sweepBuild(d, opts, st.Hash, true)
			if err != nil {
				errs = append(errs, err)
			}
			st = again
		}
		out = append(out, st)
	}
	for hash := range orphans {
		if err := sweepOrphanPlanes(d, base, hash); err != nil {
			errs = append(errs, err)
		}
	}
	// What the builds that are gone left in the state directory goes with them.
	if _, err := removeStaleState(d, base); err != nil {
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}

// The reasons a sweep keeps a build.
const (
	whyGone      = "gone"
	whyBusy      = "a launcher of it holds its lock"
	whyLive      = "a run it enforces is alive"
	whyLingering = "idle for less than bpf.linger"
	whyUnread    = "its run set cannot be read"
	// KeptLive and KeptUnread are the two reasons that keep a build past its linger whatever the sweep, gc --builds'
	// Force included (ADR 0022 (1), (5)): doctor's row shows them (BuildInfo.Kept).
	KeptLive   = whyLive
	KeptUnread = whyUnread
	// A re-arm pass's reasons (RearmTimers).
	whyTimed   = "its timer is running"
	whyRearmed = "its timer was not running and was started"
)

// openState opens the directory the build locks live in, the verified /run/tego unless dir names another. A
// detached helper (the linger timer, the ring trimmer) is handed the default spelled out as hoststate.Path on its
// argv, and that path is the host directory too: opened with OpenAt it skipped ADR 0034 item 2's owner and mode
// check (root 0700 only since ADR 0042 (3)(b)).
//
// Pins under the host's bpf filesystem (bpffs "" or DefaultBPFFS) keep their locks in the host directory only:
// every tego process on the machine (a launcher's Prepare and last-out removal, a reaper's build duties, the
// linger timer, gc) locks there for the same pins, so a lock in another directory is one none of them reads, and a
// sweep would find the build idle under a Prepare that held it (base finding 9, 2026-10-16). That pairing is refused
// with ErrHostState (lockRootOf). A directory of the caller's own goes with pins under a root of its own (tests,
// fake kernels).
func openState(bpffs, dir string) (*hoststate.Dir, error) {
	host, err := lockRootOf(bpffs, dir)
	if err != nil {
		return nil, err
	}
	if host {
		return openHostState()
	}
	return hoststate.OpenAt(dir)
}

// lockRootOf reports whether dir is the host state directory, and refuses a directory of the caller's own beside
// pins under the host's bpf filesystem (openState). A caller that reads or removes pins before it opens the
// directory (ListBuilds, SweepBuilds, PurgeRun, RearmTimers) asks it first, so the refusal never depends on what the
// pins hold and a refused caller has changed nothing.
func lockRootOf(bpffs, dir string) (host bool, err error) {
	if dir == "" || filepath.Clean(dir) == hoststate.Path {
		return true, nil
	}
	if bpffs == "" || filepath.Clean(bpffs) == DefaultBPFFS {
		return false, fmt.Errorf("%w: pins under %s keep their build locks in %s only, not in %s", hoststate.ErrHostState,
			DefaultBPFFS, hoststate.Path, dir)
	}
	return false, nil
}

// openHostState is hoststate.Open, a variable so a test sees which directories openState verifies.
var openHostState = hoststate.Open

// sweepBuild removes one build if no launcher holds it, its run set is empty and, unless force, it has been
// idle for opts.Linger. The exclusive lock is held while it removes, so a launcher that starts meanwhile waits
// for the removal in acquireBuildLock and then loads the build afresh.
func sweepBuild(d *hoststate.Dir, opts SweepOptions, hash string, force bool) (BuildState, error) {
	st := BuildState{Hash: hash}
	pins, err := newPinLayout(opts.BPFFS, hash)
	if err != nil {
		st.Why = err.Error()
		return st, err
	}
	if _, err := os.Stat(pins.Root); errors.Is(err, os.ErrNotExist) {
		st.Why = whyGone
		return st, nil
	}
	f, busy, err := lockBuildExclusiveNB(d, hash, true)
	if err != nil {
		st.Why = err.Error()
		return st, fmt.Errorf("cgroup: lock the build %s: %w", hash, err)
	}
	if busy {
		st.Why = whyBusy
		return st, nil
	}
	defer unlockClose(f)
	var fst unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &fst); err != nil {
		st.Why = err.Error()
		return st, fmt.Errorf("cgroup: stat the build lock of %s: %w", hash, err)
	}
	st.Idle = opts.Now().Sub(time.Unix(fst.Mtim.Unix()))
	if !force && st.Idle < opts.Linger {
		st.Why = whyLingering
		return st, nil
	}
	live := pinnedRunSetLive
	if opts.runSetLive != nil {
		live = opts.runSetLive
	}
	switch alive, err := live(filepath.Join(pins.Maps, ebpfbindings.MapRunSet), opts.CgroupMount); {
	case errors.Is(err, os.ErrNotExist):
		// No run set: a build a launcher died loading, whose maps never got that far. Nothing enforces a run.
	case err != nil:
		st.Why, st.Cause = whyUnread, err.Error()
		return st, fmt.Errorf("cgroup: build %s is kept: %w", hash, err)
	case alive:
		// A run it enforces is alive, so the build is not idle: its idle time starts again now. Without this
		// every later sweep, each Prepare's among them, listed the whole cgroup tree again for this build for
		// as long as the run lived; now the next one looks again only a linger from now, as the timer does
		// (runTimer). Best effort: a lock whose mtime cannot be set is looked at again by the next sweep.
		now := opts.Now()
		tv := unix.NsecToTimeval(now.UnixNano())
		if err := unix.Futimes(int(f.Fd()), []unix.Timeval{tv, tv}); err == nil {
			st.Idle = 0
		}
		st.Why = whyLive
		return st, nil
	}
	if err := pins.remove(); err != nil {
		st.Why = err.Error()
		return st, fmt.Errorf("cgroup: remove build %s: %w", hash, err)
	}
	st.Removed = true
	return st, nil
}

// sweepOrphanPlanes removes the plane directories of build hash, whose own directory is gone: a removal that stopped
// between the two, or a build removed by a tego that knew no planes. It holds the build lock exclusively, as a
// build's removal does, and looks once more under it: a launcher that recreated the build meanwhile keeps them.
func sweepOrphanPlanes(d *hoststate.Dir, base, hash string) error {
	f, busy, err := lockBuildExclusiveNB(d, hash, true)
	if err != nil {
		return fmt.Errorf("cgroup: lock the build %s: %w", hash, err)
	}
	if busy {
		return nil // a launcher of it is starting
	}
	defer unlockClose(f)
	if _, err := os.Stat(filepath.Join(base, hash)); !errors.Is(err, os.ErrNotExist) {
		return nil
	}
	// As a build's removal, it returns once the kernel has released the planes' links (pinLayout.remove).
	var td teardown
	if err := removePlaneDirs(base, hash, &td); err != nil {
		return err
	}
	td.wait()
	return nil
}

// LingerMain is the build's timer, `tego __bpf-linger <hash> <linger> <bpffs> <state dir>`, which the last
// launcher out of a build starts (startTimer). It holds the build's timer lock, so one runs per build, and
// sleeps until the build lock's mtime plus the linger; it then sweeps every build (SweepBuilds), and exits once
// its own build is gone and has not been made again. A launcher that comes and goes meanwhile moves the mtime, and
// the timer sleeps again. It returns the process's exit code.
func LingerMain(args []string) int {
	if len(args) != 4 {
		fmt.Fprintf(os.Stderr, "usage: tego %s <hash> <linger> <bpffs> <state dir>\n", LingerCommand)
		return identity.ExitUsage
	}
	hash, bpffs, stateDir := args[0], args[2], args[3]
	if !IsBuildHash(hash) {
		fmt.Fprintf(os.Stderr, "tego %s: %q is not a build hash\n", LingerCommand, hash)
		return identity.ExitUsage
	}
	linger, err := time.ParseDuration(args[1])
	if err != nil || linger < 0 {
		fmt.Fprintf(os.Stderr, "tego %s: linger %q: %v\n", LingerCommand, args[1], err)
		return identity.ExitUsage
	}
	return runTimer(hash, linger, bpffs, stateDir, timerClock{})
}

// IsBuildHash says hash can name a build: one path component, not . or .., as its pin directory and its state
// files' names need. Every pin layout (newPinLayout), the helpers a launcher starts (LingerMain, RingTrimMain,
// the reaper) and a sweep reading run_start's bpf_hash refuse any other.
func IsBuildHash(hash string) bool {
	return hash != "" && !strings.ContainsAny(hash, "/\x00") && hash != "." && hash != ".."
}

// timerClock is the timer's clock and sleep; zero fields are time.Now and time.Sleep. A test's fake clock
// advances as the timer sleeps.
type timerClock struct {
	now   func() time.Time
	sleep func(time.Duration)
	// released, when set, runs once the timer has let its timer lock go on finding its build gone, before it looks
	// whether the build is back (a test's seam for the hand-off).
	released func()
	// retry, when set, replaces the wait before the timer asks for a busy timer lock the second time.
	retry func()
	// runSetLive, when set, replaces the sweep's look at a build's pinned run set (SweepOptions.runSetLive).
	runSetLive func(path, mount string) (bool, error)
}

// runTimer is the build's timer (LingerMain), which a reaper also becomes once its run is purged and no launcher
// of the build is left (ADR 0022 (3)). It returns the process's exit code.
//
// It keeps (8)'s bound, no program attached more than bpf.linger after its build's last run ended, by these:
//
//   - While a launcher holds its build it looks again a linger later, a second at least, and only at its own build
//     (probeBuild): the launcher leaves no earlier than the look that found it, so its last-out stamp plus the
//     linger, the build's new deadline, is no earlier than the next look. The leaving launcher's own timer exits on
//     this one's timer lock, so this one is the build's only timer: its back-off was a minute whatever the linger,
//     and a build with a 10 s linger stayed attached for 60 s.
//   - A build whose run set names a live cgroup, or cannot be read, is asked about again a linger later, a minute
//     at least: each of those looks lists the whole cgroup tree or opens the pinned run set. Between them it looks
//     at the build lock's mtime once a linger, a second at least, where the run's end is stamped, and a new stamp
//     sends it back to wait out the linger from there.
//   - Once its build is gone it lets the timer lock go and only then looks whether the build is there again
//     (handOff). A launcher that made the build again, ran and left last while this one still held the lock started
//     a timer that exited on it; exiting without that look left the build with no timer until the next Prepare,
//     doctor or gc.
func runTimer(hash string, linger time.Duration, bpffs, stateDir string, clock timerClock) int {
	if clock.now == nil {
		clock.now = time.Now
	}
	if clock.sleep == nil {
		clock.sleep = time.Sleep
	}
	pins, err := newPinLayout(bpffs, hash)
	if err != nil {
		return identity.ExitUsage
	}
	d, err := openState(bpffs, stateDir)
	if err != nil {
		return identity.ExitError
	}
	defer func() { _ = d.Close() }()
	timer, busy, err := lockTimer(d, hash)
	if err == nil && busy {
		// Asked once more a moment later, as a last launcher out asks lastOut (leaveBuild): a sweep's
		// removeStaleState takes a timer file's lock for a moment, and a timer that a re-arm pass started in that
		// moment would exit and leave its build with none.
		if clock.retry != nil {
			clock.retry()
		} else {
			time.Sleep(lastOutRetry)
		}
		timer, busy, err = lockTimer(d, hash)
	}
	switch {
	case err != nil:
		return identity.ExitError
	case busy:
		return identity.ExitOK // another timer keeps this build
	}
	defer func() {
		if timer != nil {
			unlockClose(timer)
		}
	}()
	opts := SweepOptions{BPFFS: bpffs, StateDir: stateDir, Linger: linger, Now: clock.now, runSetLive: clock.runSetLive}
	for {
		wait := linger
		// The lock's mtime through the verified directory's descriptor, as every file in it is reached (ADR 0034).
		if st, err := d.Stat("bpf-" + hash + ".lock"); err == nil {
			wait = time.Unix(st.Mtim.Unix()).Add(linger).Sub(clock.now())
		}
		if wait > 0 {
			clock.sleep(wait + time.Second)
		}
		states, err := SweepBuilds(opts)
		mine := BuildState{Why: whyGone}
		if err != nil {
			// A sweep that failed before it read this build (the builds could not be listed, the state directory
			// not reopened) says nothing of it: it is not gone, so it is asked about again, not left pinned.
			mine.Why = whyUnread
		}
		for _, s := range states {
			if s.Hash == hash {
				mine = s
			}
		}
		gone := mine.Removed || mine.Why == whyGone
		switch {
		case gone, mine.Why == whyLingering:
		case mine.Why == whyBusy:
			// Held: look at its own build only, a linger from each look, until no launcher holds it; the deadline
			// its last launcher out stamped is then waited for at the top of the loop.
			for {
				clock.sleep(max(linger, time.Second))
				g, held, err := probeBuild(d, pins, hash)
				if g || err != nil || !held {
					gone = g
					break
				}
			}
		default:
			// A run it enforces is alive, or its run set cannot be read: ask again a linger from now, or a minute
			// when the linger is shorter, so the cgroup tree is not listed hot. Meanwhile look at the build lock's
			// mtime once a linger, a second at least: the run's end is stamped there (its reaper's ReapBuild, or a
			// launcher leaving last), and a stamp is a new deadline, which the top of the loop waits for. Without
			// this look a build with a linger under a minute stayed attached up to a minute after its last run.
			stamped := lockMtime(d, hash)
			for slept, total := time.Duration(0), max(linger, time.Minute); slept < total; {
				step := min(max(linger, time.Second), total-slept)
				clock.sleep(step)
				slept += step
				if m := lockMtime(d, hash); !m.Equal(stamped) {
					break
				}
			}
		}
		if gone {
			if timer = handOff(d, pins, hash, timer, clock.released); timer == nil {
				return identity.ExitOK
			}
		}
	}
}

// lockMtime is build hash's lock's mtime through the verified directory's descriptor, the zero time when it cannot
// be read.
func lockMtime(d *hoststate.Dir, hash string) time.Time {
	st, err := d.Stat("bpf-" + hash + ".lock")
	if err != nil {
		return time.Time{}
	}
	return time.Unix(st.Mtim.Unix())
}

// probeBuild is the timer's look at its own build while a launcher holds it: gone when its pin directory is, and
// otherwise held unless its build lock can be taken exclusively, which it lets go at once, as a sweep's look does.
// A launcher whose lastOut falls in that moment asks again (leaveBuild).
func probeBuild(d *hoststate.Dir, pins pinLayout, hash string) (gone, held bool, err error) {
	if _, err := os.Stat(pins.Root); errors.Is(err, os.ErrNotExist) {
		return true, false, nil
	}
	f, busy, err := lockBuildExclusiveNB(d, hash, true)
	if err != nil || busy {
		return false, busy, err
	}
	unlockClose(f)
	return false, false, nil
}

// handOff is what the timer does once its build is gone: it lets its timer lock go, then looks whether the build
// is there again. If not, it returns nil and the timer exits; a launcher that makes the build from then on starts a
// timer that takes the lock. If it is, the timer takes the lock again and keeps going with the file it returns, or
// it returns nil when another timer took the lock first and keeps the build.
func handOff(d *hoststate.Dir, pins pinLayout, hash string, timer *os.File, released func()) *os.File {
	unlockClose(timer)
	if released != nil {
		released()
	}
	if _, err := os.Stat(pins.Root); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	next, busy, err := lockTimer(d, hash)
	if err != nil || busy {
		return nil
	}
	return next
}

// lockTimer takes the build's timer lock, bpf-<hash>.timer, LOCK_EX|LOCK_NB; busy means another timer holds it. It
// keeps the lock only once the name still leads to the file it locked, as lockBuildExclusiveNB does: a sweep removes
// a gone build's timer file when no one holds it (removeStaleState), and a lock on the unlinked file would let a
// second timer lock the new one. Holding it, it writes its pid into the file: that pid is how Prepare's re-arm pass
// tells that the timer lives (timerRunning, ADR 0022 note 2026-10-16), and stop's pass reads the kernel's lock table
// only for a build whose file shows no live timer (rearmTimers).
func lockTimer(d *hoststate.Dir, hash string) (f *os.File, busy bool, err error) {
	name := "bpf-" + hash + ".timer"
	for range 8 {
		f, err := d.OpenFile(name, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			return nil, false, err
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			_ = f.Close()
			if errors.Is(err, unix.EWOULDBLOCK) {
				return nil, true, nil
			}
			return nil, false, fmt.Errorf("cgroup: lock the timer file %s: %w", filepath.Join(d.Path(), name), err)
		}
		if d.Names(name, f) {
			if f.Truncate(0) == nil {
				_, _ = f.WriteAt([]byte(strconv.Itoa(os.Getpid())+"\n"), 0) // best effort: a timer it misses gets a second one, which exits on this lock
			}
			return f, false, nil
		}
		_ = f.Close()
	}
	return nil, true, nil
}
