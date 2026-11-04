// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// fakeTimerClock is a timerClock whose time moves only as the timer sleeps, recording each sleep; onSleep, when
// set, runs at each sleep with its index, before the clock moves.
type fakeTimerClock struct {
	at      time.Time
	sleeps  []time.Duration
	onSleep func(i int)
}

func (c *fakeTimerClock) clock() timerClock {
	return timerClock{
		now: func() time.Time { return c.at },
		sleep: func(d time.Duration) {
			if c.onSleep != nil {
				c.onSleep(len(c.sleeps))
			}
			c.sleeps = append(c.sleeps, d)
			c.at = c.at.Add(d)
		},
	}
}

// leaveLock lets a stand-in launcher's hold on its build lock go as a launcher does (buildLock.Close): LOCK_UN first,
// then the close. A close alone keeps the lock for as long as any copy of the descriptor lives, and a child that a
// parallel test forks holds one until its exec: the timer, whose fake sleeps take no time, then found the build
// still held at each of its looks (11 one-second back-offs instead of 2, once in a -tags integration run).
func leaveLock(f *os.File) {
	_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
	_ = f.Close()
}

// timerBuild makes a build's pins on a plain directory standing in for the bpf filesystem and its lock in state,
// idle since at. It returns the pin directory.
func timerBuild(t *testing.T, bpffs, state, hash string, at time.Time) string {
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
	if err := os.Chtimes(lock, at, at); err != nil {
		t.Fatal(err)
	}
	return p.Root
}

// TestTheTimerSleepsOutTheLingerThenRemovesItsBuild is ADR 0022 (2)-(4) in the timer: it sleeps from now until
// the build lock's mtime plus the linger (and a second), sweeps, and exits once its build is removed.
func TestTheTimerSleepsOutTheLingerThenRemovesItsBuild(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "th1", c.at.Add(-10*time.Minute))
	if code := runTimer("th1", time.Hour, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if want := []time.Duration{50*time.Minute + time.Second}; !slices.Equal(c.sleeps, want) {
		t.Errorf("sleeps %v, want %v: the rest of the linger from the lock's mtime", c.sleeps, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the build's pins are still there after its linger: %v", err)
	}
}

// TestTheTimerBacksOffWhileALauncherHoldsItsBuild: a build a launcher holds is not removed, and its timer asks
// again a linger later rather than polling it hot; once the launcher is gone the next sweep removes the build and
// the timer exits.
func TestTheTimerBacksOffWhileALauncherHoldsItsBuild(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "th2", c.at.Add(-2*time.Hour))
	held, err := os.Open(filepath.Join(state, "bpf-th2.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	c.onSleep = func(i int) {
		if i == 0 {
			if _, err := os.Stat(root); err != nil {
				t.Errorf("a held build was removed: %v", err)
			}
			leaveLock(held) // the launcher leaves
		}
	}
	if code := runTimer("th2", 30*time.Second, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if want := []time.Duration{30 * time.Second}; !slices.Equal(c.sleeps, want) {
		t.Errorf("sleeps %v, want %v: one linger's back-off while held", c.sleeps, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the build's pins are still there once no launcher held it: %v", err)
	}
}

// TestTheTimerKeepsTheBoundWhenALauncherLeavesWithinTheLinger is ADR 0022 (8)'s bound with a linger under a minute
// (D1): the timer finds its build held, a launcher that adopted it leaves a second later, and the build is removed
// no later than the linger and the timer's one second of slack after that leave, at +12 s for a 10 s linger. The
// leaving launcher's own timer exits on the timer lock this one holds, so this one is the build's only timer; its
// back-off was a minute, and the build stayed attached for 60 s.
func TestTheTimerKeepsTheBoundWhenALauncherLeavesWithinTheLinger(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	start := time.Unix(1_700_000_000, 0)
	c := &fakeTimerClock{at: start}
	root := timerBuild(t, bpffs, state, "tb1", start.Add(-2*time.Hour))
	lock := filepath.Join(state, "bpf-tb1.lock")
	held, err := os.Open(lock)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	left := start.Add(time.Second)
	c.onSleep = func(i int) {
		if i == 0 {
			// The launcher leaves at +1 s, last out: it stamps the idle start and lets the lock go.
			if err := os.Chtimes(lock, left, left); err != nil {
				t.Error(err)
			}
			leaveLock(held)
		}
	}
	const linger = 10 * time.Second
	if code := runTimer("tb1", linger, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	removedBy := c.at
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("the build's pins are still there after the timer exited: %v", err)
	}
	if bound := left.Add(linger + time.Second); removedBy.After(bound) {
		t.Errorf("removed at +%v (sleeps %v), want by +%v: a linger and a second after the launcher left",
			removedBy.Sub(start), c.sleeps, bound.Sub(start))
	}
}

// TestTheTimerBacksOffALingerWithASecondsFloorAndProbesOnlyItsOwnBuild: while a launcher holds its build the timer
// looks again a linger later, a second at least, and each look is at its own build only: another build past its
// linger is left to its own timer until this one's deadline sweep (one that expires during the back-off: one already
// expired goes at the timer's first sweep). A five-minute linger backs off five minutes, as before.
func TestTheTimerBacksOffALingerWithASecondsFloorAndProbesOnlyItsOwnBuild(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		linger, backOff time.Duration
	}{
		{100 * time.Millisecond, time.Second},
		{5 * time.Minute, 5 * time.Minute},
	} {
		t.Run(tc.linger.String(), func(t *testing.T) {
			t.Parallel()
			bpffs, state := t.TempDir(), t.TempDir()
			c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
			root := timerBuild(t, bpffs, state, "tb2", c.at.Add(-2*time.Hour))
			other := timerBuild(t, bpffs, state, "tb2other", c.at)
			held, err := os.Open(filepath.Join(state, "bpf-tb2.lock"))
			if err != nil {
				t.Fatal(err)
			}
			if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
				t.Fatal(err)
			}
			c.onSleep = func(i int) {
				if i == 1 {
					if _, err := os.Stat(other); err != nil {
						t.Errorf("a look at its held build swept another build: %v", err)
					}
					leaveLock(held) // the launcher leaves after the timer's first look
				}
			}
			if code := runTimer("tb2", tc.linger, bpffs, state, c.clock()); code != identity.ExitOK {
				t.Fatalf("runTimer: exit %d", code)
			}
			if want := []time.Duration{tc.backOff, tc.backOff}; !slices.Equal(c.sleeps, want) {
				t.Errorf("sleeps %v, want %v: a back-off of max(linger, 1s) at each look", c.sleeps, want)
			}
			for _, r := range []string{root, other} {
				if _, err := os.Stat(r); !os.IsNotExist(err) {
					t.Errorf("%s is still there after the timer's deadline sweep: %v", r, err)
				}
			}
		})
	}
}

// TestTheTimerTakesItsBuildBackWhenItIsMadeAgainAsItExits is ADR 0022 (3)'s hand-off (D2): a timer that finds its
// build gone lets its timer lock go and then looks once more. A launcher that made the build again, ran and left
// last while the old timer still held the lock started a timer that exited on it; the old timer now takes the build
// back and removes it at its deadline, instead of exiting and leaving it with no timer. The timer file it locks is
// the one its name leads to, though a sweep unlinked the old one in the window, so a later timer still finds it held.
func TestTheTimerTakesItsBuildBackWhenItIsMadeAgainAsItExits(t *testing.T) {
	// Not parallel: a sibling test that forks while this one's sweep holds a build's flock keeps the descriptor until
	// its exec (the race this file's header describes), and the fake clock then runs through dozens of busy retries in
	// no real time (CI, 2026-11-03: 57 extra one-minute backoffs).
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	timerBuild(t, bpffs, state, "tb3", c.at.Add(-2*time.Hour))
	var root string
	clk := c.clock()
	handOffs := 0
	clk.released = func() {
		handOffs++
		if handOffs > 1 {
			return
		}
		// Another process's sweep removes the gone build's timer file, which no one holds now.
		if err := os.Remove(filepath.Join(state, "bpf-tb3.timer")); err != nil {
			t.Error(err)
		}
		root = timerBuild(t, bpffs, state, "tb3", c.at) // made again, and its launcher left now
	}
	c.onSleep = func(int) {
		f, err := os.OpenFile(filepath.Join(state, "bpf-tb3.timer"), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Error(err)
			return
		}
		defer f.Close()
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
			t.Error("the timer file is not held while the timer waits for the build it took back: a second timer would run")
		}
	}
	if code := runTimer("tb3", time.Minute, bpffs, state, clk); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if handOffs != 2 {
		t.Fatalf("the timer let its lock go %d times, want 2: once per removal", handOffs)
	}
	if want := []time.Duration{time.Minute + time.Second}; !slices.Equal(c.sleeps, want) {
		t.Errorf("sleeps %v, want %v: the linger of the build made again", c.sleeps, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the build made again is still there after the timer exited: %v", err)
	}
}

// TestTheTimerLeavesABuildMadeAgainToTheTimerThatHoldsItsLock: in the same hand-off, a build made again whose
// launcher's timer took the timer lock first keeps that timer; the old one exits without sweeping.
func TestTheTimerLeavesABuildMadeAgainToTheTimerThatHoldsItsLock(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	timerBuild(t, bpffs, state, "tb4", c.at.Add(-2*time.Hour))
	var root string
	var next *os.File
	clk := c.clock()
	clk.released = func() {
		root = timerBuild(t, bpffs, state, "tb4", c.at)
		f, err := os.OpenFile(filepath.Join(state, "bpf-tb4.timer"), os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatalf("the new timer could not take the lock the old one let go: %v", err)
		}
		next = f
	}
	if code := runTimer("tb4", time.Minute, bpffs, state, clk); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if next == nil {
		t.Fatal("the timer never let its lock go")
	}
	defer next.Close()
	if len(c.sleeps) != 0 {
		t.Errorf("sleeps %v, want none: the build made again is the new timer's", c.sleeps)
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("the old timer removed the build the new one keeps: %v", err)
	}
}

// TestTheTimerExitsWhenItsBuildIsGone: a build removed by someone else (gc, another timer's sweep) ends its timer
// at the next sweep; it does not wait for a build that will not come back.
func TestTheTimerExitsWhenItsBuildIsGone(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	if code := runTimer("th3", time.Hour, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if len(c.sleeps) != 1 {
		t.Errorf("sleeps %v, want the one linger before its sweep", c.sleeps)
	}
}

// TestTheTimerRetriesASweepThatCouldNotListTheBuilds is ADR 0022 (3): the timer exits when its build is gone, and a
// sweep that failed before it read any build (here the builds' directory cannot be listed) does not say so. The
// timer backs off as for a held build and removes the build once a sweep can read it, instead of exiting and
// leaving it pinned.
func TestTheTimerRetriesASweepThatCouldNotListTheBuilds(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "th5", c.at.Add(-2*time.Hour))
	base := filepath.Join(bpffs, pinRoot)
	if err := os.Rename(base, base+".aside"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, nil, 0o600); err != nil { // ReadDir: ENOTDIR, not ENOENT
		t.Fatal(err)
	}
	c.onSleep = func(i int) {
		if i == 0 {
			if err := os.Remove(base); err != nil {
				t.Error(err)
			}
			if err := os.Rename(base+".aside", base); err != nil {
				t.Error(err)
			}
		}
	}
	if code := runTimer("th5", 30*time.Second, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	// A minute's back-off, in looks at the lock's mtime a linger apart, none of which saw a new stamp.
	if want := []time.Duration{30 * time.Second, 30 * time.Second}; !slices.Equal(c.sleeps, want) {
		t.Errorf("sleeps %v, want %v: one back-off after the failed sweep", c.sleeps, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the build's pins are still there after the timer exited: %v", err)
	}
}

// TestTheTimerKeepsTheBoundWhenTheRunItWaitedForIsReaped is ADR 0022 (8)'s bound with a linger under a minute when
// the build's last run is an orphan: the timer finds a run the build enforces alive and backs off, the run's reaper
// purges it at +1 s and stamps the build's idle start, and the build is removed no later than the linger and the
// timer's second of slack after that stamp, at +12 s for a 10 s linger. The reaper's own timer exits on the timer lock
// this one holds; this one's back-off for a live run was a minute, and the build stayed attached for 60 s (found by
// the step-2 kill test at a linger of 2 s, TestIntegrationABuildOutlivesItsLastLauncherWhileAKilledOnesRunLives).
// Between its looks at the run set, a minute apart at least so the cgroup tree is not listed hot, it looks at the
// build lock's mtime once a linger, a second at least.
func TestTheTimerKeepsTheBoundWhenTheRunItWaitedForIsReaped(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	start := time.Unix(1_700_000_000, 0)
	c := &fakeTimerClock{at: start}
	root := timerBuild(t, bpffs, state, "tr1", start.Add(-2*time.Hour))
	lock := filepath.Join(state, "bpf-tr1.lock")
	live := true
	reaped := start.Add(time.Second)
	c.onSleep = func(i int) {
		if i == 0 {
			// The reaper purges the run at +1 s, and stamps the build's idle start (ReapBuild).
			live = false
			if err := os.Chtimes(lock, reaped, reaped); err != nil {
				t.Error(err)
			}
		}
	}
	clock := c.clock()
	clock.runSetLive = func(string, string) (bool, error) { return live, nil }
	const linger = 10 * time.Second
	if code := runTimer("tr1", linger, bpffs, state, clock); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("the build's pins are still there after the timer exited: %v", err)
	}
	if bound := reaped.Add(linger + time.Second); c.at.After(bound) {
		t.Errorf("removed at +%v (sleeps %v), want by +%v: a linger and a second after the reaper's stamp",
			c.at.Sub(start), c.sleeps, bound.Sub(start))
	}
}

// TestASecondTimerOfABuildExitsAtOnce: one timer runs per build, by its timer lock; another started while it runs
// exits without sleeping or sweeping.
func TestASecondTimerOfABuildExitsAtOnce(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "th4", c.at.Add(-2*time.Hour))
	first, err := os.OpenFile(filepath.Join(state, "bpf-th4.timer"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	if err := unix.Flock(int(first.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if code := runTimer("th4", time.Minute, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if len(c.sleeps) != 0 {
		t.Errorf("sleeps %v, want none", c.sleeps)
	}
	if _, err := os.Stat(root); err != nil {
		t.Errorf("a second timer swept the build: %v", err)
	}
}

// TestTheHelpersRefuseANameThatIsNoBuildHash: the timer and the ring trimmer name their build by a command-line
// hash, which becomes state-file names and a pin directory; one that is not a single path component (empty, ., ..,
// or with a slash) is a usage error, before either touches the state directory.
func TestTheHelpersRefuseANameThatIsNoBuildHash(t *testing.T) {
	t.Parallel()
	for _, hash := range []string{"", ".", "..", "a/b", "a\x00b"} {
		bpffs, state := t.TempDir(), t.TempDir()
		if code := LingerMain([]string{hash, "0s", bpffs, state}); code != identity.ExitUsage {
			t.Errorf("LingerMain(%q): exit %d, want usage (%d)", hash, code, identity.ExitUsage)
		}
		if code := RingTrimMain([]string{hash, bpffs, state}); code != identity.ExitUsage {
			t.Errorf("RingTrimMain(%q): exit %d, want usage (%d)", hash, code, identity.ExitUsage)
		}
		if entries, _ := os.ReadDir(state); len(entries) != 0 {
			t.Errorf("hash %q: the state directory holds %d files, want none", hash, len(entries))
		}
	}
}

// TestAGoneBuildWithoutALockHasItsFilesRemoved is removeBuildState's lock-absent branch: a gone build whose lock
// file is already gone (removed out of band, or never made) has its other files removed, each only when no one
// holds a lock on it: a timer still running keeps its timer file. No launcher can be starting such a build, since
// a launcher makes its build lock before its slot table (acquireBuildLock, then openSlotTable).
func TestAGoneBuildWithoutALockHasItsFilesRemoved(t *testing.T) {
	t.Parallel()
	state, base := t.TempDir(), t.TempDir()
	for _, name := range []string{"slots-nolock", "bpf-nolock.timer", "bpf-nolock-lib-8-9-abc.lock"} {
		if err := os.WriteFile(filepath.Join(state, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	timer, err := os.Open(filepath.Join(state, "bpf-nolock.timer"))
	if err != nil {
		t.Fatal(err)
	}
	defer timer.Close()
	if err := unix.Flock(int(timer.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	n, err := removeStaleState(d, base)
	if err != nil || n != 2 {
		t.Errorf("removeStaleState = %d, %v, want the 2 files no one holds", n, err)
	}
	for _, name := range []string{"slots-nolock", "bpf-nolock-lib-8-9-abc.lock"} {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Errorf("%s of a gone build without a lock is still there", name)
		}
	}
	if _, err := os.Stat(filepath.Join(state, "bpf-nolock.timer")); err != nil {
		t.Errorf("the timer file a running timer holds was removed: %v", err)
	}
}
