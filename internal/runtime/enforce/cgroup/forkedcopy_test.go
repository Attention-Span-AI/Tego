// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// holdInAChild starts a child that keeps a copy of f's open file description, as a child that any goroutine of this
// process forks between f's open and its close keeps one until its exec: an flock belongs to the description, so
// that copy holds whatever lock f takes until the child lets it go. The child here is sleep with the copy as its
// descriptor 3, which keeps it past its exec, so the copy lives until the returned function kills it (the stand-in
// for the forked child's exec) or the test ends.
func holdInAChild(t *testing.T, f *os.File) (end func()) {
	t.Helper()
	fd, err := unix.Dup(int(f.Fd()))
	if err != nil {
		t.Fatal(err)
	}
	copied := os.NewFile(uintptr(fd), f.Name())
	defer func() { _ = copied.Close() }() // the child has its own copy once started
	child := exec.Command("sleep", "60")
	child.ExtraFiles = []*os.File{copied}
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	done := false
	end = func() {
		if done {
			return
		}
		done = true
		_ = child.Process.Kill()
		_ = child.Wait()
	}
	t.Cleanup(end)
	return end
}

// holdOpensInAChild makes each open of build hash's lock by lockBuildExclusiveNB, while *on, hand a copy of the
// opened file to a child (holdInAChild) before the flock, as a fork in that window does. It returns the children's
// ends.
func holdOpensInAChild(t *testing.T, hash string, on *bool) *[]func() {
	t.Helper()
	saved := buildLockOpened
	t.Cleanup(func() { buildLockOpened = saved })
	var ends []func()
	buildLockOpened = func(name string, f *os.File) {
		if *on && name == "bpf-"+hash+".lock" {
			ends = append(ends, holdInAChild(t, f))
		}
	}
	return &ends
}

// TestABuildLockLetGoIsFreeWhileAForkedChildKeepsACopy: each look that takes a build's lock exclusively for a moment
// (the timer's probe, a sweep that keeps the build, an orphan-plane or stale-state removal that finds the build back)
// lets it go with LOCK_UN, not by its close alone. A close alone left the lock held for as long as a child forked in
// that moment kept its copy of the descriptor: the timer then found the build held at each look and backed off a
// linger each time (TestTheTimerBacksOffWhileALauncherHoldsItsBuild failed with 14 back-offs in a tag rehearsal,
// 403 of 12,000 repetitions with forks running).
func TestABuildLockLetGoIsFreeWhileAForkedChildKeepsACopy(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		// look takes and lets go the lock of build hash, whose pins are under bpffs and lock in d, idle a minute.
		look func(t *testing.T, d *hoststate.Dir, bpffs, state, hash string)
	}{
		{"the timer's probe", func(t *testing.T, d *hoststate.Dir, bpffs, _, hash string) {
			pins, err := newPinLayout(bpffs, hash)
			if err != nil {
				t.Fatal(err)
			}
			if gone, held, err := probeBuild(d, pins, hash); gone || held || err != nil {
				t.Fatalf("probeBuild = gone %v, held %v, %v; want a build no launcher holds", gone, held, err)
			}
		}},
		{"a sweep that keeps a lingering build", func(t *testing.T, d *hoststate.Dir, bpffs, state, hash string) {
			opts := SweepOptions{BPFFS: bpffs, StateDir: state, Linger: time.Hour, Now: func() time.Time { return now }}
			if st, err := sweepBuild(d, opts, hash, false); err != nil || st.Why != whyLingering {
				t.Fatalf("sweepBuild = %+v, %v; want it kept as lingering", st, err)
			}
		}},
		{"an orphan-plane removal that finds the build", func(t *testing.T, d *hoststate.Dir, bpffs, _, hash string) {
			if err := sweepOrphanPlanes(d, filepath.Join(bpffs, pinRoot), hash); err != nil {
				t.Fatal(err)
			}
		}},
		{"a stale-state removal that finds the build", func(t *testing.T, d *hoststate.Dir, bpffs, _, hash string) {
			if n, err := removeBuildState(d, filepath.Join(bpffs, pinRoot), hash, nil); n != 0 || err != nil {
				t.Fatalf("removeBuildState = %d, %v; want nothing removed of a pinned build", n, err)
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			bpffs, state := t.TempDir(), t.TempDir()
			const hash = "fc1"
			timerBuild(t, bpffs, state, hash, now.Add(-time.Minute))
			d, err := hoststate.OpenAt(state)
			if err != nil {
				t.Fatal(err)
			}
			defer d.Close()
			on := true
			ends := holdOpensInAChild(t, hash, &on)
			tc.look(t, d, bpffs, state, hash)
			on = false
			if len(*ends) == 0 {
				t.Fatal("no open of the build lock was handed to a child")
			}
			f, busy, err := lockBuildExclusiveNB(d, hash, false)
			if err != nil {
				t.Fatal(err)
			}
			if busy {
				t.Fatal("the build lock is still held after the look let it go: a forked child's copy keeps it")
			}
			leaveLock(f)
		})
	}
}

// TestATimerLockHandedOffIsFreeWhileAForkedChildKeepsACopy: the timer that finds its build gone lets its timer
// lock go with LOCK_UN before it closes it (handOff). With a close alone a forked child's copy kept the lock, and
// the next launcher's timer, finding it busy twice, exited and left the build with no timer.
func TestATimerLockHandedOffIsFreeWhileAForkedChildKeepsACopy(t *testing.T) {
	t.Parallel()
	bpffs, state := t.TempDir(), t.TempDir()
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	pins, err := newPinLayout(bpffs, "fc2") // never created: the build is gone
	if err != nil {
		t.Fatal(err)
	}
	timer, busy, err := lockTimer(d, "fc2")
	if err != nil || busy {
		t.Fatalf("lockTimer = busy %v, %v", busy, err)
	}
	holdInAChild(t, timer)
	if next := handOff(d, pins, "fc2", timer, nil); next != nil {
		_ = next.Close()
		t.Fatal("handOff kept the timer lock of a gone build")
	}
	again, busy, err := lockTimer(d, "fc2")
	if err != nil {
		t.Fatal(err)
	}
	if busy {
		t.Fatal("the timer lock is still held after handOff let it go: a forked child's copy keeps it")
	}
	leaveLock(again)
}

// TestTheTimerBacksOffOnceWhenAForkedChildKeepsACopyOfItsLook is the tag rehearsal's failure made certain: once the
// launcher leaves, a child forked while the timer's probe holds the build lock keeps a copy of it for three of the
// timer's sleeps (it execs then). The timer backs off one linger while the launcher holds the build, as
// TestTheTimerBacksOffWhileALauncherHoldsItsBuild wants, not once more for each look the child's copy answered.
func TestTheTimerBacksOffOnceWhenAForkedChildKeepsACopyOfItsLook(t *testing.T) {
	bpffs, state := t.TempDir(), t.TempDir()
	c := &fakeTimerClock{at: time.Unix(1_700_000_000, 0)}
	root := timerBuild(t, bpffs, state, "fc3", c.at.Add(-2*time.Hour))
	held, err := os.Open(filepath.Join(state, "bpf-fc3.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(int(held.Fd()), unix.LOCK_SH); err != nil {
		t.Fatal(err)
	}
	on := false
	ends := holdOpensInAChild(t, "fc3", &on)
	c.onSleep = func(i int) {
		switch i {
		case 0:
			leaveLock(held) // the launcher leaves; the next open is the probe's, and a child is forked in it
			on = true
		case 1:
			on = false
		case 3:
			for _, end := range *ends {
				end() // the child execs
			}
		}
	}
	if code := runTimer("fc3", 30*time.Second, bpffs, state, c.clock()); code != identity.ExitOK {
		t.Fatalf("runTimer: exit %d", code)
	}
	if want := []time.Duration{30 * time.Second}; !slices.Equal(c.sleeps, want) {
		t.Errorf("sleeps %v, want %v: one linger's back-off while the launcher held the build", c.sleeps, want)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Errorf("the build's pins are still there once no launcher held it: %v", err)
	}
}
