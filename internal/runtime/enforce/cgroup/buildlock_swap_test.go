// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// swapLockOnOpen makes the next open of build hash's lock by lockBuildExclusiveNB race a removal and a new
// launcher: between the open and the flock the lock file is unlinked, as removeStaleState does once the build is
// gone, and a new one is created and held shared, as a launcher recreating the build holds it while it loads.
func swapLockOnOpen(t *testing.T, state, hash string) {
	t.Helper()
	lock := filepath.Join(state, "bpf-"+hash+".lock")
	saved := buildLockOpened
	t.Cleanup(func() { buildLockOpened = saved })
	fired := false
	buildLockOpened = func(name string, _ *os.File) {
		if fired || name != filepath.Base(lock) {
			return
		}
		fired = true
		if err := os.Remove(lock); err != nil {
			t.Fatal(err)
		}
		f, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE, 0o600)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.Close() })
		if err := unix.Flock(int(f.Fd()), unix.LOCK_SH); err != nil {
			t.Fatal(err)
		}
	}
}

// TestASweepNeverTakesARemovedLockForTheBuilds is statefiles.go's invariant for the lock's other takers: a sweep
// that opened a build's lock file just before it was unlinked, and took it exclusively once a new launcher held the
// new one, judged the build unheld and removed it under that launcher. Every exclusive taker checks, once it
// holds the lock, that the name still leads to its file, as acquireBuildLockIn does.
func TestASweepNeverTakesARemovedLockForTheBuilds(t *testing.T) {
	bpffs, state := t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h5", "r5")
	then := time.Unix(1_600_000_000, 0)
	if err := os.Chtimes(filepath.Join(state, "bpf-h5.lock"), then, then); err != nil {
		t.Fatal(err)
	}
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	swapLockOnOpen(t, state, "h5")
	opts := SweepOptions{BPFFS: bpffs, StateDir: state, Linger: time.Minute,
		Now:        func() time.Time { return time.Unix(1_700_000_000, 0) },
		runSetLive: func(string, string) (bool, error) { return false, os.ErrNotExist }}
	st, err := sweepBuild(d, opts, "h5", false)
	if err != nil {
		t.Fatal(err)
	}
	if st.Removed || st.Why != whyBusy {
		t.Fatalf("a sweep holding a removed lock: %+v, want the build kept as busy", st)
	}
	if _, err := os.Stat(filepath.Join(bpffs, pinRoot, "h5")); err != nil {
		t.Fatalf("the build was removed under the launcher holding its new lock: %v", err)
	}
}

// TestARunningProbeNeverTakesARemovedLockForTheBuilds: buildRunning, which a ring reclaim asks before it takes a
// build's pooled rings, must not answer "not running" for a build a launcher is preparing on a new lock file.
func TestARunningProbeNeverTakesARemovedLockForTheBuilds(t *testing.T) {
	state := t.TempDir()
	if err := os.WriteFile(filepath.Join(state, "bpf-h6.lock"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = d.Close() }()
	swapLockOnOpen(t, state, "h6")
	if !buildRunning(d, "h6") {
		t.Fatal("buildRunning said a build a launcher holds is not running")
	}
}

// TestAReaperNeverTakesARemovedLockForTheBuilds: ReapBuild's lock decides whether its run was the build's last;
// one taken on a removed lock file did the last run's duties (a timer, or a sweep) for a build a new launcher holds,
// which does them itself when it leaves.
func TestAReaperNeverTakesARemovedLockForTheBuilds(t *testing.T) {
	bpffs, state, mount := t.TempDir(), t.TempDir(), t.TempDir()
	reapBuild(t, bpffs, state, "h7", "r7")
	timers := 0
	saved := startTimer
	startTimer = func(ReapTarget) error { timers++; return nil }
	t.Cleanup(func() { startTimer = saved })
	swapLockOnOpen(t, state, "h7")
	if err := ReapBuild(ReapTarget{Hash: "h7", BPFFS: bpffs, StateDir: state, Linger: time.Hour}, mount, nil); err != nil {
		t.Fatal(err)
	}
	if timers != 0 {
		t.Fatal("the reaper did the build's duties on a removed lock file while a launcher held the new one")
	}
}
