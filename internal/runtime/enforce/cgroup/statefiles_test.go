// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// TestAGoneBuildWithNoLockFileKeepsAStartingLaunchersSlotTable: a sweep working from an earlier listing finds a
// gone build's lock file already removed by another sweep partway through its files. It used to remove the rest
// holding nothing, so a launcher of the same hash that created a new lock and slot table meanwhile lost its table,
// and with it its slot record. The removal now creates the lock again and holds it, so a launcher starts only
// once it is done, and its table stays.
func TestAGoneBuildWithNoLockFileKeepsAStartingLaunchersSlotTable(t *testing.T) {
	state, base := t.TempDir(), t.TempDir()
	table := filepath.Join(state, "slots-h1")
	if err := os.WriteFile(table, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	started := make(chan *buildLock, 1)
	startErr := make(chan error, 1)
	stateLockHeld = func(string) {
		go func() {
			l, err := acquireBuildLockIn(d, "h1")
			if err == nil {
				err = os.WriteFile(table, []byte("live"), 0o600)
			}
			started <- l
			startErr <- err
		}()
		// Let the launcher start if it can: it cannot while this removal holds the build's lock.
		select {
		case err := <-startErr:
			startErr <- err
		case <-time.After(time.Second):
		}
	}
	defer func() { stateLockHeld = func(string) {} }()

	if _, err := removeBuildState(d, base, "h1", []string{"slots-h1"}); err != nil {
		t.Fatal(err)
	}
	if err := <-startErr; err != nil {
		t.Fatal(err)
	}
	l := <-started
	defer l.Close()
	if got, err := os.ReadFile(table); err != nil || string(got) != "live" {
		t.Errorf("the starting launcher's slot table = %q, %v, want its record kept", got, err)
	}
	if !d.Names("bpf-h1.lock", l.f) {
		t.Error("the launcher does not hold the build's lock file")
	}
}

// TestStaleStateOfGoneBuildsIsRemoved is L4 of the round-7 review: /run/tego collected a lock, a timer lock, a
// slot table and capture-library locks for every build a host ever ran. A build whose pins are gone has them
// removed, its lock last and under its own exclusive hold; a build still pinned keeps them, and so does a gone
// build a launcher is starting (it holds the lock), and the host-wide rings lock is no build's.
func TestStaleStateOfGoneBuildsIsRemoved(t *testing.T) {
	t.Parallel()
	state, base := t.TempDir(), t.TempDir()
	if err := os.Mkdir(filepath.Join(base, "livehash"), 0o700); err != nil {
		t.Fatal(err)
	}
	gone := []string{"bpf-gonehash.lock", "bpf-gonehash.timer", "slots-gonehash",
		"bpf-gonehash-lib-8-9-abc.lock", "bpf-gonehash-lib-8-9-abc.pin"}
	kept := []string{"bpf-livehash.lock", "slots-livehash", "bpf-busyhash.lock", "slots-busyhash", ringsLockName}
	for _, name := range append(slices.Clone(gone), kept...) {
		if err := os.WriteFile(filepath.Join(state, name), nil, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	busy, err := acquireBuildLockIn(d, "busyhash")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()

	n, err := removeStaleState(d, base)
	if err != nil || n != len(gone) {
		t.Errorf("removeStaleState = %d, %v, want the %d files of the gone build", n, err, len(gone))
	}
	for _, name := range gone {
		if _, err := os.Stat(filepath.Join(state, name)); !os.IsNotExist(err) {
			t.Errorf("%s of a gone build is still there", name)
		}
	}
	for _, name := range kept {
		if _, err := os.Stat(filepath.Join(state, name)); err != nil {
			t.Errorf("%s was removed: %v", name, err)
		}
	}
}

// TestABuildLockWhoseNameWasRemovedIsTakenAgain: a launcher that opened a gone build's lock just before its holder
// removed it would hold a file that is no longer the build's lock, beside a launcher holding the new one. Once it
// holds the lock it checks that the name still leads to it; the removal is seen, and a fresh lock is taken.
func TestABuildLockWhoseNameWasRemovedIsTakenAgain(t *testing.T) {
	t.Parallel()
	state := t.TempDir()
	d, err := hoststate.OpenAt(state)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	l, err := acquireBuildLockIn(d, "h1")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Names("bpf-h1.lock", l.f) {
		t.Fatal("a lock just taken is not the one its name leads to")
	}
	if err := d.Unlink("bpf-h1.lock"); err != nil {
		t.Fatal(err)
	}
	if d.Names("bpf-h1.lock", l.f) {
		t.Error("a removed lock file still reads as the build's lock")
	}
	_ = l.Close()
	again, err := acquireBuildLockIn(d, "h1")
	if err != nil {
		t.Fatal(err)
	}
	defer again.Close()
	if !d.Names("bpf-h1.lock", again.f) {
		t.Error("the lock taken after the removal is not the build's lock file")
	}
}

// TestStateHash names the build a state file belongs to, and no build for the host-wide files.
func TestStateHash(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"bpf-0123abcd.lock": "0123abcd", "bpf-0123abcd.timer": "0123abcd", "slots-0123abcd": "0123abcd",
		"bpf-0123abcd-lib-1-2-none.pin": "0123abcd", "rings.lock": "", "bpf-.lock": "",
	} {
		got, ok := stateHash(name)
		if got != want || ok != (want != "") {
			t.Errorf("stateHash(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
}
