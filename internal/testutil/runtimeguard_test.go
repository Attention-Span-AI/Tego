// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/realtego"
)

// runDir makes parent/name as a run's runtime directory with its lock file and, when held, returns the lock held
// as a live launcher holds it (closed at the test's end); a dead launcher's directory has the file and no holder.
func runDir(t *testing.T, parent, name string, held bool) {
	t.Helper()
	dir := filepath.Join(parent, name)
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, realtego.RuntimeLockFile), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		_ = f.Close()
		return
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = f.Close() })
}

// TestGuardRuntimeReportsWhatATestRunLeaves: the runtime guard reports a parent made, removed or replaced, any entry
// made that no live run holds the lock of (a lock-less directory and a file too: stricter than the sweep, since no
// run of the developer's makes one), and an entry gone that a launch's sweep would have removed (a run id's private
// directory with a free lock); it passes an unchanged parent, an absent one, an entry a live run made, a launch's
// entry still being made (whose lock it never takes, as the sweep never does: its launcher's own flock would fail),
// a live run's entry gone, and an entry gone that no sweep removes (not a run id, no lock file, a file, a link, a
// directory others can write), which a test's sweep cannot have done (identity-config.md R27 clause b4).
func TestGuardRuntimeReportsWhatATestRunLeaves(t *testing.T) {
	const id, id2 = "r-00000000-0000000000000-aaaaaa", "r-00000000-0000000000000-bbbbbb"
	type guardCase struct {
		name   string
		before func(t *testing.T, p string) // the parent's state at the snapshot; nil: absent
		during func(t *testing.T, p string) // what the tests did
		want   string                       // "" for a pass, else what the report names
	}
	cases := []guardCase{
		{"absent and untouched", nil, func(*testing.T, string) {}, ""},
		{"made", nil, func(t *testing.T, p string) { mkdir(t, p) }, "(made)"},
		{"made and an entry left", nil, func(t *testing.T, p string) { mkdir(t, p); runDir(t, p, id, false) }, "(made)"},
		{"unchanged", mkdir, func(*testing.T, string) {}, ""},
		{"unchanged with live and dead runs", func(t *testing.T, p string) {
			mkdir(t, p)
			runDir(t, p, id, true)
			runDir(t, p, id2, false)
		}, func(*testing.T, string) {}, ""},
		{"new locked entry", mkdir, func(t *testing.T, p string) { runDir(t, p, id, true) }, ""},
		{"new unlocked entry", mkdir, func(t *testing.T, p string) { runDir(t, p, id, false) }, id + " (made, and no live run holds it)"},
		{"a launch's pending entry, its lock not yet taken", mkdir,
			func(t *testing.T, p string) { runDir(t, p, realtego.RuntimeDirPending+id, false) }, ""},
		{"a pending entry renamed to its run id once locked", func(t *testing.T, p string) {
			mkdir(t, p)
			runDir(t, p, realtego.RuntimeDirPending+id, false)
		}, func(t *testing.T, p string) {
			rmAll(t, filepath.Join(p, realtego.RuntimeDirPending+id))
			runDir(t, p, id, true)
		}, ""},
		{"removed", mkdir, func(t *testing.T, p string) { rmAll(t, p) }, "(removed)"},
		{"replaced", mkdir, func(t *testing.T, p string) { rmAll(t, p); mkdir(t, p) }, "(replaced)"},
		{"a dead run's directory swept", func(t *testing.T, p string) { mkdir(t, p); runDir(t, p, id, false) },
			func(t *testing.T, p string) { rmAll(t, filepath.Join(p, id)) }, id + " (removed: a run's directory whose launcher was gone"},
		{"a live run's directory gone", func(t *testing.T, p string) { mkdir(t, p); runDir(t, p, id, true) },
			func(t *testing.T, p string) { rmAll(t, filepath.Join(p, id)) }, ""},
	}
	// Each shape of entry made during the tests, and each gone during them: made is reported unless a live run holds
	// it or a launch is still making it; gone only where a launch's sweep would have removed it (internal/runtime's
	// TestTheGuardsSweepableEntriesAreWhatASweepRemoves holds that set to a real sweep's).
	for _, shape := range RuntimeEntryShapes {
		made, gone := " (made, and no live run holds it)", ""
		switch shape {
		case entryLiveRun, entryPending:
			made = ""
		case entryDeadRun:
			gone = " (removed: a run's directory whose launcher was gone"
		}
		cases = append(cases,
			guardCase{"made: " + shape, mkdir, func(t *testing.T, p string) { PlantRuntimeEntry(t, p, shape) }, made},
			guardCase{"gone: " + shape, func(t *testing.T, p string) { mkdir(t, p); PlantRuntimeEntry(t, p, shape) },
				func(t *testing.T, p string) { rmAll(t, filepath.Join(p, runtimeEntryName(shape))) }, gone})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "tego")
			if c.before != nil {
				c.before(t, p)
			}
			check := guardRuntime([]string{p})
			c.during(t, p)
			err := check()
			switch {
			case c.want == "" && err != nil:
				t.Errorf("reported %v", err)
			case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
				t.Errorf("got %v, want a report naming %q", err, c.want)
			}
		})
	}
}

// TestRunLockIsTheSweepsTest: an entry's run is live only when its directory's lock file is a regular file another
// descriptor holds an exclusive flock on, and its lock is free only when such a file takes one; no lock file, a
// linked lock or directory, or a file in place of the directory has neither, and the check leaves a free lock free.
func TestRunLockIsTheSweepsTest(t *testing.T) {
	p := t.TempDir()
	runDir(t, p, "live", true)
	runDir(t, p, "dead", false)
	mkdir(t, filepath.Join(p, "nolock"))
	mkdir(t, filepath.Join(p, "linkedlock"))
	if err := os.Symlink(filepath.Join(p, "live", realtego.RuntimeLockFile), filepath.Join(p, "linkedlock", realtego.RuntimeLockFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(p, "live"), filepath.Join(p, "linkeddir")); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(p, "file"))
	for name, want := range map[string]lockState{"live": lockHeld, "dead": lockFree, "nolock": lockNone, "linkedlock": lockNone,
		"linkeddir": lockNone, "file": lockNone, "absent": lockNone} {
		if got := runLock(filepath.Join(p, name)); got != want {
			t.Errorf("%s: lock %v, want %v", name, got, want)
		}
	}
	f, err := os.Open(filepath.Join(p, "dead", realtego.RuntimeLockFile))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Errorf("the check left the dead run's lock held: %v", err)
	}
}

// TestGuardedRunFailsTheBinaryOnALeakedRuntimeDir is the deliberately leaking test, as a unit test of the guard:
// tests that leave a run's directory in a watched runtime parent, as a run that inherited the developer's
// XDG_RUNTIME_DIR did, fail the binary that passed them, and the line names the directory.
func TestGuardedRunFailsTheBinaryOnALeakedRuntimeDir(t *testing.T) {
	p := filepath.Join(t.TempDir(), "tego")
	mkdir(t, p)
	saved := guardRuntimeParents
	t.Cleanup(func() { guardRuntimeParents = saved })
	guardRuntimeParents = func() []string { return []string{p} }
	var stderr bytes.Buffer
	code := guardedRun(func() int { runDir(t, p, "r-00000000-0000000000000-cccccc", false); return 0 }, &stderr)
	if code == 0 || !strings.Contains(stderr.String(), filepath.Join(p, "r-00000000-0000000000000-cccccc")+" (made") {
		t.Errorf("code %d, stderr %q", code, stderr.String())
	}
	stderr.Reset()
	if code := guardedRun(func() int { return 0 }, &stderr); code != 0 {
		t.Errorf("an untouched parent failed the binary: %d %q", code, stderr.String())
	}
}

// TestRealGuardRuntimeParentsAreTheRealOnes: what GuardRealTego watches outside this package's own tests is every
// RealRuntimeDirs parent.
func TestRealGuardRuntimeParentsAreTheRealOnes(t *testing.T) {
	if got := guardRuntimeParents(); !slices.Equal(got, RealRuntimeDirs()) {
		t.Errorf("runtime parents %v, want RealRuntimeDirs %v", got, RealRuntimeDirs())
	}
}

func mkdir(t *testing.T, p string) {
	t.Helper()
	if err := os.Mkdir(p, 0o700); err != nil {
		t.Fatal(err)
	}
}

func rmAll(t *testing.T, p string) {
	t.Helper()
	if err := os.RemoveAll(p); err != nil {
		t.Fatal(err)
	}
}

func writeFile(t *testing.T, p string) {
	t.Helper()
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
}
