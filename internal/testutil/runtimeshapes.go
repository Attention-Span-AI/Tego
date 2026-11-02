// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/attention-span-ai/tego/internal/realtego"
)

// The shapes of entry a runtime parent can hold, as the test guard and a launch's sweep (internal/runtime
// sweepRuntimeParent) tell them apart. Only a dead run's directory is one a sweep removes.
const (
	entryDeadRun     = "a dead run's directory"                                // a run id's private directory, its lock free
	entryLiveRun     = "a live run's directory"                                // its lock held
	entryPending     = "a launch's directory being made"                       // .new-<run id>, its lock not yet taken
	entryNoLock      = "a run id's directory with no lock file"                // a sweep leaves it
	entryLinkedLock  = "a run id's directory whose lock file is a link"        // a sweep refuses it
	entryOthersWrite = "a run id's directory, its lock free, others can write" // a sweep refuses it
	entryFile        = "a file with a run id's name"                           // a sweep refuses it
	entryLink        = "a link with a run id's name to a dead run's directory" // a sweep refuses it
	entryNotRunID    = "a directory, its lock free, with no run id's name"     // a sweep skips it
)

// RuntimeEntryShapes is every shape PlantRuntimeEntry makes.
var RuntimeEntryShapes = []string{entryDeadRun, entryLiveRun, entryPending, entryNoLock, entryLinkedLock, entryOthersWrite,
	entryFile, entryLink, entryNotRunID}

// runtimeEntryName is the name PlantRuntimeEntry gives the entry of shape: a name of its own for each, so that every
// shape can stand in one parent.
func runtimeEntryName(shape string) string {
	tag := map[string]string{entryDeadRun: "dead00", entryLiveRun: "live00", entryPending: "pend00", entryNoLock: "nolock",
		entryLinkedLock: "lnlock", entryOthersWrite: "others", entryFile: "file00", entryLink: "link00"}[shape]
	switch {
	case shape == entryNotRunID:
		return "not-a-run"
	case tag == "":
		panic("testutil: no runtime entry shape " + shape)
	case shape == entryPending:
		return realtego.RuntimeDirPending + "r-00000000-0000000000000-" + tag
	}
	return "r-00000000-0000000000000-" + tag
}

// PlantRuntimeEntry makes the entry of the given shape (one of RuntimeEntryShapes) in parent, as a run, a launch or
// something else would leave it, and returns its name. A live run's lock is held until the test ends; a link's
// target and a linked lock's file are outside parent.
func PlantRuntimeEntry(t testing.TB, parent, shape string) string {
	t.Helper()
	name := runtimeEntryName(shape)
	dir := filepath.Join(parent, name)
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	lock := func(dir string, held bool) {
		t.Helper()
		f, err := os.OpenFile(filepath.Join(dir, realtego.RuntimeLockFile), os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		must(err)
		if !held {
			must(f.Close())
			return
		}
		must(syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB))
		t.Cleanup(func() { _ = f.Close() })
	}
	switch shape {
	case entryFile:
		must(os.WriteFile(dir, nil, 0o600))
		return name
	case entryLink:
		target := filepath.Join(t.TempDir(), name)
		must(os.Mkdir(target, 0o700))
		lock(target, false)
		must(os.Symlink(target, dir))
		return name
	}
	must(os.Mkdir(dir, 0o700))
	switch shape {
	case entryLiveRun:
		lock(dir, true)
	case entryNoLock:
	case entryLinkedLock:
		other := filepath.Join(t.TempDir(), realtego.RuntimeLockFile)
		must(os.WriteFile(other, nil, 0o600))
		must(os.Symlink(other, filepath.Join(dir, realtego.RuntimeLockFile)))
	case entryOthersWrite:
		lock(dir, false)
		must(os.Chmod(dir, 0o770))
	default: // a dead run, a launch's directory being made, a name that is no run id: a free lock
		lock(dir, false)
	}
	return name
}

// SweepableRuntimeEntries names the entries of parent that the test guard counts as what a launch's sweep removes:
// those whose disappearance it reports.
func SweepableRuntimeEntries(parent string) []string {
	var out []string
	for name, st := range snapshotRuntime([]string{parent}, false)[parent].entries {
		if st == runtimeSweepable {
			out = append(out, name)
		}
	}
	return out
}
