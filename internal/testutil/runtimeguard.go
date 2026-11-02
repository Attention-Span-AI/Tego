// SPDX-License-Identifier: Apache-2.0

package testutil

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/realtego"
	"github.com/attention-span-ai/tego/pkg/spec/identity"
)

// guardRuntimeParents names the runtime parents GuardRealTego watches: RealRuntimeDirs. Only this package's own
// tests replace it.
var guardRuntimeParents = RealRuntimeDirs

// runtimeParent is what guardRuntime records of one runtime parent that exists: its device and inode, what each entry
// is (classifyRuntimeEntry) and, in the snapshot, the descriptor that pins the inode.
type runtimeParent struct {
	dev, ino uint64
	entries  map[string]runtimeEntry
	pin      *os.File
}

// runtimeEntry is what the guard makes of one entry of a runtime parent.
type runtimeEntry uint8

const (
	runtimeHeld      runtimeEntry = iota // a live run's directory, or a launch's being made: never reported
	runtimeSweepable                     // what a launch's sweep removes: reported when made or gone
	runtimeOther                         // neither: reported when made, never when gone
)

// snapshotRuntime records each parent that exists: its device and inode and what each entry is. A
// parent it cannot open or stat (without following a final link) is recorded as absent. With pin, it keeps an
// O_PATH descriptor of each parent open, which blocks no removal and nothing else: while it is open the inode is
// not freed, so a directory made in the parent's place cannot be handed its number (tmpfs and ext4 reuse a freed
// one at once, within the same timestamp tick) and is told from it. The descriptor lives as long as the check
// that holds the snapshot, and its finalizer closes it.
func snapshotRuntime(parents []string, pin bool) map[string]runtimeParent {
	snap := map[string]runtimeParent{}
	for _, p := range parents {
		fd, err := unix.Open(p, unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			continue
		}
		f := os.NewFile(uintptr(fd), p)
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil {
			_ = f.Close()
			continue
		}
		rp := runtimeParent{dev: st.Dev, ino: st.Ino, entries: map[string]runtimeEntry{}}
		if pin {
			rp.pin = f
		} else {
			_ = f.Close()
		}
		ents, _ := os.ReadDir(p)
		for _, e := range ents {
			rp.entries[e.Name()] = classifyRuntimeEntry(p, e.Name())
		}
		snap[p] = rp
	}
	return snap
}

// classifyRuntimeEntry says what parent/name is to the guard. Held: a launch's directory being made (internal/runtime
// makeRunRuntimeDir), whose lock file its launcher has made and not yet locked, so an flock of it meanwhile would
// fail that launch's own and it is never opened, as the sweep never opens it either; or a directory whose lock a
// live run holds. Sweepable: exactly what a launch's sweep removes (sweepRuntimeParent, removeDeadRuntimeDir): a
// name of a run id's shape, a directory (not followed through a link) of this euid that neither group nor others can
// write, and a lock file, a regular file opened without following a link, that takes an exclusive flock without
// waiting. Other: anything else (no run id's name, no lock file, a linked lock, a file, a link, a directory others
// can write), which no sweep removes and no run of the developer's leaves. The guard is stricter than the sweep for
// an entry made (it reports any entry made that is not held, since a test that leaves one there reached the
// developer's runtime parent whatever it left) and exactly the sweep for an entry gone (it reports only what a sweep
// would have removed, so the developer removing an odd entry by hand fails nothing). internal/runtime's
// TestTheGuardsSweepableEntriesAreWhatASweepRemoves holds the sweepable set to a real sweep's.
func classifyRuntimeEntry(parent, name string) runtimeEntry {
	if strings.HasPrefix(name, realtego.RuntimeDirPending) {
		return runtimeHeld
	}
	dir := filepath.Join(parent, name)
	switch runLock(dir) {
	case lockHeld:
		return runtimeHeld
	case lockFree:
		if identity.RunID(name).Valid() && privateToEUID(dir) {
			return runtimeSweepable
		}
	case lockNone:
	}
	return runtimeOther
}

// privateToEUID reports whether dir, not followed through a link, is a directory owned by this euid that neither
// group nor others can write: the sweep's own test (internal/runtime privateRuntimeDirs) of an entry it removes.
func privateToEUID(dir string) bool {
	var st unix.Stat_t
	if err := unix.Lstat(dir, &st); err != nil {
		return false
	}
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && int(st.Uid) == os.Geteuid() && st.Mode&0o022 == 0
}

// lockState is what runLock finds of a run directory's lock.
type lockState uint8

const (
	lockNone lockState = iota // not a directory, no lock file, or one that is not a regular file
	lockFree                  // an exclusive flock of it was taken without waiting, and released
	lockHeld                  // it refused an exclusive flock without waiting: its launcher lives
)

// runLock tests the lock of dir, a directory not followed through a link, as a launch's sweep does before it
// removes a run's directory (removeDeadRuntimeDir): its lock file, realtego.RuntimeLockFile, opened without
// following a link and refused unless a regular file, then an exclusive flock without waiting. A lock it takes is
// released at once: a launch's own sweep meeting the entry meanwhile leaves it, as it leaves one another sweep
// holds.
func runLock(dir string) lockState {
	if st, err := os.Lstat(dir); err != nil || !st.IsDir() {
		return lockNone
	}
	f, err := os.OpenFile(filepath.Join(dir, realtego.RuntimeLockFile), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return lockNone
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err != nil || !st.Mode().IsRegular() {
		return lockNone
	}
	raw, err := f.SyscallConn()
	if err != nil {
		return lockNone
	}
	var lockErr error
	if err := raw.Control(func(fd uintptr) { lockErr = unix.Flock(int(fd), unix.LOCK_EX|unix.LOCK_NB) }); err != nil {
		return lockNone
	}
	switch {
	case lockErr == nil:
		return lockFree // released when f closes
	case errors.Is(lockErr, unix.EWOULDBLOCK):
		return lockHeld
	}
	return lockNone
}

// guardRuntime is GuardRealTego's check of the given runtime parents: it reports a parent made, removed or replaced
// since it was called, any entry made there that is not held (classifyRuntimeEntry), and an entry that was sweepable
// when it was called and is gone (a sweep's removal). It reports nothing of an entry whose lock is held, nor of
// one a live run made and removed meanwhile, nor of an entry gone that no sweep removes.
func guardRuntime(parents []string) func() error {
	before := snapshotRuntime(parents, true)
	return func() error {
		after := snapshotRuntime(parents, false)
		var changed []string
		for _, p := range parents {
			b, wasThere := before[p]
			a, isThere := after[p]
			switch {
			case !wasThere && isThere:
				changed = append(changed, p+" (made)")
			case wasThere && !isThere:
				changed = append(changed, p+" (removed)")
			case !wasThere:
			case a.dev != b.dev || a.ino != b.ino:
				changed = append(changed, p+" (replaced)")
			default:
				for name, st := range a.entries {
					if _, old := b.entries[name]; !old && st != runtimeHeld {
						changed = append(changed, filepath.Join(p, name)+" (made, and no live run holds it)")
					}
				}
				for name, st := range b.entries {
					if _, still := a.entries[name]; !still && st == runtimeSweepable {
						changed = append(changed, filepath.Join(p, name)+" (removed: a run's directory whose launcher was gone, as a sweep removes it)")
					}
				}
			}
		}
		if len(changed) == 0 {
			return nil
		}
		slices.Sort(changed)
		return fmt.Errorf("these tests reached the invoking user's real runtime directory, where every run keeps its "+
			"CODEX_HOME and every launch sweeps crashed runs' directories (a tego launched by hand meanwhile sweeps one "+
			"of yours too, and a run of yours killed meanwhile leaves its own: compare each run id's launch time with "+
			"yours, or rerun to tell): %s", strings.Join(changed, ", "))
	}
}
