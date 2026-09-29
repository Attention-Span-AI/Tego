// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/runtime/hoststate"
)

// A build leaves files in /run/tego named by its hash: its build lock (bpf-<hash>.lock), its linger timer's lock
// (bpf-<hash>.timer), its slot table (slots-<hash>) and its capture libraries' locks (bpf-<hash>-lib-<key>.lock
// and .pin). tmpfs clears them at boot, but a host that upgrades tego, or runs builds side by side, collects
// them for every build it ever ran until then. removeStaleState removes those of each build whose pins are gone,
// holding that build's lock exclusively, so no launcher of it is between taking its lock and letting it go; one
// that opened the lock file just before it went finds, once it holds the lock, that the name no longer leads to
// the file it holds, and opens it again (acquireBuildLockIn), so no two launchers ever hold two different files
// as one build's lock. The exclusive takers that are not launchers (a sweep, a reaper, a ring reclaim's probe,
// this removal itself) check the same way (lockBuildExclusiveNB): one holding a removed file would judge unheld a
// build a new launcher holds on the new one.

// stateHash is the build hash a file of /run/tego is named by, and ok false for a file that is not a build's.
func stateHash(name string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(name, slotTableName+"-"):
		return strings.TrimPrefix(name, slotTableName+"-"), true
	case strings.HasPrefix(name, "bpf-"):
		rest = strings.TrimPrefix(name, "bpf-")
	default:
		return "", false
	}
	if i := strings.IndexAny(rest, "-."); i > 0 {
		return rest[:i], true
	}
	return "", false
}

// removeStaleState removes the files of every build under base whose pin directory is gone and whose lock no
// launcher holds, and reports how many it removed. A file another process holds a lock on stays.
func removeStaleState(d *hoststate.Dir, base string) (int, error) {
	entries, err := os.ReadDir(d.Path())
	if err != nil {
		return 0, fmt.Errorf("cgroup: list %s: %w", d.Path(), err)
	}
	files := map[string][]string{}
	for _, e := range entries {
		if hash, ok := stateHash(e.Name()); ok && e.Type().IsRegular() {
			files[hash] = append(files[hash], e.Name())
		}
	}
	var (
		removed int
		errs    []error
	)
	for hash, names := range files {
		if _, err := os.Stat(filepath.Join(base, hash)); !errors.Is(err, os.ErrNotExist) {
			continue // a build still pinned, or one that cannot be told gone
		}
		n, err := removeBuildState(d, base, hash, names)
		removed += n
		if err != nil {
			errs = append(errs, err)
		}
	}
	return removed, errors.Join(errs...)
}

// removeBuildState removes one gone build's files, its lock last and while holding it exclusively. A build whose
// lock file is already gone (another sweep, working from an earlier listing, is partway through its files) has the
// lock created again and held: removing the rest holding nothing would unlink the slot table of a launcher of the
// same hash that created a new lock and table meanwhile, and lose its slot record.
func removeBuildState(d *hoststate.Dir, base, hash string, names []string) (int, error) {
	lockName := "bpf-" + hash + ".lock"
	lock, busy, err := lockBuildExclusiveNB(d, hash, true)
	switch {
	case err != nil:
		return 0, fmt.Errorf("cgroup: lock the build %s: %w", hash, err)
	case busy:
		return 0, nil // a launcher of it is starting
	}
	defer func() { _ = lock.Close() }()
	stateLockHeld(hash)
	// A launcher that held the lock until now may have pinned the build again.
	if _, err := os.Stat(filepath.Join(base, hash)); !errors.Is(err, os.ErrNotExist) {
		return 0, nil
	}
	removed := 0
	for _, name := range names {
		if name == lockName {
			continue
		}
		f, err := d.OpenFile(name, os.O_RDWR, 0)
		if err != nil {
			continue
		}
		if unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB) == nil && d.Unlink(name) == nil {
			removed++
		}
		_ = f.Close()
	}
	// The lock goes last, whether it was listed or this removal created it; only a listed one counts as removed.
	if d.Unlink(lockName) == nil && slices.Contains(names, lockName) {
		removed++
	}
	return removed, nil
}

// stateLockHeld runs once removeBuildState holds the build's lock; a test replaces it to start a launcher there.
var stateLockHeld = func(string) {}
