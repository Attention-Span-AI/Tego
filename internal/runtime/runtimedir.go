// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A run's runtime directory, $XDG_RUNTIME_DIR/tego/<run id> (createRuntimeDir), holds its CODEX_HOME, with the
// key Codex types into auth.json, and its last-refusal mirror. The shutdown sequence removes it. A launcher killed
// before its shutdown (SIGKILL, the OOM killer, a crash) left it there until logout, and on a directory on disk past
// reboots, where any later run of the same user that may read the parent could read it.
//
// So the launcher holds an exclusive flock on runtimeLockFile in its directory for the run's life, through a
// descriptor no child inherits (O_CLOEXEC), and every launch first removes each run's directory under its parent
// whose lock nobody holds: the kernel drops a dead process's flock, so a free lock is a launcher that is gone.
//
// Rejected: asking the ledger whether the run is live. The parent is one per user and XDG_RUNTIME_DIR, while runs
// of that user may record into different ledger roots (TEGO_CONFIG, ledger_root), so a launcher cannot find every
// sibling's ledger lock, and a run it cannot find would have to be kept or guessed at. Removing by age was rejected
// as well: a run lasts as long as its agent does.
//
// The directory is made under a name that is no run id, ".new-<id>", locked, and only then renamed to <id>
// (RENAME_NOREPLACE), so a concurrent launch's sweep never meets it made and not yet locked. A directory with no lock
// file is left alone: an older tego made it, and nothing says whether its run still lives. Each entry is opened
// without following links and must be a directory of this euid that only it can write (privateRuntimeDirs), as the
// parent was before any of this ran; a root launcher makes and sweeps nothing (createRuntimeDir).

// runtimeLockFile is the lock file in a run's runtime directory.
const runtimeLockFile = ".lock"

// runtimeDirPending prefixes the name a run's runtime directory is made under before it is locked.
const runtimeDirPending = ".new-"

// makeRunRuntimeDir makes parent/<id>, mode 0700, with its lock held, and returns it and the lock's descriptor.
func makeRunRuntimeDir(parent, id string) (string, *os.File, error) {
	dir, pending := filepath.Join(parent, id), filepath.Join(parent, runtimeDirPending+id)
	if err := os.Mkdir(pending, 0o700); err != nil {
		return "", nil, fmt.Errorf("runtime: create run socket dir: %w", err)
	}
	fail := func(err error, lock *os.File) (string, *os.File, error) {
		if lock != nil {
			_ = lock.Close()
		}
		_ = os.RemoveAll(pending)
		return "", nil, fmt.Errorf("runtime: create run socket dir: %w", err)
	}
	lock, err := os.OpenFile(filepath.Join(pending, runtimeLockFile), os.O_RDWR|os.O_CREATE|os.O_EXCL|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return fail(err, nil)
	}
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock %s: %w", lock.Name(), err), lock)
	}
	if err := unix.Renameat2(unix.AT_FDCWD, pending, unix.AT_FDCWD, dir, unix.RENAME_NOREPLACE); err != nil {
		return fail(fmt.Errorf("rename %s to %s: %w", pending, dir, err), lock)
	}
	return dir, lock, nil
}

// closeRuntimeLock releases the run's lock, once its directory is gone.
func (r *runner) closeRuntimeLock() {
	if r.runtimeLock != nil {
		_ = r.runtimeLock.Close()
		r.runtimeLock = nil
	}
}

// sweepRuntimeParent removes each run's directory under parent whose launcher is gone. A failure costs the
// cleanup of that entry, never the launch, and is logged.
func sweepRuntimeParent(parent string, log *slog.Logger) {
	entries, err := os.ReadDir(parent)
	if err != nil {
		log.Warn("runtime: sweep runtime directory", "dir", parent, "err", err)
		return
	}
	for _, e := range entries {
		if !ledger.IsRunID(e.Name()) {
			continue // a directory being made (runtimeDirPending), or nothing of a run's
		}
		dir := filepath.Join(parent, e.Name())
		if removed, err := removeDeadRuntimeDir(dir); err != nil {
			log.Warn("runtime: sweep runtime directory", "dir", dir, "err", err)
		} else if removed {
			log.Info("runtime: removed the runtime directory of a run whose launcher is gone", "dir", dir)
		}
	}
}

// removeDeadRuntimeDir removes dir when it is a private directory of this euid whose lock nobody holds; it removes
// nothing and reports no error for a live run's directory or one with no lock file.
func removeDeadRuntimeDir(dir string) (bool, error) {
	if err := privateRuntimeDirs("", dir); err != nil {
		return false, err
	}
	lock, err := ledger.OpenRegular(filepath.Join(dir, runtimeLockFile)) // O_NOFOLLOW, refused unless a regular file
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer func() { _ = lock.Close() }()
	if err := sys.Flock(lock, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return false, nil // its launcher lives
		}
		return false, err
	}
	// Held from here until the removal is done, so a second sweep meeting the entry leaves it to this one.
	return true, os.RemoveAll(dir)
}
