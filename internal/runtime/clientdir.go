// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/ledger"
	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// A root launcher makes no runtime directory (createRuntimeDir: $XDG_RUNTIME_DIR names a directory the invoking user
// controls, and root creating and deleting through it is root writing where that user points it), yet a source may
// have a file the agent must read that only the launcher can compose: the MCP relay's client config
// (TEGO_MCP_CONFIG). At a root tier the run gets a client directory instead, made where no user can rearrange the
// path: /run/tego-agent (root, 0711: one may walk through it to a name one knows, never list it or add to it) and
// under it /run/tego-agent/<run id> (root, 0711, locked as a runtime directory is). The file in it is made by root
// with O_EXCL and O_NOFOLLOW in a directory only root can write, 0400, and handed by its descriptor to the account the
// agent drops to (sudo's SUDO_UID and SUDO_GID): that account reads it, no other user does (the file is not group or
// world readable, whatever group they share), and nothing beside it can be added, renamed or removed by anyone but
// root. The agent may chmod or rewrite its own copy; the relay never reads the file back (mcprelay.Service.UseClientDir).
// The shutdown sequence removes the directory, and a launcher that died first leaves it to the next root launch's
// sweep (sweepClientParent).
//
// /run itself is checked first and held by its descriptor: a directory of this euid (root's) that group and others
// cannot write, unless it is sticky as /tmp is, since where another user can rename /run's entries, any later step
// that looked a name up again by path could be sent through a link. After that check every step goes through an open
// descriptor: mkdirat, openat with O_NOFOLLOW and O_DIRECTORY, fchmod, fchown, renameat2 and unlinkat with one name
// each, never a path (the sweep and the removal too). A directory swapped for a link, or renamed, after it was opened
// changes nothing: the steps go on in the directory that was checked.
//
// An unprivileged launcher needs none: its runtime directory is private to the user the agent runs as. When it has
// none (XDG_RUNTIME_DIR not set, not absolute, missing, or not private) a source that needs a file in it refuses the
// run (ErrNoClientDir), saying which.
//
// Rejected: the file written by the child stage once it is the agent's user, into that user's runtime directory. It
// needs the stage to carry the file's bytes, and the account may have no /run/user/<uid> at all (sudo from su or
// from ssh without pam_systemd), so the run would still lack the file there.

// clientDirParent is the parent of a root run's client directory. Its own parent (/run) is the directory that is
// checked and held. A variable so this package's tests can make one in their own directory; nothing in a product
// build reassigns it.
var clientDirParent = "/run/tego-agent"

// clientDirMode is the mode of the parent and of each run's directory: search for everyone, nothing else.
const clientDirMode = 0o711

// clientPendingStale is how old a `.new-<run id>` directory with no lock file must be before a sweep takes it: a
// launcher makes the directory, then its lock, within microseconds, so one this old with no lock was left by a launcher
// that died between the two.
const clientPendingStale = 5 * time.Minute

// clientDirRoot says whether this launcher is root, and clientDirTarget names the account its agent drops to; both
// are variables for this package's tests. clientStepHook is called between makeClientDir's steps, a seam for a test
// that swaps a directory for a link at that moment.
var (
	clientDirRoot   = func() bool { return os.Geteuid() == 0 }
	clientDirTarget = dropTarget
	clientStepHook  = func(string) {}
)

// ErrNoClientDir is a run whose rules ask for a file the agent reads (an `mcp:` server behind the relay) where the
// launcher has no place for it: an unprivileged one with no usable runtime directory, or a root one that cannot make
// its client directory. Refused before run_start, exit 125.
var ErrNoClientDir = errors.New("runtime: no directory for the files the run's agent reads")

// clientFileSource is a source that writes a file the agent reads, before the agent's environment is built (the
// relay's client config, TEGO_MCP_CONFIG), into the directory it is handed. For a root launcher fd is that directory
// held open (the file is made through it, never through path), and uid and gid are the owner of the file: the account
// the agent drops to. For an unprivileged launcher fd is nil, path is the run's runtime directory, already private to
// the agent's user, and uid is -1.
type clientFileSource interface {
	Name() string
	UseClientDir(path string, fd *sys.FD, uid, gid int) error
}

// tellClientDir gives each source that writes a file the agent reads its directory, after the runtime directory is
// made and before the child's environment is built. A source that is given none because the launcher has no place
// for it refuses the run: the rules asked for what the file carries, so the run does not start without it.
func (r *runner) tellClientDir() error {
	var sources []clientFileSource
	for _, s := range r.deps.Extra {
		if d, ok := s.(clientFileSource); ok {
			sources = append(sources, d)
		}
	}
	if len(sources) == 0 {
		return nil
	}
	path, fd, uid, gid, err := r.clientFileDir()
	if err != nil {
		return err
	}
	for _, s := range sources {
		if err := s.UseClientDir(path, fd, uid, gid); err != nil {
			return fmt.Errorf("runtime: %s: %w", s.Name(), err)
		}
	}
	return nil
}

// clientFileDir is where the run's agent reads the files its sources write: the runtime directory of an unprivileged
// launcher (no descriptor, uid and gid -1), or a root launcher's client directory made for the account the agent
// drops to.
func (r *runner) clientFileDir() (path string, fd *sys.FD, uid, gid int, err error) {
	if !clientDirRoot() {
		if r.runtimeDir == "" {
			return "", nil, -1, -1, noRuntimeDirError()
		}
		return r.runtimeDir, nil, -1, -1, nil
	}
	uid, gid, err = clientDirTarget()
	if err != nil {
		return "", nil, -1, -1, err
	}
	c, err := makeClientDir(clientDirParent, string(r.id), r.log)
	if err != nil {
		return "", nil, -1, -1, fmt.Errorf("%w: %w", ErrNoClientDir, err)
	}
	r.client = c
	return c.path, c.dir, uid, gid, nil
}

// noRuntimeDirError says why an unprivileged launcher has no runtime directory for a run whose rules ask for a file in
// it, one true sentence for each cause, with what to do about it: XDG_RUNTIME_DIR not set, not an absolute path, not
// there, or there and not private to this user (what createRuntimeDir refuses, in its own words).
func noRuntimeDirError() error {
	base := os.Getenv("XDG_RUNTIME_DIR")
	var cause, fix string
	switch {
	case base == "":
		cause = "XDG_RUNTIME_DIR is not set"
		fix = fmt.Sprintf("log in through a session that sets it (systemd-logind sets XDG_RUNTIME_DIR=/run/user/%d), or export XDG_RUNTIME_DIR as an absolute directory only you can write", os.Getuid())
	case !filepath.IsAbs(base):
		cause = fmt.Sprintf("XDG_RUNTIME_DIR is %q, which is not an absolute path", base)
		fix = "export XDG_RUNTIME_DIR as an absolute directory only you can write"
	default:
		if _, err := os.Stat(base); errors.Is(err, os.ErrNotExist) {
			cause = fmt.Sprintf("XDG_RUNTIME_DIR %s does not exist", base)
			fix = "create it (mode 0700), or export XDG_RUNTIME_DIR as an existing absolute directory only you can write"
		} else if err != nil {
			cause = fmt.Sprintf("XDG_RUNTIME_DIR %s cannot be read: %v", base, err)
			fix = "export XDG_RUNTIME_DIR as an absolute directory only you can write"
		} else if err := privateRuntimeDirs(base); err != nil {
			cause, fix = err.Error(), ""
		} else if err := privateRuntimeDirs("", filepath.Join(base, "tego")); err != nil && !errors.Is(err, os.ErrNotExist) {
			cause, fix = err.Error(), ""
		} else {
			cause = fmt.Sprintf("XDG_RUNTIME_DIR %s gave this run no runtime directory", base)
			fix = "see tego's own log for the reason (" + base + "/tego must be a directory only you can write)"
		}
	}
	if fix != "" {
		fix += "; "
	}
	return fmt.Errorf("%w: %s, and the run's rules ask for a file in a runtime directory, the MCP relay's client config (TEGO_MCP_CONFIG): %sor remove the mcp entries from the contract",
		ErrNoClientDir, cause, fix)
}

// clientDir is a root launcher's client directory for one run, held by descriptor.
type clientDir struct {
	path   string  // parent/<id>: what the agent is told, and what messages name
	id     string  // the run's name under the parent
	parent *sys.FD // the checked parent, /run/tego-agent
	dir    *sys.FD // the run's directory
	lock   *sys.FD // its lock file, flocked for the run's life
}

// close removes the run's directory and everything in it, by descriptor, then releases the lock and the descriptors.
// The lock is dropped last, so no sweep meets the directory unlocked while it is still there.
func (c *clientDir) close() error {
	var errs []error
	if err := removeTreeAt(c.dir, 0); err != nil {
		errs = append(errs, err)
	}
	if err := c.parent.Borrow(func(n int) error { return unix.Unlinkat(n, c.id, unix.AT_REMOVEDIR) }); err != nil && !errors.Is(err, unix.ENOENT) {
		errs = append(errs, fmt.Errorf("remove %s: %w", c.path, err))
	}
	for _, f := range []*sys.FD{c.dir, c.lock, c.parent} {
		if err := f.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// removeClientDir removes the run's client directory, once no process of the run is left.
func (r *runner) removeClientDir() {
	if r.client == nil {
		return
	}
	if err := r.client.close(); err != nil {
		r.log.Warn("run: remove the client directory", "dir", r.client.path, "err", err)
	}
	r.client = nil
}

// makeClientDir makes parent/<id> for a root launcher. The parent's own parent (/run) is opened and checked first and
// held; the client parent is made in it by name and opened without following a link, checked (this euid's) and given
// clientDirMode; the sweep of the directories whose launcher is gone follows; then the run's directory is made under
// the parent as `.new-<id>`, locked, renamed to <id> (RENAME_NOREPLACE) and given clientDirMode. Every step after the
// first goes through a descriptor opened in the step before.
func makeClientDir(parent, id string, log *slog.Logger) (*clientDir, error) {
	runFD, err := openCheckedRun(filepath.Dir(parent))
	if err != nil {
		return nil, err
	}
	defer func() { _ = runFD.Close() }()
	clientStepHook("run")
	pfd, err := makeClientParent(runFD, parent)
	if err != nil {
		return nil, err
	}
	clientStepHook("parent")
	sweepClientParent(pfd, parent, log)
	clientStepHook("swept")
	c, err := makeClientRunDir(pfd, parent, id)
	if err != nil {
		_ = pfd.Close()
		return nil, err
	}
	return c, nil
}

// openCheckedRun opens /run (or the directory a test gave) without following a link and refuses it unless this euid
// owns it and group and others cannot write it, or it is sticky: otherwise another user could rename what the steps
// after this one look up by name.
func openCheckedRun(path string) (*sys.FD, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, fmt.Errorf("runtime: open %s: %w", path, err)
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("runtime: stat %s: %w", path, err)
	}
	switch {
	case int(st.Uid) != os.Geteuid():
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not %d, so another user could change what tego makes in it; %s must be root's and not writable by group or others",
			ErrRuntimeDirUnsafe, path, st.Uid, os.Geteuid(), path)
	case st.Mode&0o022 != 0 && st.Mode&unix.S_ISVTX == 0:
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is writable by group or others (mode %#o) without the sticky bit, so another user could replace tego's directory in it; %s must be root's and not writable by group or others",
			ErrRuntimeDirUnsafe, path, st.Mode&0o7777, path)
	}
	return fd, nil
}

// checkDirFD refuses a directory, held open, that is not this euid's or that group or others can write.
func checkDirFD(fd *sys.FD, path string) error {
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		return fmt.Errorf("runtime: stat %s: %w", path, err)
	}
	if int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is not a directory of uid %d that only it can write (mode %#o, owner %d); remove it",
			ErrRuntimeDirUnsafe, path, os.Geteuid(), st.Mode&0o7777, st.Uid)
	}
	return nil
}

// makeClientParent makes the client parent in the checked /run when it is absent, opens it without following a link,
// requires it to be this euid's and gives it clientDirMode, by descriptor.
func makeClientParent(runFD *sys.FD, parent string) (*sys.FD, error) {
	name := filepath.Base(parent)
	if err := runFD.Borrow(func(n int) error { return unix.Mkdirat(n, name, clientDirMode) }); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("runtime: create %s: %w", parent, err)
	}
	fd, err := runFD.Openat(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("runtime: open %s: %w", parent, err)
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("runtime: stat %s: %w", parent, err)
	}
	if int(st.Uid) != os.Geteuid() {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not %d; remove it", ErrRuntimeDirUnsafe, parent, st.Uid, os.Geteuid())
	}
	if err := fd.Borrow(func(n int) error { return unix.Fchmod(n, clientDirMode) }); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("runtime: chmod %s: %w", parent, err)
	}
	return fd, nil
}

// makeClientRunDir makes the run's directory under the checked parent, as runtimedir.go's makeRunRuntimeDir does a
// runtime directory, but through descriptors.
func makeClientRunDir(pfd *sys.FD, parent, id string) (*clientDir, error) {
	pending := runtimeDirPending + id
	if err := pfd.Borrow(func(n int) error { return unix.Mkdirat(n, pending, 0o700) }); err != nil {
		return nil, fmt.Errorf("runtime: create %s: %w", filepath.Join(parent, pending), err)
	}
	var dir, lock *sys.FD
	name := pending
	fail := func(err error) (*clientDir, error) {
		if dir != nil {
			_ = removeTreeAt(dir, 0)
			_ = dir.Close()
		}
		if lock != nil {
			_ = lock.Close()
		}
		_ = pfd.Borrow(func(n int) error { return unix.Unlinkat(n, name, unix.AT_REMOVEDIR) })
		return nil, fmt.Errorf("runtime: create %s: %w", filepath.Join(parent, id), err)
	}
	dir, err := pfd.Openat(pending, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return fail(err)
	}
	if err := checkDirFD(dir, filepath.Join(parent, pending)); err != nil {
		return fail(err)
	}
	lock, err = sys.Strict(dir.Openat(runtimeLockFile, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600))
	if err != nil {
		return fail(err)
	}
	if err := lock.Flock(unix.LOCK_EX | unix.LOCK_NB); err != nil {
		return fail(fmt.Errorf("lock: %w", err))
	}
	if err := pfd.Borrow(func(n int) error { return unix.Renameat2(n, pending, n, id, unix.RENAME_NOREPLACE) }); err != nil {
		return fail(fmt.Errorf("rename %s to %s: %w", pending, id, err))
	}
	name = id
	if err := dir.Borrow(func(n int) error { return unix.Fchmod(n, clientDirMode) }); err != nil {
		return fail(err)
	}
	return &clientDir{path: filepath.Join(parent, id), id: id, parent: pfd, dir: dir, lock: lock}, nil
}

// sweepClientParent removes each run's directory under the parent, held open, whose launcher is gone: a failure
// costs the cleanup of that entry, never the launch, and is logged. A directory counts as gone when it is this euid's,
// nobody can write it but its owner, and nobody holds the flock on its lock file (the kernel drops a dead process's).
// A `.new-<run id>` directory, which a launcher that died between its mkdir and its rename leaves, is taken by the same
// proof when it has a lock file; with none yet it is taken when it is older than clientPendingStale.
func sweepClientParent(pfd *sys.FD, parent string, log *slog.Logger) {
	names, err := clientDirNames(pfd)
	if err != nil {
		log.Warn("runtime: sweep client directory", "dir", parent, "err", err)
		return
	}
	for _, name := range names {
		pending := strings.HasPrefix(name, runtimeDirPending)
		if !ledger.IsRunID(strings.TrimPrefix(name, runtimeDirPending)) {
			continue
		}
		if removed, err := removeDeadClientDir(pfd, name, pending); err != nil {
			log.Warn("runtime: sweep client directory", "dir", filepath.Join(parent, name), "err", err)
		} else if removed {
			log.Info("runtime: removed the client directory of a run whose launcher is gone", "dir", filepath.Join(parent, name))
		}
	}
}

// removeDeadClientDir is sweepClientParent's test of one entry and its removal; it removes nothing and reports no
// error for a live run's directory.
func removeDeadClientDir(pfd *sys.FD, name string, pending bool) (bool, error) {
	var st unix.Stat_t
	if err := pfd.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return false, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || int(st.Uid) != os.Geteuid() || st.Mode&0o022 != 0 {
		return false, fmt.Errorf("%w: %s is not a directory of uid %d that only it can write", ErrRuntimeDirUnsafe, name, os.Geteuid())
	}
	dir, err := pfd.Openat(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = dir.Close() }()
	lock, err := sys.Strict(dir.Openat(runtimeLockFile, unix.O_RDWR|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	switch {
	case errors.Is(err, unix.ENOENT):
		if !pending || time.Since(time.Unix(st.Mtim.Unix())) < clientPendingStale {
			return false, nil // a directory with no lock yet: its launcher may be about to make it
		}
	case err != nil:
		return false, err
	default:
		defer func() { _ = lock.Close() }()
		var ls unix.Stat_t
		if err := lock.Fstat(&ls); err != nil {
			return false, err
		}
		if ls.Mode&unix.S_IFMT != unix.S_IFREG {
			return false, fmt.Errorf("%s/%s is not a regular file", name, runtimeLockFile)
		}
		if err := lock.Flock(unix.LOCK_EX | unix.LOCK_NB); err != nil {
			if errors.Is(err, unix.EWOULDBLOCK) {
				return false, nil // its launcher lives
			}
			return false, err
		}
	}
	// The lock, when there is one, is held until the removal is done, so a second sweep meeting the entry leaves it.
	if err := removeTreeAt(dir, 0); err != nil {
		return false, err
	}
	return true, pfd.Borrow(func(n int) error { return unix.Unlinkat(n, name, unix.AT_REMOVEDIR) })
}

// clientDirNames lists the entries of the directory fd holds, through a new open file description of it (so no read offset
// is shared with another user of the descriptor).
func clientDirNames(fd *sys.FD) ([]string, error) {
	rd, err := fd.Openat(".", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f, err := rd.Release("directory")
	if err != nil {
		_ = rd.Close()
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return f.Readdirnames(-1)
}

// clientTreeDepth bounds removeTreeAt: a client directory holds files, so anything deeper was not made by tego.
const clientTreeDepth = 4

// removeTreeAt removes every entry of the directory fd holds, by name through fd and without following a link;
// a directory in it is opened without following one and emptied first. The directory itself stays, for its owner to
// unlink from its parent.
func removeTreeAt(fd *sys.FD, depth int) error {
	names, err := clientDirNames(fd)
	if err != nil {
		return err
	}
	var errs []error
	for _, name := range names {
		var st unix.Stat_t
		if err := fd.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
			errs = append(errs, err)
			continue
		}
		flags := 0
		if st.Mode&unix.S_IFMT == unix.S_IFDIR {
			flags = unix.AT_REMOVEDIR
			if depth >= clientTreeDepth {
				errs = append(errs, fmt.Errorf("%s: nested too deep to be tego's", name))
				continue
			}
			child, err := fd.Openat(name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			if err := removeTreeAt(child, depth+1); err != nil {
				errs = append(errs, err)
			}
			_ = child.Close()
		}
		if err := fd.Borrow(func(n int) error { return unix.Unlinkat(n, name, flags) }); err != nil {
			errs = append(errs, fmt.Errorf("remove %s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}
