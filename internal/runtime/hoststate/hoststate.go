// SPDX-License-Identifier: Apache-2.0

// Package hoststate is the root tiers' host-wide state directory, /run/tego (ADR 0034): the build locks and
// the slot tables every launcher of a build shares, so that "last out" and slot uniqueness are true across the
// whole host. The tier-2 backend kept them in the first of /run/tego, $XDG_RUNTIME_DIR/tego and
// /tmp/tego-<uid> it could write, with no owner or symlink check: a file-capability launcher cannot write a
// root-owned /run/tego and always fell back, so two users' launchers of one build held two lock files and two
// slot tables, could each judge themselves last out and unpin under the other's live run, and could be handed
// the same run_idx.
//
// There is no fallback now. Open verifies /run/tego and refuses anything else with ErrHostState, and every
// file in it is opened relative to the verified descriptor, never by path. Only a root launcher uses it (ADR
// 0042 (2)): the root:tego 1770 form ADR 0034 provisioned for a file-capability copy is withdrawn (ADR 0042
// (3)(b)), since no launcher used it and it handed root's slot tables and locks to every group member.
package hoststate

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// Path is the host state directory.
const Path = "/run/tego"

// ErrHostState is wrapped when the host state directory is not one tego can trust.
var ErrHostState = errors.New("hoststate: the host state directory cannot be trusted")

// Fix is the one line that makes Path trusted again, which doctor and the refusal print. A root launcher creates
// the directory root 0700 itself when it is absent, and /run is root's, so no one else can create the name
// first; a directory there of any other form was made by hand (ADR 0042 (3)(b)).
const Fix = "/run/tego must be root 0700: `chmod 0700 /run/tego && chgrp root /run/tego`, and remove any tego tmpfiles.d line (ADR 0042)"

// Dir is a verified state directory, held open by its descriptor's owner (ADR 0023): Close closes it once, and
// every use after a Close answers sys.ErrClosed.
type Dir struct {
	fd   *sys.FD
	path string
}

// Open opens Path, verified (ADR 0034 item 2 as ADR 0042 (3)(b) narrows it): a directory, not a symbolic link,
// owned by root, mode 0700 (created so when absent and this process is root). Anything else fails with
// ErrHostState and Fix, the withdrawn root:tego 1770 form included.
func Open() (*Dir, error) { return openHost(Path) }

// openHost is Open for a directory at path, which tests give.
func openHost(path string) (*Dir, error) {
	fd, err := openDir(path)
	if errors.Is(err, unix.ENOENT) && os.Geteuid() == 0 {
		if merr := unix.Mkdir(path, 0o700); merr != nil && !errors.Is(merr, unix.EEXIST) {
			return nil, fmt.Errorf("%w: create %s: %w", ErrHostState, path, merr)
		}
		fd, err = openDir(path)
	}
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: fstat %s: %w", ErrHostState, path, err)
	}
	d := &Dir{fd: fd, path: path}
	if err := d.verifyHost(st); err != nil {
		_ = fd.Close()
		return nil, err
	}
	return d, nil
}

// verifyHost is Open's check of the directory's owner and mode. The group is not read: with mode 0700 it grants
// nothing.
func (d *Dir) verifyHost(st unix.Stat_t) error {
	perm := st.Mode & 0o7777
	switch {
	case st.Mode&unix.S_IFMT != unix.S_IFDIR:
		return fmt.Errorf("%w: %s is not a directory", ErrHostState, d.path)
	case st.Uid != 0:
		return fmt.Errorf("%w: %s is owned by uid %d, not root; %s", ErrHostState, d.path, st.Uid, Fix)
	case perm == 0o700:
		return nil
	}
	return fmt.Errorf("%w: %s is mode %#o, want 0700; %s", ErrHostState, d.path, perm, Fix)
}

// OpenAt opens path as a state directory the caller chose itself (the tier-2 backend's Options.StateDir, which
// tests set): a directory, not a symbolic link, and not writable by everyone unless sticky. Its owner and group
// are the caller's to choose; a file in it is still opened only as a regular file and never through a link.
func OpenAt(path string) (*Dir, error) {
	fd, err := openDir(path)
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: fstat %s: %w", ErrHostState, path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR || (st.Mode&0o002 != 0 && st.Mode&unix.S_ISVTX == 0) {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is mode %#o: a directory everyone can write", ErrHostState, path, st.Mode&0o7777)
	}
	return &Dir{fd: fd, path: path}, nil
}

// openDir opens path O_PATH|O_DIRECTORY|O_NOFOLLOW. O_DIRECTORY|O_NOFOLLOW refuses a symbolic link as ENOTDIR.
func openDir(path string) (*sys.FD, error) {
	fd, err := sys.Own(unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: open %s: %w", ErrHostState, path, err)
	}
	return fd, nil
}

// Path returns the directory's path, for messages.
func (d *Dir) Path() string { return d.path }

// OpenFile opens name, one path component, relative to the verified directory: never through a symbolic link,
// only a regular file, and only one this process's effective uid owns (ADR 0042 (3)(b)). The owner check is
// defence in depth: it closes the "create the name first" class (a slot table or lock planted before the launcher
// made it) even if the directory check ever lets a writer in. A lock file is unlinked only by its holder, and
// only a build's that is gone (internal/runtime/enforce/cgroup's removeStaleState), which every taker of a build
// lock checks for once it holds it; the rest tmpfs clears at boot.
func (d *Dir) OpenFile(name string, flags int, perm uint32) (*os.File, error) {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return nil, fmt.Errorf("%w: %q is not a file name", ErrHostState, name)
	}
	full := filepath.Join(d.path, name)
	fd, err := d.fd.Openat(name, flags|unix.O_NOFOLLOW|unix.O_CLOEXEC|unix.O_NONBLOCK, perm)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	var st unix.Stat_t
	if err := fd.Fstat(&st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is not a regular file", ErrHostState, full)
	}
	if euid := os.Geteuid(); int(st.Uid) != euid {
		_ = fd.Close()
		return nil, fmt.Errorf("%w: %s is owned by uid %d, not this process's uid %d", ErrHostState, full, st.Uid, euid)
	}
	f, err := fd.Release(full)
	if err != nil {
		_ = fd.Close()
		return nil, &os.PathError{Op: "open", Path: full, Err: err}
	}
	return f, nil
}

// Unlink removes name, one path component, from the verified directory.
func (d *Dir) Unlink(name string) error {
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return fmt.Errorf("%w: %q is not a file name", ErrHostState, name)
	}
	if err := d.fd.Borrow(func(n int) error { return unix.Unlinkat(n, name, 0) }); err != nil {
		return &os.PathError{Op: "unlink", Path: filepath.Join(d.path, name), Err: err}
	}
	return nil
}

// Names reports whether name, in the verified directory, still leads to the file f holds: false once it was
// removed or given to another file.
func (d *Dir) Names(name string, f *os.File) bool {
	var held, named unix.Stat_t
	if sys.FstatFile(f, &held) != nil {
		return false
	}
	if d.fd.Fstatat(name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return false
	}
	return held.Dev == named.Dev && held.Ino == named.Ino
}

// Stat stats name, one path component, relative to the verified directory and without following a symbolic link
// (fstatat AT_SYMLINK_NOFOLLOW): the file the verified directory holds, never one its path names after a rename.
// An error for a missing name wraps os.ErrNotExist.
func (d *Dir) Stat(name string) (unix.Stat_t, error) {
	var st unix.Stat_t
	if name == "" || name == "." || name == ".." || strings.Contains(name, "/") {
		return st, fmt.Errorf("%w: %q is not a file name", ErrHostState, name)
	}
	if err := d.fd.Fstatat(name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return st, &os.PathError{Op: "stat", Path: filepath.Join(d.path, name), Err: err}
	}
	return st, nil
}

// Dup is a second Dir on the directory d holds, with its own descriptor (close-on-exec) and d's verification,
// for an owner that closes what it is given: never a reopen by path, which would verify nothing again.
func (d *Dir) Dup() (*Dir, error) {
	fd, err := d.fd.Dup()
	if err != nil {
		return nil, fmt.Errorf("%w: duplicate the descriptor of %s: %w", ErrHostState, d.path, err)
	}
	return &Dir{fd: fd, path: d.path}, nil
}

// Close closes the directory's descriptor once: a later Close, or one racing it, is a no-op.
func (d *Dir) Close() error {
	if d == nil {
		return nil
	}
	return d.fd.Close()
}
