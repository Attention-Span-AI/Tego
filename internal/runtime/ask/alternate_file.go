// SPDX-License-Identifier: Apache-2.0

package ask

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// AlternateFile is the file a person names as an alternate (ADR 0057 D2), held by a descriptor from the moment
// they name it. Its identity is fixed there: `tego alternate` opens the path in the person's own process with no
// symbolic link anywhere on the way (OpenAlternateFile) and passes the descriptor to the broker over the socket
// (SCM_RIGHTS), and the broker and the supervisor only ever use that descriptor, never the path again. The
// supervisor runs outside the agent's Landlock domain with the person's full identity at tier 1, so a path it
// resolved itself, after the person named it, could be steered by the agent (a directory it renamed, a symbolic
// link it swapped in) to a file the agent could never open: a confused deputy. A descriptor cannot be steered.
//
// The descriptor is an *os.File so that a Close racing a use is safe: Control holds it against Close, and a use
// after Close fails rather than reaching whatever file a reused descriptor number names by then.
type AlternateFile struct {
	f *os.File
	// Named is the path the person's command named the file by: the kernel's name for the descriptor in the
	// command's view (an absolute, clean path; ValidAlternate). It is shown to the person; the record names the
	// file by the supervisor's own reading of the descriptor (Decision.Alternate).
	Named string
	// Dev and Ino are the file's identity as the broker received it (fstat), which the answer line records.
	Dev, Ino uint64
}

// ErrAlternateSymlink is an alternate path with a symbolic link in it: refused, since a link is what an agent can
// swap between the person's look and the open. The person names the file by the path it resolves to.
var ErrAlternateSymlink = errors.New("ask: an alternate is named by a path with no symbolic link in it")

// OpenAlternateFile opens path as the person's alternate, in the calling process: O_PATH, the final component not
// followed, and openat2 RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS, so no symbolic link and no /proc magic link is
// followed anywhere on the way (ErrAlternateSymlink names the path it resolves to, for the person to name). A
// relative path is taken from the calling process's directory. The file must be a regular file; every other check
// is the supervisor's, made on the descriptor.
func OpenAlternateFile(path string) (*AlternateFile, error) {
	if path == "" {
		return nil, fmt.Errorf("%w: an alternate names a file", ErrProtocol)
	}
	how := unix.OpenHow{Flags: unix.O_PATH | unix.O_NOFOLLOW | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS}
	var fd int
	var err error
	for tries := 0; ; tries++ {
		fd, err = unix.Openat2(unix.AT_FDCWD, path, &how)
		if (err == unix.EAGAIN && tries < 8) || err == unix.EINTR {
			continue
		}
		break
	}
	if err == nil {
		// O_NOFOLLOW with O_PATH opens a final symbolic link itself rather than failing.
		var st unix.Stat_t
		if e := unix.Fstat(fd, &st); e == nil && st.Mode&unix.S_IFMT == unix.S_IFLNK {
			_ = unix.Close(fd)
			err = unix.ELOOP
		}
	}
	if errors.Is(err, unix.ELOOP) {
		hint := ""
		if real, e := filepath.EvalSymlinks(path); e == nil && real != path {
			hint = " (it resolves to " + strconv.Quote(real) + " now; check that file, then name it)"
		}
		return nil, fmt.Errorf("%w: %s%s", ErrAlternateSymlink, strconv.Quote(path), hint)
	}
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	a, err := newAlternateFile(fd)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", strconv.Quote(path), err)
	}
	named, err := fdPath(a)
	if err != nil || !ValidAlternate(named) {
		_ = a.Close()
		if err == nil {
			err = fmt.Errorf("its path %s is not one a person can be shown (absolute, clean, no control character, at most %d bytes)", strconv.Quote(named), MaxAlternate)
		}
		return nil, fmt.Errorf("%s: %w", strconv.Quote(path), err)
	}
	a.Named = named
	return a, nil
}

// newAlternateFile takes ownership of fd, which must be a regular file, and reads its identity.
func newAlternateFile(fd int) (*AlternateFile, error) {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return nil, err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return nil, errors.New("not a regular file")
	}
	return &AlternateFile{f: os.NewFile(uintptr(fd), "alternate"), Dev: uint64(st.Dev), Ino: st.Ino}, nil //nolint:unconvert // Dev is uint32 on some arches
}

// fdPath is the kernel's name for a's descriptor in this process's view.
func fdPath(a *AlternateFile) (string, error) {
	var name string
	err := a.Control(func(fd int) error {
		buf := make([]byte, unix.PathMax)
		n, err := unix.Readlink("/proc/self/fd/"+strconv.Itoa(fd), buf)
		if err != nil {
			return err
		}
		if n >= len(buf) {
			return unix.ENAMETOOLONG
		}
		name = string(buf[:n])
		return nil
	})
	return name, err
}

// Control runs fn with a's descriptor, held open against a concurrent Close for fn's duration. A closed (or nil)
// AlternateFile runs nothing and returns an error.
func (a *AlternateFile) Control(fn func(fd int) error) error {
	if a == nil || a.f == nil {
		return os.ErrClosed
	}
	raw, err := a.f.SyscallConn()
	if err != nil {
		return err
	}
	var inner error
	if err = raw.Control(func(fd uintptr) { inner = fn(int(fd)) }); err != nil {
		return err
	}
	return inner
}

// Dup is a second AlternateFile for the same open file description, which the caller owns and closes.
func (a *AlternateFile) Dup() (*AlternateFile, error) {
	var nfd int
	err := a.Control(func(fd int) error {
		var e error
		nfd, e = unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		return e
	})
	if err != nil {
		return nil, err
	}
	return &AlternateFile{f: os.NewFile(uintptr(nfd), "alternate"), Named: a.Named, Dev: a.Dev, Ino: a.Ino}, nil
}

// Close closes a's descriptor; nil and an already closed AlternateFile are fine.
func (a *AlternateFile) Close() error {
	if a == nil || a.f == nil {
		return nil
	}
	err := a.f.Close()
	if errors.Is(err, os.ErrClosed) {
		return nil
	}
	return err
}
