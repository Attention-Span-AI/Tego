// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strconv"
	"sync"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// DNS clients must use literal short Unix addresses: the supervisor correctly
// refuses procfd magic links supplied by a task. A private short directory is
// separate from the ledger. Root never trusts TMPDIR or XDG_RUNTIME_DIR here.
type dnsDirectory struct {
	parent, file         *os.File
	path, name           string
	socketDev, socketIno uint64
	once                 sync.Once
	err                  error
}

// newDNSDirectory makes the run's DNS socket directory under a verified /tmp. Both descriptors are born owners
// and released into the Files the struct keeps (ADR 0023 C9), which the reaper inherits as ExtraFiles.
func newDNSDirectory() (*dnsDirectory, error) {
	parent, err := sys.Own(unix.Open("/tmp", unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0))
	if err != nil {
		return nil, err
	}
	var st unix.Stat_t
	if err = parent.Fstat(&st); err != nil {
		_ = parent.Close()
		return nil, err
	}
	// A writable shared directory must be sticky and root-owned. Otherwise a
	// different user could replace a newly created runtime endpoint directory.
	if st.Uid != 0 || st.Mode&0022 != 0 && st.Mode&unix.S_ISVTX == 0 {
		_ = parent.Close()
		return nil, errors.New("DNS socket base /tmp is not a trusted root-owned directory")
	}
	var name string
	if err = parent.Borrow(func(n int) error {
		var err error
		name, err = mkdirTempAt(n, "tego-dns-", rand.Uint32)
		return err
	}); err != nil {
		_ = parent.Close()
		return nil, err
	}
	cleanup := func() {
		_ = parent.Borrow(func(n int) error { return unix.Unlinkat(n, name, unix.AT_REMOVEDIR) })
		_ = parent.Close()
	}
	if os.Geteuid() == 0 {
		// Root retains ownership; the target may search but never replace the
		// directory under sticky /tmp. The socket itself is target-UID 0600.
		if err = parent.Borrow(func(n int) error { return unix.Fchmodat(n, name, 0711, 0) }); err != nil {
			cleanup()
			return nil, err
		}
	}
	dir, err := parent.Openat(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		cleanup()
		return nil, err
	}
	path := filepath.Join("/tmp", name)
	file, err := dir.Release(path)
	if err != nil {
		_ = dir.Close()
		cleanup()
		return nil, err
	}
	pfile, err := parent.Release("/tmp")
	if err != nil {
		_ = file.Close()
		cleanup()
		return nil, err
	}
	return &dnsDirectory{parent: pfile, file: file, path: path, name: name}, nil
}

// mkdirTempAt is os.MkdirTemp beneath the directory dirfd names: a new 0700 directory named prefix and a number
// from next (rand.Uint32; a test's sequence), made with mkdirat so the name resolves against the verified directory
// and no path, and retried on a name already taken, at most mkdirTempTries times. It returns the name.
func mkdirTempAt(dirfd int, prefix string, next func() uint32) (string, error) {
	for range mkdirTempTries {
		name := prefix + strconv.FormatUint(uint64(next()), 10)
		err := unix.Mkdirat(dirfd, name, 0o700)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, unix.EEXIST) {
			return "", fmt.Errorf("mkdir %s in /tmp: %w", name, err)
		}
	}
	return "", errors.New("mkdir in /tmp: too many names taken")
}

// mkdirTempTries bounds mkdirTempAt's retries, as os.MkdirTemp's own bound does.
const mkdirTempTries = 10000

// Close removes only the empty directory with the identity this run created.
// A foreign replacement is preserved, and owned descriptors close regardless.
func (d *dnsDirectory) Close() error {
	d.once.Do(func() {
		var held unix.Stat_t
		err := sys.FstatFile(d.file, &held)
		if err == nil {
			err = sys.FileDo(d.parent, func(n int) error {
				var current unix.Stat_t
				if err := unix.Fstatat(n, d.name, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
					return err
				}
				if current.Dev != held.Dev || current.Ino != held.Ino {
					return errors.New("DNS socket directory identity changed")
				}
				return unix.Unlinkat(n, d.name, unix.AT_REMOVEDIR)
			})
		}
		if errors.Is(err, os.ErrNotExist) {
			err = nil
		}
		d.err = errors.Join(err, d.file.Close(), d.parent.Close())
	})
	return d.err
}
