// SPDX-License-Identifier: Apache-2.0

package launch

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// TTYRuleset builds ADR 0113's additional Landlock layer. Intersecting it with
// the ordinary contract keeps a grant on canonical /dev/pts from admitting
// another terminal. No directory grant covers /dev/pts or numeric consoles.
// Ordinary directories are granted recursively, so compile separately refuses
// write grants reaching devpts mounts at other paths. New slaves beneath the
// canonical /dev/pts receive no right from this snapshot either.
func ttyRuleset() (*sys.FD, error) {
	rights := uint64(unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE)
	abi, err := sys.LandlockABI()
	if err != nil {
		return nil, err
	}
	if abi >= 2 {
		rights |= unix.LANDLOCK_ACCESS_FS_REFER
	}
	if abi >= 5 {
		rights |= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
	}
	rs, err := sys.LandlockCreateRulesetFD(&sys.LandlockRulesetAttr{Handled_access_fs: rights})
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*sys.FD, error) { return nil, errors.Join(err, rs.Close()) }
	// REFER is implicitly denied by every layer that does not handle it.
	// This layer confines terminal I/O; the contract alone decides ordinary
	// links and renames. Grant REFER globally without granting terminal I/O.
	if abi >= 2 {
		root, err := sys.Own(unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0))
		if err != nil {
			return fail(err)
		}
		err = rs.AddLandlockPath(root, unix.LANDLOCK_ACCESS_FS_REFER)
		err = errors.Join(err, root.Close())
		if err != nil {
			return fail(err)
		}
	}
	grant := func(p string) error {
		f, err := sys.Own(unix.Open(p, unix.O_PATH|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0))
		if err != nil {
			return err
		}
		defer f.Close() //nolint:errcheck // O_PATH reference
		var st unix.Stat_t
		if err := f.Fstat(&st); err != nil {
			return err
		}
		if st.Mode&unix.S_IFMT == unix.S_IFLNK {
			return nil
		}
		allowed := rights &^ unix.LANDLOCK_ACCESS_FS_REFER
		if st.Mode&unix.S_IFMT != unix.S_IFDIR && st.Mode&unix.S_IFMT != unix.S_IFCHR && st.Mode&unix.S_IFMT != unix.S_IFBLK {
			allowed &^= unix.LANDLOCK_ACCESS_FS_IOCTL_DEV
		}
		return rs.AddLandlockPath(f, allowed)
	}
	roots, err := os.ReadDir("/")
	if err != nil {
		return fail(err)
	}
	for _, e := range roots {
		if e.Name() != "dev" {
			if err := grant("/" + e.Name()); err != nil {
				return fail(err)
			}
		}
	}
	devs, err := os.ReadDir("/dev")
	if err != nil {
		return fail(err)
	}
	for _, e := range devs {
		n := e.Name()
		if n == "pts" || numericTTY(n) {
			continue
		}
		if err := grant("/dev/" + n); err != nil {
			return fail(err)
		}
	}
	if err := grant("/dev/pts/ptmx"); err != nil {
		return fail(err)
	}
	// /dev/tty refers to this process's controlling terminal. TIOCGDEV gives
	// its device identity, including when stdin was redirected.
	rdev, err := sys.ControllingTTYDevice()
	if err != nil {
		return fail(err)
	}
	if rdev != 0 {
		pts, e := os.ReadDir("/dev/pts")
		if e != nil {
			return fail(e)
		}
		for _, d := range append(pts, devs...) {
			p := filepath.Join("/dev/pts", d.Name())
			if strings.HasPrefix(d.Name(), "tty") {
				p = filepath.Join("/dev", d.Name())
			}
			var st unix.Stat_t
			if unix.Stat(p, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFCHR && uint32(st.Rdev) == uint32(rdev) {
				if e := grant(p); e != nil {
					return fail(e)
				}
			}
		}
	}
	return rs, nil
}

func numericTTY(name string) bool {
	if !strings.HasPrefix(name, "tty") || len(name) == 3 {
		return false
	}
	for _, c := range name[3:] {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}
