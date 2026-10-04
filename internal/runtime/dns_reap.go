// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/internal/runtime/dnsbroker"
	"golang.org/x/sys/unix"
)

func (d *dnsDirectory) captureSocket() error {
	var st unix.Stat_t
	if err := sys.FileDo(d.file, func(fd int) error {
		return unix.Fstatat(fd, dnsbroker.SocketName, &st, unix.AT_SYMLINK_NOFOLLOW)
	}); err != nil {
		return err
	}
	if st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Ino == 0 {
		return errors.New("DNS endpoint is not a socket")
	}
	d.socketDev, d.socketIno = uint64(st.Dev), st.Ino
	return nil
}

func validDNSDirectoryName(name string) bool {
	suffix, ok := strings.CutPrefix(name, "tego-dns-")
	if !ok || len(suffix) == 0 || len(suffix) > 10 {
		return false
	}
	for _, c := range suffix {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// cleanupReapDNS borrows only the two inherited descriptors. The caller has
// proved that the tree is empty before invoking it. No path outside the held
// root-owned /tmp parent and exact allocated leaf is walked or removed.
func cleanupReapDNS(spec reapSpec, dirFD, parentFD int) error {
	if !validDNSDirectoryName(spec.DNSName) || spec.DNSIno == 0 {
		return errors.New("invalid DNS cleanup identity")
	}
	var parent, actualParent, held, current, socket unix.Stat_t
	if err := unix.Fstat(parentFD, &parent); err != nil {
		return err
	}
	if err := unix.Fstatat(unix.AT_FDCWD, "/tmp", &actualParent, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return err
	}
	if parent.Mode&unix.S_IFMT != unix.S_IFDIR || parent.Dev != actualParent.Dev || parent.Ino != actualParent.Ino || parent.Uid != 0 || parent.Mode&0022 != 0 && parent.Mode&unix.S_ISVTX == 0 {
		return errors.New("DNS cleanup parent is not the verified /tmp directory")
	}
	if err := unix.Fstat(dirFD, &held); err != nil {
		return err
	}
	if held.Mode&unix.S_IFMT != unix.S_IFDIR || held.Uid != uint32(os.Geteuid()) || held.Mode&0022 != 0 {
		return errors.New("DNS cleanup directory is not owned by the reaper")
	}
	if err := unix.Fstatat(parentFD, spec.DNSName, &current, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		return err
	}
	if current.Mode&unix.S_IFMT != unix.S_IFDIR || current.Dev != held.Dev || current.Ino != held.Ino {
		return errors.New("DNS cleanup directory identity changed")
	}
	if err := unix.Fstatat(dirFD, dnsbroker.SocketName, &socket, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		if !errors.Is(err, unix.ENOENT) {
			return err
		}
	} else {
		if socket.Mode&unix.S_IFMT != unix.S_IFSOCK || uint64(socket.Dev) != spec.DNSDev || socket.Ino != spec.DNSIno {
			return errors.New("DNS cleanup socket identity changed")
		}
		if err := unix.Unlinkat(dirFD, dnsbroker.SocketName, 0); err != nil {
			return fmt.Errorf("unlink owned DNS socket: %w", err)
		}
	}
	return unix.Unlinkat(parentFD, spec.DNSName, unix.AT_REMOVEDIR)
}
