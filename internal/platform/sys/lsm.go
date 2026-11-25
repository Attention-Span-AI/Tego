// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LSMListModules returns the complete active LSM IDs (Linux 6.8+). It does not
// infer inactivity from a denied syscall or a masked securityfs mount.
func LSMListModules() ([]uint64, error) {
	var ids [64]uint64
	size := uint32(len(ids) * 8)
	n, _, errno := unix.Syscall(unix.SYS_LSM_LIST_MODULES, uintptr(unsafe.Pointer(&ids[0])), uintptr(unsafe.Pointer(&size)), 0)
	if errno != 0 {
		return nil, fmt.Errorf("lsm_list_modules: %w", errno)
	}
	if n == 0 || n > uintptr(len(ids)) || size != uint32(n)*8 {
		return nil, fmt.Errorf("invalid LSM list size: count=%d bytes=%d", n, size)
	}
	return ids[:n], nil
}

// LSMListUnreadVia says, in words, why the active LSM list could not be read and what can be done, from what each way
// answered: syscallErr from lsm_list_modules(2) (Linux 6.8 and later; the error LSMListModules returned), fileErr from
// reading /sys/kernel/security/lsm, and the third way, the machine config's lsm.list_file: listFile is its path ("" when
// none is set) and listErr why it was not believed (its error already names the file). Tego refuses a held file open
// while the list is unread (the supervisor's held-label-unavailable): without the list it cannot tell which module labels
// the agent's task, and a label the completing process lacks could let the open succeed where the agent's own would
// not. A nil error means that way was not tried and is left out. The text says only what the errors show: ENOSYS is
// either a kernel older than 6.8 or a filter that hides the call, so it says both. When a file is named, what is wrong
// with it comes first in the remedy; when none is, the remedy says that a list can be handed in and how.
func LSMListUnreadVia(syscallErr, fileErr error, listFile string, listErr error) (why, remedy string) {
	var parts []string
	if syscallErr != nil {
		switch {
		case errors.Is(syscallErr, unix.ENOSYS):
			parts = append(parts, "lsm_list_modules(2) answered ENOSYS: this kernel is older than Linux 6.8, which added it, or a seccomp filter outside Tego hides it")
		case errors.Is(syscallErr, unix.EPERM), errors.Is(syscallErr, unix.EACCES):
			var en unix.Errno
			errors.As(syscallErr, &en)
			parts = append(parts, fmt.Sprintf("lsm_list_modules(2) was refused (%v): a seccomp filter outside Tego, such as Docker's default profile, blocks it", en))
		default:
			parts = append(parts, fmt.Sprintf("lsm_list_modules(2) failed (%v)", syscallErr))
		}
	}
	if fileErr != nil {
		switch {
		case errors.Is(fileErr, unix.ENOENT), errors.Is(fileErr, fs.ErrNotExist):
			parts = append(parts, "/sys/kernel/security/lsm is not there (securityfs is not mounted in this container or mount namespace)")
		case errors.Is(fileErr, unix.EACCES), errors.Is(fileErr, unix.EPERM), errors.Is(fileErr, fs.ErrPermission):
			parts = append(parts, "/sys/kernel/security/lsm was refused (permission denied): a security policy blocks it, as Docker's docker-default AppArmor profile does")
		default:
			parts = append(parts, fmt.Sprintf("/sys/kernel/security/lsm could not be read (%v)", fileErr))
		}
	}
	if listErr != nil {
		parts = append(parts, listErr.Error())
	}
	why = strings.Join(parts, "; ")
	switch {
	case syscallErr != nil && errors.Is(syscallErr, unix.ENOSYS):
		remedy = "on a kernel older than 6.8 only the file can answer: expose a readable /sys/kernel/security/lsm in the container, or run on a host kernel 6.8 or later and permit lsm_list_modules in the outer seccomp filter"
	default:
		remedy = "permit lsm_list_modules in the outer seccomp filter (Linux 6.8 and later) or expose a readable /sys/kernel/security/lsm in the container"
	}
	if listFile != "" {
		return why, "make the list file " + listFile + " what the entrypoint writes at each start (it is refused for the reason above; an entrypoint that cannot read the list itself needs the container settings of examples/container/compose.yaml, or a read-only bind of the host's /sys/kernel/security/lsm); or " + remedy
	}
	return why, remedy + "; or hand the list in from where it can be read: the image's tego-entrypoint writes it as root before it drops its privileges and /etc/tego/config.yaml names it (lsm.list_file), or bind the host's /sys/kernel/security/lsm read-only into the container and name that path"
}
