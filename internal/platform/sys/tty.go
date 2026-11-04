// SPDX-License-Identifier: Apache-2.0

package sys

import "golang.org/x/sys/unix"

// IsTerminal reports whether fd refers to a terminal (ioctl TCGETS succeeds). The launcher uses it on
// stdin to decide whether terminal-generated SIGINT/SIGQUIT already reached the agent's process group.
func IsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}

// ControllingTTYDevice returns the device id of this process's controlling
// terminal, even with redirected stdin; zero means there is no terminal.
func ControllingTTYDevice() (uint64, error) {
	fd, err := Own(unix.Open("/dev/tty", unix.O_RDONLY|unix.O_NOCTTY|unix.O_CLOEXEC, 0))
	if err == unix.ENXIO || err == unix.ENODEV || err == unix.ENOENT {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer fd.Close() //nolint:errcheck // the ioctl returns no descriptor
	var n int
	err = fd.Borrow(func(num int) error {
		var e error
		n, e = unix.IoctlGetInt(num, unix.TIOCGDEV)
		return e
	})
	return uint64(uint32(n)), err
}
