// SPDX-License-Identifier: Apache-2.0

package ui

import "golang.org/x/sys/unix"

// The ioctls that read and set a terminal's mode on macOS (the BSD names; Linux's are in termios_linux.go).
const (
	ioctlGetTermios = unix.TIOCGETA
	ioctlSetTermios = unix.TIOCSETA
)
