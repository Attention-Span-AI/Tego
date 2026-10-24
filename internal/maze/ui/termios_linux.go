// SPDX-License-Identifier: Apache-2.0

package ui

import "golang.org/x/sys/unix"

// The ioctls that read and set a terminal's mode on Linux (macOS's are in termios_darwin.go).
const (
	ioctlGetTermios = unix.TCGETS
	ioctlSetTermios = unix.TCSETS
)
