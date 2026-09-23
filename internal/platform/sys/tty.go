// SPDX-License-Identifier: Apache-2.0

package sys

import "golang.org/x/sys/unix"

// IsTerminal reports whether fd refers to a terminal (ioctl TCGETS succeeds). The launcher uses it on
// stdin to decide whether terminal-generated SIGINT/SIGQUIT already reached the agent's process group.
func IsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
