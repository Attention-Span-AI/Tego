// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"runtime"
	"syscall"

	"github.com/attention-span-ai/tego/internal/platform/proc"
	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// foregroundGuideLogin gives the login its own cancellable group and the controlling terminal.
// Foreground makes the child's tcsetpgrp happen before exec, so its first read cannot receive SIGTTIN.
func foregroundGuideLogin(c *proc.Cmd) (func() error, error) {
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	restore := func() error { resetTerminal(); return nil }
	err := sys.FileDo(os.Stdin, func(fd int) error {
		group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
		if errors.Is(err, unix.ENOTTY) {
			return nil
		}
		if err != nil {
			return err
		}
		modes, err := unix.IoctlGetTermios(fd, unix.TCGETS)
		if err != nil {
			return err
		}
		// The CLI inherits its controlling terminal on standard input (descriptor 0).
		// Leave Ctty at that standard descriptor; do not retain a borrowed descriptor number.
		c.SysProcAttr.Foreground = true
		restore = func() error {
			return sys.FileDo(os.Stdin, func(fd int) error {
				// The guide is temporarily in the background. Block SIGTTOU on this thread only while
				// reclaiming the terminal, preserving the process's signal handlers and the thread's mask.
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()
				var block, old unix.Sigset_t
				block.Val[0] = 1 << (uint(syscall.SIGTTOU) - 1)
				if err := unix.PthreadSigmask(unix.SIG_BLOCK, &block, &old); err != nil {
					return err
				}
				defer func() { _ = unix.PthreadSigmask(unix.SIG_SETMASK, &old, nil) }()
				if err := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, group); err != nil {
					return err
				}
				resetTerminal()
				return unix.IoctlSetTermios(fd, unix.TCSETS, modes)
			})
		}
		return nil
	})
	return restore, err
}
