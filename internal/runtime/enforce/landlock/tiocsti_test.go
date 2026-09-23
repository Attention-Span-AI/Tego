// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"os"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TestFilterRefusesTerminalInjection installs the real filter on a thread and tries the escape.
//
// An agent inherits the launcher's stdio, which on an interactive run is the user's own terminal.
// ioctl(TIOCSTI) writes a byte into that terminal's input queue and the shell reading it runs whatever
// was written, as the user, outside every boundary the run installs. That is CVE-2017-5226 against
// bubblewrap, and the reason flatpak, firejail and snap all refuse it. Landlock has no view of ioctl and
// the supervisor's filesystem answers are advisory, so this filter is tier 1's only chance to stop it.
//
// The thread is poisoned by the filter and never unlocked, so the Go runtime destroys it with the
// goroutine rather than handing it back to the pool.
func TestFilterRefusesTerminalInjection(t *testing.T) {
	prog, err := assembleFilter(NativeArch(), filterOpts{full: false, abi: minTruncateABI})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}

	type result struct {
		tiocsti, tioclinux, benign error
		installed                  bool
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // deliberately never unlocked: the filter cannot be removed
		var out result

		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			done <- out
			return
		}
		// The filter's notify arms need no listener here: nothing this test calls is notified, and a
		// notified syscall with no listener would simply get ENOSYS.
		if err := setFilterNoListener(prog); err != nil {
			done <- out
			return
		}
		out.installed = true

		var b byte = 'x'
		_, _, e1 := unix.Syscall(unix.SYS_IOCTL, 0, ioctlTIOCSTI, uintptr(unsafe.Pointer(&b)))
		out.tiocsti = errnoOrNil(e1)
		_, _, e2 := unix.Syscall(unix.SYS_IOCTL, 0, ioctlTIOCLINUX, uintptr(unsafe.Pointer(&b)))
		out.tioclinux = errnoOrNil(e2)
		// A benign ioctl must still reach the kernel, so the guard is not a blanket ioctl denial.
		var ws unix.Winsize
		_, _, e3 := unix.Syscall(unix.SYS_IOCTL, uintptr(os.Stdout.Fd()), unix.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
		out.benign = errnoOrNil(e3)

		done <- out
		runtime.Goexit()
	}()

	got := <-done
	if !got.installed {
		t.Skip("could not install a seccomp filter on this thread")
	}
	if !errors.Is(got.tiocsti, unix.EPERM) {
		t.Errorf("ioctl(TIOCSTI) returned %v, want EPERM: the terminal-injection escape is open", got.tiocsti)
	}
	if !errors.Is(got.tioclinux, unix.EPERM) {
		t.Errorf("ioctl(TIOCLINUX) returned %v, want EPERM", got.tioclinux)
	}
	// TIOCGWINSZ on a non-tty is ENOTTY or EINVAL; either means the filter let it through, which is the
	// point. EPERM would mean the guard had become a blanket refusal.
	if errors.Is(got.benign, unix.EPERM) {
		t.Errorf("an unrelated ioctl was refused with EPERM: the guard is too broad")
	}
}

func errnoOrNil(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

// setFilterNoListener installs prog with no user-notification listener, which is all this test needs.
func setFilterNoListener(prog []bpf.RawInstruction) error {
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0,
		uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		return errno
	}
	return nil
}
