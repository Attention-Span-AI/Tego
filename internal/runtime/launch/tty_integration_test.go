// SPDX-License-Identifier: Apache-2.0

//go:build integration

package launch

import (
	"errors"
	"os"
	"os/exec"
	goruntime "runtime"
	"strconv"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"golang.org/x/sys/unix"
)

// TestAgentCannotReadOtherPty checks the actual domain, including a terminal
// made after the ruleset: a broad write grant in another layer cannot reopen it.
func TestAgentCannotReadOtherPty(t *testing.T) {
	if p := os.Getenv("TEGO_C40_OTHER_PTY"); p != "" {
		goruntime.LockOSThread()
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		rs, err := ttyRuleset()
		if err != nil {
			t.Fatal(err)
		}
		defer rs.Close() //nolint:errcheck // owned test ruleset
		if err := rs.Borrow(func(fd int) error { return sys.RestrictSelf(fd, 0) }); err != nil {
			t.Fatal(err)
		}
		for _, flags := range []int{unix.O_RDONLY, unix.O_WRONLY, unix.O_RDWR | unix.O_NOCTTY} {
			fd, err := unix.Open(p, flags, 0)
			if fd >= 0 {
				_ = unix.Close(fd)
			}
			if !errors.Is(err, unix.EACCES) {
				t.Errorf("other pty open flags %#x: %v, want EACCES", flags, err)
			}
		}
		master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(master) //nolint:errcheck // test pty
		if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
			t.Fatal(err)
		}
		idx, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.Open("/dev/pts/"+strconv.Itoa(idx), unix.O_RDONLY|unix.O_NOCTTY, 0)
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("a slave made after the ruleset was granted by path: %v", err)
		}
		// The relay's primitive gets this master's slave without a pathname.
		slave, _, e := unix.Syscall(unix.SYS_IOCTL, uintptr(master), unix.TIOCGPTPEER, unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC)
		if e != unix.EACCES {
			if e == 0 {
				_ = unix.Close(int(slave))
			}
			t.Fatalf("TIOCGPTPEER in the domain: %v, want EACCES (the supervisor must install it)", e)
		}
		return
	}
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(master) //nolint:errcheck // test pty
	if err := unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, 0); err != nil {
		t.Fatal(err)
	}
	idx, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		t.Fatal(err)
	}
	p := "/dev/pts/" + strconv.Itoa(idx)
	fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOCTTY, 0)
	if err != nil {
		t.Fatalf("unconfined control: %v", err)
	}
	_ = unix.Close(fd)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAgentCannotReadOtherPty$", "-test.v")
	cmd.Env = append(os.Environ(), "TEGO_C40_OTHER_PTY="+p)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("confined terminal test: %v\n%s", err, out)
	}
}
