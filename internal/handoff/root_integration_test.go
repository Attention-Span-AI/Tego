// SPDX-License-Identifier: Apache-2.0

//go:build integration

package handoff

import (
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

// The root rows of the handoff (test/vm/root-suites.sh runs them as root in a KVM guest, CI's root-suites job under
// sudo). They skip as any other user.

// TestHandoffRefusesRootAsRoot: [control-as-root] at a real euid 0. Open, which reads this process's own euid, and a
// tego process at euid 0 both refuse before they open anything: a correctly pinned tego-control beside the caller is
// never opened (inotify sees no open in its directory) and never runs.
func TestHandoffRefusesRootAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: test/vm/root-suites.sh runs it")
	}
	dir := t.TempDir()
	pin := plant(t, dir)
	in, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Close(in) })
	if _, err := unix.InotifyAddWatch(in, dir, unix.IN_OPEN|unix.IN_ACCESS); err != nil {
		t.Fatal(err)
	}
	_, err = config{dir: dir, pin: pin, euid: os.Geteuid()}.open()
	wantCode(t, err, CodeAsRoot)
	_, err = Open()
	wantCode(t, err, CodeAsRoot)
	if out := runCallerAs(t, -1, dir, pin, ""); !strings.Contains(out, "open: ["+CodeAsRoot+"]") || strings.Contains(out, verified) {
		t.Fatalf("a tego at euid 0 printed %q, want the refusal [%s] and no tego-control", out, CodeAsRoot)
	}
	buf := make([]byte, 4096)
	if n, err := unix.Read(in, buf); n > 0 || !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("inotify read %d bytes (%v) from %s, want none: the refused handoff opened the file", n, err, dir)
	}
}

// TestHandoffRefusesNoexecMountAsRoot: a tego-control on a mount with MS_NOEXEC is [control-untrusted], read from the
// mount itself (fstatfs's ST_NOEXEC on the opened descriptor), and the same file on the same tmpfs remounted with exec
// allowed is opened, so the flag is what refuses it.
func TestHandoffRefusesNoexecMountAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: test/vm/root-suites.sh runs it")
	}
	dir := t.TempDir()
	if err := unix.Mount("tego-noexec", dir, "tmpfs", unix.MS_NOEXEC|unix.MS_NOSUID|unix.MS_NODEV, "mode=0755"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = unix.Unmount(dir, unix.MNT_DETACH) })
	pin := plant(t, dir)
	_, err := open(t, dir, pin)
	wantCode(t, err, CodeUntrusted)
	if !strings.Contains(err.Error(), "noexec") {
		t.Errorf("refusal %q does not name the noexec mount", err)
	}
	if err := unix.Mount("", dir, "", unix.MS_REMOUNT|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := open(t, dir, pin); err != nil {
		t.Fatalf("the same file with exec allowed: %v", err)
	}
}

// TestHandoffMemfdNoexecOnTheKernel: [memfd-noexec] from the kernel itself. In a new pid namespace (so the guest's
// own setting is untouched), the first process opens a planted tego-control, sets its namespace's vm.memfd_noexec to
// 2, under which memfd_create refuses MFD_EXEC with EACCES, and opens it again: the first open succeeds and the
// second is [memfd-noexec] with a fix whose command, `cat /proc/sys/vm/memfd_noexec`, shows the refusing 2 there. A
// kernel without the setting skips: mainline added it in 6.3 (AL2023's 6.1 has none), and distributions backport it
// (RHEL 9's 5.14 has it and runs this).
func TestHandoffMemfdNoexecOnTheKernel(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: test/vm/root-suites.sh runs it")
	}
	before, err := os.ReadFile(memfdNoexec)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("this kernel has no vm.memfd_noexec (mainline added it in 6.3; some distributions backport it)")
	}
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(before)) == "2" {
		t.Skipf("vm.memfd_noexec is 2 already here, so no executable memfd can be made to compare with")
	}
	dir := t.TempDir()
	pin := plant(t, dir)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(self)
	cmd.Env = append(os.Environ(), roleEnv+"="+roleNoexec, "TEGO_HANDOFF_TEST_DIR="+dir, "TEGO_HANDOFF_TEST_PIN="+pin)
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWPID}
	b, err := cmd.CombinedOutput()
	out := string(b)
	if err != nil {
		t.Fatalf("the namespace's process: %v: %s", err, out)
	}
	for _, want := range []string{"before: ok", "scope=2 ", "after: [" + CodeMemfdNoexec + "]", "`cat " + memfdNoexec + "`"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q, want %q", out, want)
		}
	}
	if after, err := os.ReadFile(memfdNoexec); err != nil || string(after) != string(before) {
		t.Fatalf("this namespace's vm.memfd_noexec is %q (%v) after the test, was %q: the setting leaked", after, err, before)
	}
}
