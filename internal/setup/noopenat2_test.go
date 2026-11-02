// SPDX-License-Identifier: Apache-2.0

package setup

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

// noOpenat2Env makes the test binary re-exec itself under openat2Filter, answering openat2 with the errno it holds.
const noOpenat2Env = "TEGO_SETUP_NO_OPENAT2_HELPER"

// The helper's statuses when it stops before the run under the filter, as internal/platform/sys's
// TestKernelWithoutPidfdThreadHelper has them. Each exit first names the step and its error on stderr.
const (
	// exitNoFilter: this host would not let the helper set no_new_privs, install the filter or re-exec itself.
	// Nothing was measured, so the parent skips.
	exitNoFilter = 7
	// exitFilterBroken: the filter did not answer openat2 with the errno, or refused open too: a bug in this file,
	// so the parent fails rather than skip the only run of the code that stands in for openat2.
	exitFilterBroken = 8
)

// withoutOpenat2Tests are this package's tests that make or remove folders. TestWithoutOpenat2 runs each again where
// openat2 is refused, and each must pass there as it passes here.
var withoutOpenat2Tests = []string{
	"TestApplyRefusesALinkSwappedInAfterTheCheck",
	"TestCreateMakesNothingThroughAFile",
	"TestCreateOutsideTheProject",
	"TestDraftCreatesNothingAndCompiles",
	"TestApplyRemovesWhatItMadeWhenTheSecondCompileRefuses",
	"TestRemoveNeverThroughALinkNorAFile",
}

// auditArch is the AUDIT_ARCH_* value of the running architecture, for the filter's arch guard.
func auditArch(t *testing.T) uint32 {
	switch runtime.GOARCH {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64
	default:
		t.Skipf("no audit arch for %s", runtime.GOARCH)
		return 0
	}
}

// openat2Filter answers openat2 with errno and allows every other call, as tego's own run filter answers it with
// ENOSYS at every tier (enforce-landlock R10), so a `tego init --preset` run inside a run meets it, and as a
// container's seccomp profile that predates openat2 answers it with EPERM. A call of another syscall ABI is allowed.
func openat2Filter(arch uint32, errno unix.Errno) []unix.SockFilter {
	return []unix.SockFilter{
		/* 0 */ {Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch
		/* 1 */ {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jf: 3},
		/* 2 */ {Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
		/* 3 */ {Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: unix.SYS_OPENAT2, Jf: 1},
		/* 4 */ {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(errno)},
		/* 5 */ {Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
}

// helperExit writes why the helper stops to stderr and exits with code.
func helperExit(code int, step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(code)
}

// TestWithoutOpenat2Helper is the re-exec step of TestWithoutOpenat2, not a test on its own. It installs
// openat2Filter on its locked thread, checks that openat2 is answered with the errno and open is not, and execs the
// test binary from that thread with withoutOpenat2Tests: a seccomp filter is per thread but survives execve, and
// every thread of the new image is cloned from the one that exec'd, so the whole run below meets the filter.
func TestWithoutOpenat2Helper(t *testing.T) {
	v := os.Getenv(noOpenat2Env)
	if v == "" {
		t.Skip("helper process for TestWithoutOpenat2")
	}
	runtime.LockOSThread() // the filter is this thread's, and this thread must be the one that execs
	n, err := strconv.Atoi(v)
	if err != nil {
		helperExit(exitFilterBroken, noOpenat2Env, err)
	}
	errno := unix.Errno(n)
	filter := openat2Filter(auditArch(t), errno)
	prog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		helperExit(exitNoFilter, "prctl(PR_SET_NO_NEW_PRIVS)", err)
	}
	if _, _, e := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0, uintptr(unsafe.Pointer(&prog))); e != 0 {
		helperExit(exitNoFilter, "seccomp(SECCOMP_SET_MODE_FILTER)", e)
	}
	if fd, err := unix.Openat2(unix.AT_FDCWD, "/", &unix.OpenHow{Flags: unix.O_PATH | unix.O_CLOEXEC}); !errors.Is(err, errno) {
		helperExit(exitFilterBroken, "openat2 under the filter, want "+unix.ErrnoName(errno), fmt.Errorf("fd %d, err %v", fd, err))
	}
	fd, err := unix.Open("/", unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		helperExit(exitFilterBroken, "open under the filter", err)
	}
	_ = unix.Close(fd)

	exe, err := os.Executable()
	if err != nil {
		helperExit(exitNoFilter, "os.Executable", err)
	}
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, noOpenat2Env+"=") {
			env = append(env, kv)
		}
	}
	err = syscall.Exec(exe, []string{exe, "-test.run=^(" + strings.Join(withoutOpenat2Tests, "|") + ")$", "-test.v",
		"-test.timeout=120s"}, env)
	helperExit(exitNoFilter, "execve("+exe+")", err)
}

// TestWithoutOpenat2 runs withoutOpenat2Tests where openat2 is refused, with ENOSYS as tego's own run filter refuses
// it (so `tego init --preset` inside a run failed with "function not implemented") and with EPERM as an older
// container profile does. Create and Remove then walk a component at a time with openat O_NOFOLLOW, and every test
// must pass there: a folder is made beneath the project folder, a link on the way is refused by name, and nothing
// is made or removed where it leads.
func TestWithoutOpenat2(t *testing.T) {
	auditArch(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, errno := range []unix.Errno{unix.ENOSYS, unix.EPERM} {
		t.Run(unix.ErrnoName(errno), func(t *testing.T) {
			cmd := exec.Command(exe, "-test.run=^TestWithoutOpenat2Helper$", "-test.timeout=150s")
			cmd.Env = append(os.Environ(), noOpenat2Env+"="+strconv.Itoa(int(errno)))
			out, err := cmd.CombinedOutput()
			var ee *exec.ExitError
			code := 0
			if errors.As(err, &ee) {
				code = ee.ExitCode()
			}
			switch code {
			case exitNoFilter:
				t.Skipf("this host would not let the helper refuse openat2:\n%s", out)
			case exitFilterBroken:
				t.Fatalf("the filter does not refuse openat2 alone, so nothing run under it would test the walk:\n%s", out)
			}
			if err != nil {
				t.Fatalf("the tests where openat2 is refused with %s: %v\n%s", unix.ErrnoName(errno), err, out)
			}
			for _, name := range withoutOpenat2Tests {
				if !bytes.Contains(out, []byte("--- PASS: "+name+" ")) {
					t.Errorf("%s did not pass where openat2 is refused with %s:\n%s", name, unix.ErrnoName(errno), out)
				}
			}
		})
	}
}
