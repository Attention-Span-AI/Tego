// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// auditArch is the AUDIT_ARCH_* value of the running architecture for a seccomp arch guard. Only
// little-endian architectures are listed, which withoutPidfdThreadFilter's argument offsets rely on.
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

// noPidfdThreadEnv makes the test binary re-exec itself under withoutPidfdThreadFilter.
const noPidfdThreadEnv = "TEGO_SYS_NO_PIDFD_THREAD_HELPER"

// offLeaderEnv, which the emulated run's environment carries, keeps the main thread for the main goroutine (init
// below), so that every test of that run runs on a thread that is not its thread group's leader, as the supervisor
// does for a notification an agent's worker thread raised. Below 6.9 only a leader's tid opens with the plain form,
// so a test that opens its own tid there fails on every run, not only when the scheduler happens to place it off the
// main thread (TestPidfdOwnerForms did, on a loaded machine, 2026-10-16).
const offLeaderEnv = "TEGO_SYS_TESTS_OFF_LEADER"

// init holds the main thread for the main goroutine under offLeaderEnv. It must be an init: only there is the main
// goroutine still on the main thread.
func init() {
	if os.Getenv(offLeaderEnv) != "" {
		runtime.LockOSThread()
	}
}

// The helper's statuses when it stops before the emulated run. Each exit first names the step and its error
// on stderr, which the parent prints, so neither a skip nor a failure loses its reason.
const (
	// exitEmulationUnavailable: this host would not let the helper set no_new_privs, install a seccomp
	// filter or re-exec itself. Nothing about the wrappers was measured, so the parent skips.
	exitEmulationUnavailable = 7
	// exitEmulationBroken: the filter did not assemble, or it answered a pidfd call differently from a
	// 5.14–6.8 kernel. That is a bug in this file, not a property of the host, so the parent fails: a skip
	// there would drop the only pre-6.9 coverage without turning anything red.
	exitEmulationBroken = 8
)

// emulationExit writes why the helper stops to stderr and exits with code.
func emulationExit(code int, step string, err error) {
	fmt.Fprintf(os.Stderr, "%s: %v\n", step, err)
	os.Exit(code)
}

// withoutPidfdThreadFilter makes this kernel answer the two pidfd flags Linux 6.9 introduced the way a
// 5.14–6.8 kernel does: pidfd_open with any flag but PIDFD_NONBLOCK, and pidfd_send_signal with any flag at
// all, fail EINVAL, the check both syscalls make first below 6.9. Only those flag answers are emulated.
// Every other call gets the running kernel's own answer, even where older kernels answer differently:
// plain pidfd_open on a tid that is not a thread-group leader still fails ENOENT here, where 5.14–6.8 say
// EINVAL. Calls from another syscall ABI are allowed untouched. A test run under it may therefore rely on
// those two EINVALs and on nothing else that differs below 6.9.
func withoutPidfdThreadFilter(arch uint32) ([]bpf.RawInstruction, error) {
	const (
		// seccomp_data.args[i] starts at 16+8*i; the flags are unsigned int, the low word on the
		// little-endian architectures auditArch admits.
		pidfdOpenFlags  = 16 + 8*1
		sendSignalFlags = 16 + 8*3
	)
	einval := unix.SECCOMP_RET_ERRNO | uint32(unix.EINVAL)
	return bpf.Assemble([]bpf.Instruction{
		/* 0 */ bpf.LoadAbsolute{Off: 4, Size: 4}, // seccomp_data.arch
		/* 1 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: arch, SkipFalse: 7},
		/* 2 */ bpf.LoadAbsolute{Off: 0, Size: 4}, // seccomp_data.nr
		/* 3 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SYS_PIDFD_OPEN, SkipFalse: 2},
		/* 4 */ bpf.LoadAbsolute{Off: pidfdOpenFlags, Size: 4},
		/* 5 */ bpf.JumpIf{Cond: bpf.JumpBitsSet, Val: ^uint32(unix.O_NONBLOCK), SkipTrue: 4, SkipFalse: 3},
		/* 6 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: unix.SYS_PIDFD_SEND_SIGNAL, SkipFalse: 2},
		/* 7 */ bpf.LoadAbsolute{Off: sendSignalFlags, Size: 4},
		/* 8 */ bpf.JumpIf{Cond: bpf.JumpEqual, Val: 0, SkipFalse: 1},
		/* 9 */ bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
		/* 10 */ bpf.RetConstant{Val: einval},
	})
}

// TestKernelWithoutPidfdThreadHelper is the re-exec step of TestKernelWithoutPidfdThread, not a test on its
// own. It installs withoutPidfdThreadFilter on its locked thread, checks the filter answers as a pre-6.9
// kernel would, and execs the test binary from that thread: a seccomp filter is per thread but survives
// execve, and every thread of the new image is cloned from the one that exec'd, so the whole run below sees
// the emulated kernel — including the helpers it spawns in turn.
func TestKernelWithoutPidfdThreadHelper(t *testing.T) {
	if os.Getenv(noPidfdThreadEnv) == "" {
		t.Skip("helper process for TestKernelWithoutPidfdThread")
	}
	runtime.LockOSThread() // the filter is this thread's, and this thread must be the one that execs
	prog, err := withoutPidfdThreadFilter(auditArch(t))
	if err != nil {
		emulationExit(exitEmulationBroken, "bpf.Assemble(withoutPidfdThreadFilter)", err)
	}
	filter := make([]unix.SockFilter, len(prog))
	for i, in := range prog {
		filter[i] = unix.SockFilter{Code: in.Op, Jt: in.Jt, Jf: in.Jf, K: in.K}
	}
	fprog := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	if err := SetNoNewPrivs(); err != nil {
		emulationExit(exitEmulationUnavailable, "prctl(PR_SET_NO_NEW_PRIVS)", err)
	}
	if _, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, 0,
		uintptr(unsafe.Pointer(&fprog))); errno != 0 {
		emulationExit(exitEmulationUnavailable, "seccomp(SECCOMP_SET_MODE_FILTER)", errno)
	}
	// A filter that let either flag through would make the run below a second 6.9+ run that proves
	// nothing about older kernels, and one that refused a call older kernels accept would fail wrappers
	// that are correct there, so the filter's answers are checked both ways before anything is judged.
	if fd, err := unix.PidfdOpen(os.Getpid(), PidfdThread); !errors.Is(err, unix.EINVAL) {
		emulationExit(exitEmulationBroken, "pidfd_open(self, PIDFD_THREAD) under the filter, want EINVAL",
			fmt.Errorf("fd %d, err %v", fd, err))
	}
	if fd, err := unix.PidfdOpen(os.Getpid(), unix.PIDFD_NONBLOCK); err != nil {
		emulationExit(exitEmulationBroken, "pidfd_open(self, PIDFD_NONBLOCK) under the filter", err)
	} else {
		unix.Close(fd)
	}
	self, err := unix.PidfdOpen(os.Getpid(), 0)
	if err != nil {
		emulationExit(exitEmulationBroken, "pidfd_open(self, 0) under the filter", err)
	}
	if err := unix.PidfdSendSignal(self, 0, nil, PidfdSignalThreadGroup); !errors.Is(err, unix.EINVAL) {
		emulationExit(exitEmulationBroken,
			"pidfd_send_signal(self, 0, PIDFD_SIGNAL_THREAD_GROUP) under the filter, want EINVAL", err)
	}
	if err := unix.PidfdSendSignal(self, 0, nil, 0); err != nil {
		emulationExit(exitEmulationBroken, "pidfd_send_signal(self, 0, 0) under the filter", err)
	}
	unix.Close(self)

	exe, err := os.Executable()
	if err != nil {
		emulationExit(exitEmulationUnavailable, "os.Executable", err)
	}
	env := []string{offLeaderEnv + "=1"}
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(kv, noPidfdThreadEnv+"=") && !strings.HasPrefix(kv, offLeaderEnv+"=") {
			env = append(env, kv)
		}
	}
	// ^Test(Pidfd|Poll) is every pidfd test in this package and cannot match TestKernelWithoutPidfdThread,
	// so the run below does not re-enter this one.
	err = syscall.Exec(exe, []string{exe, "-test.run=^Test(Pidfd|Poll)", "-test.v", "-test.timeout=60s"}, env)
	emulationExit(exitEmulationUnavailable, "execve("+exe+")", err)
}

// TestKernelWithoutPidfdThread runs this package's pidfd tests on an emulated kernel that refuses the pidfd
// flags Linux 6.9 added (PIDFD_THREAD, PIDFD_SIGNAL_THREAD_GROUP) with EINVAL, as every kernel from the
// support matrix's 5.14 up to 6.8 does. Those flag answers are all it emulates (withoutPidfdThreadFilter),
// and they are what the wrappers' retries exist for, which a 6.9+ machine never exercises otherwise. Each
// test must pass or skip there, and the thread-group signal test must skip: with no thread scope there is
// nothing for it to discriminate, and a failure there would report a correct wrapper as broken on most of
// the kernels Tego supports. Every test there runs off its thread group's leader thread (offLeaderEnv).
func TestKernelWithoutPidfdThread(t *testing.T) {
	auditArch(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestKernelWithoutPidfdThreadHelper$", "-test.timeout=90s")
	cmd.Env = append(os.Environ(), noPidfdThreadEnv+"=1")
	out, err := cmd.CombinedOutput()
	switch helperExitCode(err) {
	case exitEmulationUnavailable:
		t.Skipf("this host would not let the helper emulate a kernel without PIDFD_THREAD:\n%s", out)
	case exitEmulationBroken:
		t.Fatalf("the emulation does not answer as a 5.14–6.8 kernel, so nothing it ran would test one:\n%s", out)
	}
	if err != nil {
		t.Fatalf("pidfd tests on a kernel without PIDFD_THREAD: %v\n%s", err, out)
	}
	for _, want := range []string{
		"--- SKIP: TestPidfdSendSignalTargetsTheThreadGroup",
		// PidfdSendSignal's retry with flags 0 is the only way SIGKILL reaches the child here.
		"--- PASS: TestPidfdSignalAndWait",
		// PidfdOpenThread's retry without PIDFD_THREAD is the only way a tgid opens here.
		"--- PASS: TestPidfdOpenThreadAcceptsATgid",
		// The owner forms, run off the leader thread (offLeaderEnv) like every test here.
		"--- PASS: TestPidfdOwnerForms",
	} {
		if !bytes.Contains(out, []byte(want)) {
			t.Fatalf("on a kernel without PIDFD_THREAD, want %q in:\n%s", want, out)
		}
	}
}
