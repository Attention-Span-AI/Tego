// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"unsafe"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// runFiltered installs prog on a fresh locked thread and runs fn on it, returning fn's errors. ok is
// false when the filter could not be installed at all (no seccomp, no NO_NEW_PRIVS), which is the only
// legitimate reason to skip.
//
// The thread is poisoned by the filter and never unlocked, so the Go runtime destroys it with the
// goroutine rather than handing it back to the pool — the same discipline as the TIOCSTI test. fn must
// use raw syscalls: the filter's notify arms have no listener here, so a notified syscall returns ENOSYS.
func runFiltered(prog []bpf.RawInstruction, fn func() []error) ([]error, bool) {
	type result struct {
		errs []error
		ok   bool
	}
	done := make(chan result, 1)
	go func() {
		runtime.LockOSThread() // deliberately never unlocked: the filter cannot be removed
		if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
			done <- result{}
			return
		}
		if err := setFilterNoListener(prog); err != nil {
			done <- result{}
			return
		}
		done <- result{errs: fn(), ok: true}
		runtime.Goexit()
	}()
	r := <-done
	return r.errs, r.ok
}

// TestFilterRefusesTruncateOnABI2Kernel is R2's ABI-3 row and E31 against the real kernel.
//
// LANDLOCK_ACCESS_FS_TRUNCATE arrived with ABI 3 (6.2): "File truncation could not be denied before the
// third Landlock ABI, so it is always allowed when using a kernel that only supports the first or second
// ABI" (Documentation/userspace-api/landlock.rst). ARCHITECTURE §14 keeps 6.1 (ABI 2, Amazon Linux 2023
// stock) as the tested floor, so on a supported kernel truncate(2) — a path call needing no fd, in no
// notify table — would destroy any DAC-writable file while SEMANTICS §1 promises `fs: {}` refuses it.
//
// The Landlock side of that is not reproducible here (this box is well past 6.2), but the arm that
// closes it is pure seccomp and installs on any kernel, so the refusal itself is exercised for real: the
// ABI-2 program refuses, and the ABI-3+ program — the control — lets the same call through, which is
// precisely the kernel behaviour the gap describes. The unverified step is that a genuine 6.1 kernel
// would allow the control call too; that is what the kernel documentation states.
//
// Spec: docs/p0/enforce-landlock.md E31.
func TestFilterRefusesTruncateOnABI2Kernel(t *testing.T) {
	dir := tempDir(t)
	const content = "keep me"
	victim := filepath.Join(dir, "victim")
	ftVictim := filepath.Join(dir, "ftvictim")
	control := filepath.Join(dir, "control")
	for _, p := range []string{victim, ftVictim, control} {
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	victimPtr, err := unix.BytePtrFromString(victim)
	if err != nil {
		t.Fatal(err)
	}
	controlPtr, err := unix.BytePtrFromString(control)
	if err != nil {
		t.Fatal(err)
	}
	// Opened before the filter goes on: a write open is notified, and there is no listener here.
	ftFD, err := unix.Open(ftVictim, unix.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(ftFD)

	below, err := assembleFilter(NativeArch(), filterOpts{abi: 2})
	if err != nil {
		t.Fatalf("assemble ABI 2: %v", err)
	}
	errs, ok := runFiltered(below, func() []error {
		_, _, e1 := unix.Syscall(unix.SYS_TRUNCATE, uintptr(unsafe.Pointer(victimPtr)), 0, 0)
		_, _, e2 := unix.Syscall6(unix.SYS_OPENAT, atFDCWD, uintptr(unsafe.Pointer(victimPtr)),
			uintptr(unix.O_RDONLY|unix.O_TRUNC), 0, 0, 0)
		// A plain read open must still work: the guard is not a blanket open denial.
		fd, _, e3 := unix.Syscall6(unix.SYS_OPENAT, atFDCWD, uintptr(unsafe.Pointer(victimPtr)),
			uintptr(unix.O_RDONLY|unix.O_CLOEXEC), 0, 0, 0)
		if e3 == 0 {
			unix.Syscall(unix.SYS_CLOSE, fd, 0, 0)
		}
		// ftruncate needs a fd opened for writing, which WRITE_FILE already decided: not refused.
		_, _, e4 := unix.Syscall(unix.SYS_FTRUNCATE, uintptr(ftFD), 3, 0)
		// Access mode 3 (O_ACCMODE): no FMODE_READ or FMODE_WRITE, so Landlock below ABI 3 checks nothing,
		// yet the VFS truncates. Refused like O_RDONLY.
		_, _, e5 := unix.Syscall6(unix.SYS_OPENAT, atFDCWD, uintptr(unsafe.Pointer(victimPtr)),
			uintptr(unix.O_ACCMODE|unix.O_TRUNC), 0, 0, 0)
		return []error{errnoOrNil(e1), errnoOrNil(e2), errnoOrNil(e3), errnoOrNil(e4), errnoOrNil(e5)}
	})
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	if !errors.Is(errs[0], unix.EPERM) {
		t.Errorf("truncate(2) under the ABI-2 filter returned %v, want EPERM: the pre-6.2 truncation hole is open", errs[0])
	}
	if !errors.Is(errs[1], unix.EPERM) {
		t.Errorf("open(O_RDONLY|O_TRUNC) under the ABI-2 filter returned %v, want EPERM", errs[1])
	}
	if !errors.Is(errs[4], unix.EPERM) {
		t.Errorf("open(O_ACCMODE|O_TRUNC) under the ABI-2 filter returned %v, want EPERM", errs[4])
	}
	if errs[2] != nil {
		t.Errorf("a plain read open was refused (%v): the guard is too broad", errs[2])
	}
	if errs[3] != nil {
		t.Errorf("ftruncate on a write fd was refused (%v): the guard is too broad", errs[3])
	}
	if got, err := os.ReadFile(victim); err != nil || string(got) != content {
		t.Errorf("victim file is %q (%v), want %q: it was truncated despite the refusal", got, err, content)
	}
	if st, err := os.Stat(ftVictim); err != nil || st.Size() != 3 {
		t.Errorf("ftruncate did not take effect: size %v (%v), want 3", st, err)
	}

	// Control: the same call under the filter Prepare builds for ABI ≥ 3, where Landlock itself holds
	// the TRUNCATE right per path. It must not meet the refusing arm — otherwise the arm is unconditional and
	// over-restricts every modern run. From ABI 3 the call is notified so the supervisor records it (R11),
	// and with no listener on this thread a notified call is answered ENOSYS, leaving the file as it was.
	atOrAbove, err := assembleFilter(NativeArch(), filterOpts{abi: minTruncateABI})
	if err != nil {
		t.Fatalf("assemble ABI 3: %v", err)
	}
	errs, ok = runFiltered(atOrAbove, func() []error {
		_, _, e := unix.Syscall(unix.SYS_TRUNCATE, uintptr(unsafe.Pointer(controlPtr)), 0, 0)
		return []error{errnoOrNil(e)}
	})
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	if !errors.Is(errs[0], unix.ENOSYS) {
		t.Errorf("truncate(2) under the ABI-3 filter returned %v, want ENOSYS: notified, with no listener to answer", errs[0])
	}
}

// TestFilterRefusesMPTCPSocketOnKernel is E30 against the real kernel: socket(2) with IPPROTO_MPTCP is
// refused with EPROTONOSUPPORT, while a classic TCP socket — the one Landlock's net hooks and R6's port
// rules can actually see — is created normally.
//
// Spec: docs/p0/enforce-landlock.md E30.
func TestFilterRefusesMPTCPSocketOnKernel(t *testing.T) {
	// Informational control, outside the filter: whether this kernel offers MPTCP at all. When it does,
	// the bypass the arm closes is live on this machine.
	if fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP); err == nil {
		unix.Close(fd)
		t.Log("kernel supports IPPROTO_MPTCP: unfiltered, this socket is outside every Landlock net rule")
	} else {
		t.Logf("kernel has no IPPROTO_MPTCP (%v); the filter arm is still exercised", err)
	}

	prog, err := assembleFilter(NativeArch(), filterOpts{full: false, abi: minTruncateABI})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	errs, ok := runFiltered(prog, func() []error {
		_, _, e1 := unix.Syscall(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, ipprotoMPTCP)
		fd, _, e2 := unix.Syscall(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_STREAM, 0)
		if e2 == 0 {
			unix.Syscall(unix.SYS_CLOSE, fd, 0, 0)
		}
		return []error{errnoOrNil(e1), errnoOrNil(e2)}
	})
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	if !errors.Is(errs[0], unix.EPROTONOSUPPORT) {
		t.Errorf("socket(AF_INET, SOCK_STREAM, IPPROTO_MPTCP) returned %v, want EPROTONOSUPPORT: R6's bind denial stays bypassable", errs[0])
	}
	if errs[1] != nil {
		t.Errorf("a classic TCP socket was refused (%v): the guard is too broad", errs[1])
	}
}

// TestFilterRefusesSourceRouteOptionsOnKernel is ADR 0041 D6's source-route arm against the real kernel: under a
// net gate an unprivileged setsockopt(IP_OPTIONS) carrying an LSRR route, and setsockopt(IPV6_RTHDR) with a segment
// routing header, are refused EPERM, while IP_TTL on the same socket still works. The control is the same calls
// under the filter without the arm, where both routes are accepted: that is the window a sibling had between
// the supervisor's options read and its relayed connect.
//
// Spec: docs/p0/enforce-landlock.md R11b; supervisor R9.
func TestFilterRefusesSourceRouteOptionsOnKernel(t *testing.T) {
	// IPOPT_NOOP, then IPOPT_LSRR of length 7 with pointer 4 and one hop, 127.0.0.2.
	lsrr := []byte{1, 0x83, 7, 4, 127, 0, 0, 2}
	// A segment routing header (type 4), which needs no capability: next header, length 2 (one segment), type 4,
	// segments left 0, last entry 0, flags, tag, then the segment ::1.
	rthdr := make([]byte, 24)
	rthdr[1], rthdr[2], rthdr[23] = 2, 4, 1
	calls := func() []error {
		fd4, _, e := unix.Syscall(unix.SYS_SOCKET, unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if e != 0 {
			return []error{e, e, e}
		}
		defer unix.Syscall(unix.SYS_CLOSE, fd4, 0, 0)
		_, _, e1 := unix.Syscall6(unix.SYS_SETSOCKOPT, fd4, unix.SOL_IP, unix.IP_OPTIONS,
			uintptr(unsafe.Pointer(&lsrr[0])), uintptr(len(lsrr)), 0)
		ttl := int32(9)
		_, _, e2 := unix.Syscall6(unix.SYS_SETSOCKOPT, fd4, unix.SOL_IP, unix.IP_TTL,
			uintptr(unsafe.Pointer(&ttl)), 4, 0)
		e3 := unix.EAFNOSUPPORT
		if fd6, _, e := unix.Syscall(unix.SYS_SOCKET, unix.AF_INET6, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0); e == 0 {
			_, _, e3 = unix.Syscall6(unix.SYS_SETSOCKOPT, fd6, unix.SOL_IPV6, unix.IPV6_RTHDR,
				uintptr(unsafe.Pointer(&rthdr[0])), uintptr(len(rthdr)), 0)
			unix.Syscall(unix.SYS_CLOSE, fd6, 0, 0)
		}
		return []error{errnoOrNil(e1), errnoOrNil(e2), errnoOrNil(e3)}
	}

	without, err := assembleFilter(NativeArch(), filterOpts{abi: minTruncateABI})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	errs, ok := runFiltered(without, calls)
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	t.Logf("without the arm: IP_OPTIONS %v, IP_TTL %v, IPV6_RTHDR %v", errs[0], errs[1], errs[2])
	if errs[0] != nil {
		t.Fatalf("control: setsockopt(IP_OPTIONS, LSRR) without the arm returned %v; the test cannot show the arm's effect", errs[0])
	}
	if errs[2] != nil && !errors.Is(errs[2], unix.EAFNOSUPPORT) {
		t.Fatalf("control: setsockopt(IPV6_RTHDR, SRH) without the arm returned %v; the test cannot show the arm's effect", errs[2])
	}

	with, err := assembleFilter(NativeArch(), filterOpts{abi: minTruncateABI, gateNet: true})
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	errs, ok = runFiltered(with, calls)
	if !ok {
		t.Skip("could not install a seccomp filter on this thread")
	}
	if !errors.Is(errs[0], unix.EPERM) {
		t.Errorf("setsockopt(IP_OPTIONS, LSRR) under a net gate returned %v, want EPERM", errs[0])
	}
	if errs[1] != nil {
		t.Errorf("setsockopt(IP_TTL) under a net gate returned %v: the arm is too broad", errs[1])
	}
	if !errors.Is(errs[2], unix.EPERM) && !errors.Is(errs[2], unix.EAFNOSUPPORT) {
		t.Errorf("setsockopt(IPV6_RTHDR) under a net gate returned %v, want EPERM", errs[2])
	}
}
