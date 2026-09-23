// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// capabilityVersion3 is _LINUX_CAPABILITY_VERSION_3: two 32-bit words per set (Linux 2.6.26+).
const capabilityVersion3 = 0x20080522

// ClearCapabilities empties the calling thread's effective, permitted and inheritable capability sets
// (capset(2), _LINUX_CAPABILITY_VERSION_3) and then the ambient set (PR_CAP_AMBIENT_CLEAR_ALL). The capset
// has in fact emptied the ambient set already — the kernel masks ambient to permitted ∩ inheritable on every
// capset (security/commoncap.c cap_capset; measured on 6.17 in a user namespace) — so the prctl is a second
// statement of that postcondition, kept so the empty ambient set the child stage relies on is named here
// rather than inferred from a kernel invariant.
//
// The bounding set is left alone, because shrinking it needs CAP_SETPCAP. An empty permitted set therefore
// does not by itself keep the next execve from gaining capabilities: a setuid-root binary, or one with file
// capabilities, is granted them up to that bounding set. Whether execve can is decided by the caller's
// ordering, not here; this function neither reads nor sets no_new_privs. The child stage's unprivileged
// order (internal/runtime/launch, ARCHITECTURE.md §5 steps 2–4) sets no_new_privs after this call and
// before execve, and under that bit execve ignores setuid bits and caps the new permitted set at the old
// one, which this call emptied, so nothing is gained. The privileged order (runtime-launch.md R4) skips
// no_new_privs, so there a setuid-root or file-capability binary regains capabilities up to the untouched
// bounding set, as ARCHITECTURE.md §5 ("setuid binaries work inside the run") and runtime-launch.md R4a
// describe.
//
// The kernel clears the dumpable flag and the pending parent-death signal in commit_creds when the
// credentials change in a way that matters: a euid/egid/fsuid/fsgid change, or a capability set that is
// not a subset of the old one. Dropping capabilities alone does not, but the uid change that accompanies
// it does, so the child stage sets both afterwards regardless of the order it took here.
func ClearCapabilities() error {
	hdr := unix.CapUserHeader{Version: capabilityVersion3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset(empty sets): %w", err)
	}
	return ClearAmbientCapabilities()
}

// DropBoundingCapability removes one capability from the calling thread's bounding set (prctl PR_CAPBSET_DROP), so no
// execve on this thread or its descendants gains it, a setuid-root binary or a file capability included: the kernel
// masks what an exec grants with this set, and nothing puts a capability back (capabilities(7)). The drop needs
// CAP_SETPCAP, so one already out of the set is not dropped again: a launcher in a container that was never given it
// has nothing to do, and that is not a failure.
func DropBoundingCapability(c uintptr) error {
	held, err := InBoundingSet(c)
	if err != nil || !held {
		return err
	}
	return prctl("PR_CAPBSET_DROP", unix.PR_CAPBSET_DROP, c)
}

// InBoundingSet reports whether a capability is in the calling thread's bounding set (prctl PR_CAPBSET_READ).
func InBoundingSet(c uintptr) (bool, error) {
	v, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, c, 0, 0, 0)
	if err != nil {
		return false, fmt.Errorf("prctl(PR_CAPBSET_READ, %d): %w", c, err)
	}
	return v == 1, nil
}

// Capabilities returns the calling thread's effective, permitted and inheritable sets as 64-bit masks
// (capget(2), _LINUX_CAPABILITY_VERSION_3).
func Capabilities() (effective, permitted, inheritable uint64, err error) {
	hdr := unix.CapUserHeader{Version: capabilityVersion3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return 0, 0, 0, fmt.Errorf("capget: %w", err)
	}
	effective = uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	permitted = uint64(data[1].Permitted)<<32 | uint64(data[0].Permitted)
	inheritable = uint64(data[1].Inheritable)<<32 | uint64(data[0].Inheritable)
	return effective, permitted, inheritable, nil
}

// AmbientCapabilities returns the calling thread's ambient set as a 64-bit mask, one
// prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET) per capability number from 0 up to the first the kernel does not
// know (EINVAL above CAP_LAST_CAP). capget(2) does not report the ambient set.
func AmbientCapabilities() (uint64, error) {
	var set uint64
	for c := 0; c < 64; c++ {
		v, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(c), 0, 0)
		if errors.Is(err, unix.EINVAL) && c > 0 {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, %d): %w", c, err)
		}
		if v == 1 {
			set |= 1 << c
		}
	}
	return set, nil
}

// ClearProcessCapabilities is ClearCapabilities on every thread of the process at once
// (syscall.AllThreadsSyscall): capset(2) to empty effective, permitted and inheritable sets, then
// PR_CAP_AMBIENT_CLEAR_ALL, each run by every thread the Go runtime holds. Capabilities are per thread, and a
// launcher holds several threads before main runs, so clearing only the calling one would leave the rest, and any
// process one of them starts, with the sets (ADR 0042 (3)(a)). The runtime cannot reach the threads of a cgo build
// and then returns ENOTSUP without running anything; the shipped binary is built CGO_ENABLED=0.
func ClearProcessCapabilities() error {
	hdr := unix.CapUserHeader{Version: capabilityVersion3, Pid: 0}
	var data [2]unix.CapUserData
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_CAPSET, uintptr(unsafe.Pointer(&hdr)),
		uintptr(unsafe.Pointer(&data[0])), 0); e != 0 {
		return fmt.Errorf("capset(empty sets) on every thread: %w", e)
	}
	if _, _, e := syscall.AllThreadsSyscall(unix.SYS_PRCTL, unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL,
		0); e != 0 {
		return fmt.Errorf("prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL) on every thread: %w", e)
	}
	return nil
}
