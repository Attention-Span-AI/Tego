// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"golang.org/x/sys/unix"
)

// memcgAccounting is the release from which the kernel charges BPF memory to the memory cgroup rather than to
// RLIMIT_MEMLOCK.
var memcgAccounting = Version{5, 11, 0}

// memlockNeeded reports whether a probe on the kernel release must lift RLIMIT_MEMLOCK to load its programs and
// maps: below 5.11, or when the release cannot be read.
func memlockNeeded(release string) bool {
	v, err := ParseKernelRelease(release)
	return err != nil || !v.AtLeast(memcgAccounting)
}

// raiseMemlock lifts RLIMIT_MEMLOCK for this process where BPF memory still counts against it; from 5.11 on it
// does nothing. It is called where a probe is about to load, never at init: cilium/ebpf/rlimit, which did this
// before, probes with a bpf(2) call from an init function, and so in every tego process, the Claude Code hook
// inside a run and the child stage included, where tiers 2 and 3 refuse that call (ADR 0063 (7), ADR 0033 (3)).
// The raise needs CAP_SYS_RESOURCE; without it the probe goes on and reports the load's own error.
func raiseMemlock() {
	var u unix.Utsname
	if err := unix.Uname(&u); err == nil && !memlockNeeded(unix.ByteSliceToString(u.Release[:])) {
		return
	}
	inf := unix.Rlimit{Cur: unix.RLIM_INFINITY, Max: unix.RLIM_INFINITY}
	_ = unix.Prlimit(0, unix.RLIMIT_MEMLOCK, &inf, nil) // unprivileged: EPERM, and the load reports its own error
}
