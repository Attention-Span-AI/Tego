// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Version is a kernel release's numeric prefix.
type Version struct {
	Major, Minor, Patch int
}

// MinKernel is the floor every mechanism this binary relies on is available at: cgroup.kill and
// SECCOMP_ADDFD_FLAG_SEND arrived in 5.14 (ARCHITECTURE.md §14).
var MinKernel = Version{5, 14, 0}

// ErrRelease is a uname release string without a major.minor prefix.
var ErrRelease = errors.New("doctor: unparsable kernel release")

// ParseKernelRelease reads the leading major.minor[.patch] of a uname release such as
// "6.17.0-41-generic" or "5.15.0"; anything after the numbers is ignored. Never panics (fuzzed).
func ParseKernelRelease(release string) (Version, error) {
	num := func(s string) (int, bool) {
		if s == "" || len(s) > 9 {
			return 0, false
		}
		n, err := strconv.Atoi(s)
		return n, err == nil && n >= 0
	}
	head := release
	if i := strings.IndexFunc(head, func(r rune) bool { return r != '.' && (r < '0' || r > '9') }); i >= 0 {
		head = head[:i]
	}
	head = strings.TrimRight(head, ".")
	parts := strings.Split(head, ".")
	if len(parts) < 2 {
		return Version{}, fmt.Errorf("%w: %q", ErrRelease, release)
	}
	var v Version
	var ok bool
	if v.Major, ok = num(parts[0]); !ok {
		return Version{}, fmt.Errorf("%w: %q", ErrRelease, release)
	}
	if v.Minor, ok = num(parts[1]); !ok {
		return Version{}, fmt.Errorf("%w: %q", ErrRelease, release)
	}
	if len(parts) > 2 {
		if v.Patch, ok = num(parts[2]); !ok {
			return Version{}, fmt.Errorf("%w: %q", ErrRelease, release)
		}
	}
	return v, nil
}

// AtLeast reports v >= o.
func (v Version) AtLeast(o Version) bool {
	if v.Major != o.Major {
		return v.Major > o.Major
	}
	if v.Minor != o.Minor {
		return v.Minor > o.Minor
	}
	return v.Patch >= o.Patch
}

// String renders major.minor.patch.
func (v Version) String() string { return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch) }

// Mechanism is one kernel feature this binary relies on, with the release it arrived in
// (docs/ARCHITECTURE.md §14 "Support matrix", verified 2026-09-21).
type Mechanism struct {
	// Name is the feature as the kernel's own documentation calls it.
	Name string
	// Since is the first upstream release that has it.
	Since Version
	// What names, in one clause, what stops working without it.
	What string
}

// Mechanisms lists every per-mechanism minimum D1 reports, oldest first. A distribution that
// backports a feature into an older release (RHEL 9's 5.14, ARCHITECTURE §14) will be reported as
// missing it here and still pass its own functional probe: the runtime probes, never trusts a
// version, so D1 is advice and D4-D8 are the answer.
//
// fanotify's FAN_DENY_ERRNO (6.14) is not a row: nothing in this binary depends on it. The kernel
// takes a reply errno only from a FAN_CLASS_PRE_CONTENT group and never EACCES, so tier 2's
// FAN_CLASS_CONTENT listener refuses with the bare FAN_DENY on every kernel
// (docs/p0/enforce-cgroup-observe.md §6 E2), and a row would tell an older kernel it lacks something.
var Mechanisms = []Mechanism{
	{"seccomp NEW_LISTENER", Version{5, 0, 0}, "no supervisor, no tier 1"},
	{"fanotify exec permission events", Version{5, 0, 0}, "tier 2 cannot refuse an exec by path"},
	{"seccomp CONTINUE", Version{5, 5, 0}, "every notified syscall has to be answered by the supervisor"},
	{"pidfd_getfd", Version{5, 6, 0}, "the supervisor cannot complete a connect for the agent"},
	{"BPF LSM", Version{5, 7, 0}, "no tier 3"},
	{"BPF ring buffer", Version{5, 8, 0}, "no kernel record"},
	{"seccomp ADDFD", Version{5, 9, 0}, "the supervisor cannot hand an fd back"},
	{"BPF inode local storage", Version{5, 10, 0}, "tier 3 cannot identify a file by inode"},
	{"Landlock ABI 1", Version{5, 13, 0}, "no tier 1"},
	{"cgroup.kill", Version{5, 14, 0}, "a run is stopped process by process instead of atomically"},
	{"seccomp ADDFD_FLAG_SEND", addfdSendSince, "ask cannot complete a syscall race-free"},
	{"Landlock ABI 2 (refer)", Version{5, 19, 0}, "rename and link are confined to one directory"},
	{"Landlock ABI 3 (truncate)", Version{6, 2, 0}, "truncate is not denied outside the contract"},
	{"cgroup connect_unix", Version{6, 7, 0}, "unix connects fall back to the seccomp path"},
	{"Landlock ABI 4 (TCP)", Version{6, 7, 0}, "tier 1 cannot restrict TCP ports"},
	{"Landlock ABI 5 (ioctl_dev)", Version{6, 10, 0}, "device ioctls are not restricted"},
	{"Landlock ABI 6 (scopes)", Version{6, 12, 0}, "abstract unix sockets and signals are not scoped"},
	{"Landlock ABI 7 (audit)", Version{6, 15, 0}, "Landlock refusals are not in the audit log"},
}

// TestedFloor is the oldest kernel this project tests on (docs/ARCHITECTURE.md §14). Landlock ABI 1
// kernels, 5.13-5.18, are unsupported: rename and link would be confined to one directory.
var TestedFloor = Version{6, 1, 0}

// MissingMechanisms lists the mechanisms release v does not have, in Mechanisms order.
func MissingMechanisms(v Version) []Mechanism {
	var out []Mechanism
	for _, m := range Mechanisms {
		if !v.AtLeast(m.Since) {
			out = append(out, m)
		}
	}
	return out
}
