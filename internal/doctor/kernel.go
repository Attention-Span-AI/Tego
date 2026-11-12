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
	// LandlockABI is the Landlock ABI version this row is, 0 for a row that is not one. D1 judges such a row by
	// the ABI D4's probe answers, not by Since (missingMechanisms).
	LandlockABI int
	// unixConnect marks the row D7's cgroup/connect_unix answer decides where D7 gave one (missingMechanisms).
	unixConnect bool
}

// Mechanisms lists every per-mechanism minimum D1 reports, oldest first. A distribution that
// backports a feature into an older release (RHEL 9's 5.14, ARCHITECTURE §14) has it while its release
// says otherwise, so D1 judges a row by what the kernel answered wherever a probe answered it: the Landlock rows
// by the ABI landlock_create_ruleset answers (the probe D4 reports; a kernel that answers it has no Landlock lacks
// every Landlock row), and cgroup connect_unix by D7's load of that hook where D7 ran and answered (as root).
// *Amended 2026-11-11:* every row was judged by the release, so on AlmaLinux 9.8 D1 listed Landlock ABI 2 to 6 as
// missing four lines above D4's "ABI 6". The other rows, and these two where no probe answered, are still judged
// by the release. D1 is advice either way above MinKernel: the runtime probes, never trusts a version, and D2-D8
// decide the tiers (BTF in D2, cgroup.kill in D3, ADDFD_FLAG_SEND in D5, the BPF hooks, cgroup connect_unix among
// them, in D7).
//
// fanotify's FAN_DENY_ERRNO (6.14) is not a row: nothing in this binary depends on it. The kernel
// takes a reply errno only from a FAN_CLASS_PRE_CONTENT group and never EACCES, so tier 2's
// FAN_CLASS_CONTENT listener refuses with the bare FAN_DENY on every kernel
// (docs/p0/enforce-cgroup-observe.md §6 E2), and a row would tell an older kernel it lacks something.
var Mechanisms = []Mechanism{
	{Name: "seccomp NEW_LISTENER", Since: Version{5, 0, 0}, What: "no supervisor, no tier 1"},
	{Name: "fanotify exec permission events", Since: Version{5, 0, 0}, What: "tier 2 cannot refuse an exec by path"},
	{Name: "seccomp CONTINUE", Since: Version{5, 5, 0}, What: "every notified syscall has to be answered by the supervisor"},
	{Name: "pidfd_getfd", Since: Version{5, 6, 0}, What: "the supervisor cannot complete a connect for the agent"},
	{Name: "BPF LSM", Since: Version{5, 7, 0}, What: "no tier 3"},
	{Name: "BPF ring buffer", Since: Version{5, 8, 0}, What: "no kernel record"},
	{Name: "seccomp ADDFD", Since: Version{5, 9, 0}, What: "the supervisor cannot hand an fd back"},
	{Name: "BPF inode local storage", Since: Version{5, 10, 0}, What: "tier 3 cannot identify a file by inode"},
	{Name: "Landlock ABI 1", Since: Version{5, 13, 0}, What: "no tier 1", LandlockABI: 1},
	{Name: "cgroup.kill", Since: Version{5, 14, 0}, What: "a run is stopped process by process instead of atomically"},
	{Name: "seccomp ADDFD_FLAG_SEND", Since: addfdSendSince, What: "ask cannot complete a syscall race-free"},
	{Name: "Landlock ABI 2 (refer)", Since: Version{5, 19, 0}, What: "rename and link are confined to one directory", LandlockABI: 2},
	{Name: "Landlock ABI 3 (truncate)", Since: Version{6, 2, 0}, What: "truncate is not denied outside the contract", LandlockABI: 3},
	{Name: "cgroup connect_unix", Since: Version{6, 7, 0}, What: "unix connects fall back to the seccomp path", unixConnect: true},
	{Name: "Landlock ABI 4 (TCP)", Since: Version{6, 7, 0}, What: "tier 1 cannot restrict TCP ports", LandlockABI: 4},
	{Name: "Landlock ABI 5 (ioctl_dev)", Since: Version{6, 10, 0}, What: "device ioctls are not restricted", LandlockABI: 5},
	{Name: "Landlock ABI 6 (scopes)", Since: Version{6, 12, 0}, What: "abstract unix sockets and signals are not scoped", LandlockABI: 6},
	{Name: "Landlock ABI 7 (audit)", Since: Version{6, 15, 0}, What: "Landlock refusals are not in the audit log", LandlockABI: 7},
}

// TestedFloor is the oldest kernel this project tests on (docs/ARCHITECTURE.md §14). Landlock ABI 1
// kernels, 5.13-5.18, are unsupported: rename and link would be confined to one directory.
var TestedFloor = Version{6, 1, 0}

// kernelProbe is what the kernel itself answered for D1's rows, beside its release.
type kernelProbe struct {
	// asked marks a probe D1 made on this kernel (probeKernel). A D1 answer without it is not rendered again
	// from D7's answer (scope.run).
	asked bool
	// landlockABI is the ABI landlock_create_ruleset(VERSION) answered, 0 when it answered none.
	landlockABI int
	// landlockOff is a kernel that answered it has no Landlock: ENOSYS (not built in) or EOPNOTSUPP (built in but
	// not in the lsm= list), the answers on which D4 says the tier is unavailable. Any other error (EPERM from a
	// container's seccomp filter, say) is no answer, and the release decides.
	landlockOff bool
	// unixConnect is D7's answer for cgroup/connect_unix, nil where D7 did not run or did not answer
	// (unixConnectAnswer).
	unixConnect *bool
}

// missingMechanisms lists the mechanisms release v does not have, in Mechanisms order, on a kernel that answered
// p. A Landlock row is missing when the probed ABI is lower than the row's, or when the kernel answered it has no
// Landlock, whatever v says; the connect_unix row is missing when D7 answered that the kernel refuses the hook.
// With no answer a row is judged by v.
func missingMechanisms(v Version, p kernelProbe) []Mechanism {
	var out []Mechanism
	for _, m := range Mechanisms {
		missing := !v.AtLeast(m.Since)
		switch {
		case m.LandlockABI > 0 && p.landlockOff:
			missing = true
		case m.LandlockABI > 0 && p.landlockABI > 0:
			missing = p.landlockABI < m.LandlockABI
		case m.unixConnect && p.unixConnect != nil:
			missing = !*p.unixConnect
		}
		if missing {
			out = append(out, m)
		}
	}
	return out
}
