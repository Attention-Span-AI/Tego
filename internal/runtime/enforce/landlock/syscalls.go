// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/platform/sys"
)

// Landlock syscall constants x/sys/unix does not export (uapi/linux/landlock.h).
const (
	createRulesetVersion = 1 << 0 // LANDLOCK_CREATE_RULESET_VERSION
	ruleTypePathBeneath  = unix.LANDLOCK_RULE_PATH_BENEATH
	ruleTypeNetPort      = 2 // LANDLOCK_RULE_NET_PORT, ABI 4+
)

// netPortAttr is struct landlock_net_port_attr (ABI 4+).
type netPortAttr struct {
	AllowedAccess uint64
	Port          uint64
}

// landlockSyscalls seams the Landlock syscalls so every rule computed by R2–R22 is unit-testable with a
// fake and no kernel (§2/§4/§9). Prepare and ProbeABI go through it; nothing calls the kernel directly. The
// ruleset is applied by the child stage (sys.RestrictSelf, R18), not by this package.
type landlockSyscalls interface {
	// CreateRuleset is landlock_create_ruleset(2); attr nil with the VERSION flag probes the ABI (R1).
	CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (fd int, err error)
	// AddPathRule is landlock_add_rule(2) with LANDLOCK_RULE_PATH_BENEATH.
	AddPathRule(rulesetFD int, attr *unix.LandlockPathBeneathAttr, flags int) error
	// AddNetPortRule is landlock_add_rule(2) with LANDLOCK_RULE_NET_PORT (ABI 4+).
	AddNetPortRule(rulesetFD int, attr *netPortAttr, flags int) error
	// ProbeRuleset is landlock_add_rule(2) with LANDLOCK_RULE_PATH_BENEATH and no access, which adds
	// nothing and always fails: ENOMSG when rulesetFD names a Landlock ruleset, EBADFD when it names
	// any other file opened without O_PATH, and EBADF when it is not open or names an O_PATH file, since
	// the kernel looks the number up with fdget, which does not see O_PATH files (every ABI: the ruleset
	// is looked up before the empty access is refused, and the parent fd is never read). rulesetStill
	// reads the answer.
	ProbeRuleset(rulesetFD int) error
}

// realSyscalls issues the syscalls through internal/platform/sys's wrappers, the tree's only Landlock
// syscall callers (ADR 0029 (2)); they return the kernel's errno unwrapped.
type realSyscalls struct{}

func (realSyscalls) CreateRuleset(attr *unix.LandlockRulesetAttr, flags int) (int, error) {
	return sys.LandlockCreateRuleset(attr, flags)
}

func (realSyscalls) AddPathRule(rulesetFD int, attr *unix.LandlockPathBeneathAttr, flags int) error {
	return sys.LandlockAddRule(rulesetFD, ruleTypePathBeneath, unsafe.Pointer(attr), flags)
}

func (realSyscalls) AddNetPortRule(rulesetFD int, attr *netPortAttr, flags int) error {
	return sys.LandlockAddRule(rulesetFD, ruleTypeNetPort, unsafe.Pointer(attr), flags)
}

func (realSyscalls) ProbeRuleset(rulesetFD int) error {
	attr := unix.LandlockPathBeneathAttr{Parent_fd: -1}
	return sys.LandlockAddRule(rulesetFD, ruleTypePathBeneath, unsafe.Pointer(&attr), 0)
}

// probeABI is R1: landlock_create_ruleset(NULL, 0, VERSION). A positive return is the ABI; ENOSYS
// (kernel < 5.13 or landlock=0 at boot, E1/E2) and EOPNOTSUPP (not in the LSM list) are unsupported.
func probeABI(sc landlockSyscalls) (int, error) {
	v, err := sc.CreateRuleset(nil, createRulesetVersion)
	if err != nil {
		what := "failed"
		if errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP) {
			what = "kernel has no Landlock or landlock=0 at boot"
		}
		return 0, fmt.Errorf("%w: landlock_create_ruleset(VERSION) %s: %w", ErrLandlockUnsupported, what, err)
	}
	if v <= 0 {
		return 0, fmt.Errorf("%w: landlock_create_ruleset(VERSION) returned %d", ErrLandlockUnsupported, v)
	}
	return v, nil
}

// ProbeABI probes the running kernel's Landlock ABI (R1). doctor and enforce.Select call it ahead of
// New so the result can be threaded into Options.ABI; it costs one syscall and holds nothing.
func ProbeABI() (int, error) {
	return probeABI(realSyscalls{})
}
