// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

// LandlockRulesetAttr is the landlock_ruleset_attr passed to LandlockCreateRuleset: the access rights the
// ruleset handles (everything not listed stays allowed). From x/sys 0.49 it is the ABI 10 layout, 48 bytes with
// three Quiet_ masks after the 24 bytes every earlier kernel reads; the tree never sets them (R20).
type LandlockRulesetAttr = unix.LandlockRulesetAttr

// LandlockCreateRuleset, LandlockAddRule and LandlockRestrictSelf are the tree's only callers of the
// Landlock syscalls (ADR 0029 (2), TestOneLandlockWrapperPerSyscall): enforce/landlock's syscall seam, the
// ABI probe and the descriptor kind check go through them. LandlockCreateRuleset and LandlockAddRule return
// the kernel's errno unwrapped, so callers compare it with errors.Is and add their own context once.

// LandlockCreateRuleset is landlock_create_ruleset(2) (Linux 5.13): with attr it creates a ruleset
// handling attr's accesses and returns its fd (the kernel always sets O_CLOEXEC); with attr nil and
// LANDLOCK_CREATE_RULESET_VERSION in flags it returns the ABI version. The whole struct is passed: the
// kernel accepts a larger struct than it knows when the unknown tail is zero and refuses a non-zero tail with
// E2BIG (TestLandlockCreateRulesetTail), so a caller leaves the fields past the probed ABI zero. It is one of
// sys's int producers (ADR 0023): a caller outside sys wraps it in sys.Own or calls LandlockCreateRulesetFD.
func LandlockCreateRuleset(attr *LandlockRulesetAttr, flags int) (int, error) {
	return landlockCreateRuleset(attr, flags)
}

// landlockCreateRuleset is the one site that issues landlock_create_ruleset(2). LandlockABI calls it
// directly: the version query returns a number, never a descriptor, so it is no producer to own.
func landlockCreateRuleset(attr *LandlockRulesetAttr, flags int) (int, error) {
	var p unsafe.Pointer
	var size uintptr
	if attr != nil {
		p = unsafe.Pointer(attr)
		size = unsafe.Sizeof(*attr)
	}
	fd, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(p), size, uintptr(flags))
	if errno != 0 {
		return -1, errno
	}
	return int(fd), nil
}

// LandlockAddRule is landlock_add_rule(2) (Linux 5.13): it adds the rule attr points at, of ruleType
// (LANDLOCK_RULE_PATH_BENEATH, or LANDLOCK_RULE_NET_PORT from ABI 4), to rulesetFD.
func LandlockAddRule(rulesetFD, ruleType int, attr unsafe.Pointer, flags int) error {
	_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, uintptr(rulesetFD), uintptr(ruleType), uintptr(attr), uintptr(flags), 0, 0)
	if errno != 0 {
		return errno
	}
	return nil
}

// LandlockABI returns the kernel's Landlock ABI version (landlock_create_ruleset with
// LANDLOCK_CREATE_RULESET_VERSION, Linux 5.13). ENOSYS or EOPNOTSUPP mean Landlock is absent or disabled;
// the error wraps the errno so callers can tell.
func LandlockABI() (int, error) {
	v, err := landlockCreateRuleset(nil, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if err != nil {
		return 0, fmt.Errorf("landlock_create_ruleset(VERSION): %w", err)
	}
	return v, nil
}

// LandlockCreateRulesetFD is LandlockCreateRuleset born an owner (ADR 0023 T1.2).
func LandlockCreateRulesetFD(attr *LandlockRulesetAttr) (*FD, error) {
	return Own(LandlockCreateRuleset(attr, 0))
}

// LandlockRestrictSelf enforces rulesetFD on the calling thread (landlock_restrict_self(2), Linux 5.13).
// flags are the LANDLOCK_RESTRICT_SELF_* bits (ABI 7+ logging, ABI 8 TSYNC); pass 0 below ABI 7. Without
// no_new_privs and without CAP_SYS_ADMIN the kernel returns EPERM. The domain lives in the cred and survives
// execve.
func LandlockRestrictSelf(rulesetFD int, flags uint32) error {
	_, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, uintptr(rulesetFD), uintptr(flags), 0)
	if errno != 0 {
		return fmt.Errorf("landlock_restrict_self(ruleset=%d, flags=%#x): %w", rulesetFD, flags, errno)
	}
	return nil
}

// LandlockAccessFSABI1 is the file-system access mask every Landlock kernel handles (ABI 1, Linux 5.13).
const LandlockAccessFSABI1 uint64 = unix.LANDLOCK_ACCESS_FS_EXECUTE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE |
	unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
	unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR | unix.LANDLOCK_ACCESS_FS_MAKE_DIR |
	unix.LANDLOCK_ACCESS_FS_MAKE_REG | unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO |
	unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK | unix.LANDLOCK_ACCESS_FS_MAKE_SYM
