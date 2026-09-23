// SPDX-License-Identifier: Apache-2.0

package agent

import "strings"

// AccessSet mirrors LANDLOCK_ACCESS_FS_* from uapi/linux/landlock.h bit for
// bit. There is no chmod right in any Landlock ABI (E35); the ABI each bit
// needs is in the comment and in MinABI, and a RuleTable never sets a bit its
// target tier lacks: the Landlock backend masks with ForABI.
type AccessSet uint32

// Landlock filesystem access rights.
const (
	AccessExecute    AccessSet = 1 << 0  // ABI 1
	AccessWriteFile  AccessSet = 1 << 1  // ABI 1
	AccessReadFile   AccessSet = 1 << 2  // ABI 1
	AccessReadDir    AccessSet = 1 << 3  // ABI 1
	AccessRemoveDir  AccessSet = 1 << 4  // ABI 1
	AccessRemoveFile AccessSet = 1 << 5  // ABI 1
	AccessMakeChar   AccessSet = 1 << 6  // ABI 1
	AccessMakeDir    AccessSet = 1 << 7  // ABI 1
	AccessMakeReg    AccessSet = 1 << 8  // ABI 1
	AccessMakeSock   AccessSet = 1 << 9  // ABI 1
	AccessMakeFifo   AccessSet = 1 << 10 // ABI 1
	AccessMakeBlock  AccessSet = 1 << 11 // ABI 1
	AccessMakeSym    AccessSet = 1 << 12 // ABI 1
	AccessRefer      AccessSet = 1 << 13 // ABI 2 (5.19)
	AccessTruncate   AccessSet = 1 << 14 // ABI 3 (6.2)
	AccessIoctlDev   AccessSet = 1 << 15 // ABI 5 (6.10)
	// AccessResolveUnix is the right SEMANTICS §5 assigns to ABI 9 (7.1) for
	// unix: entries; its bit position must be re-verified against the uapi
	// header when that ABI is supported by the Landlock backend.
	AccessResolveUnix AccessSet = 1 << 16 // ABI 9 (7.1)
)

// AccessReadSet is the default read set a sibling directory receives under
// deny_read enumeration (SEMANTICS §2).
const AccessReadSet = AccessReadFile | AccessReadDir | AccessExecute

// AccessWriteSet is every right a write entry grants: all modifications
// SEMANTICS §1 lists for "fs: {}" plus REFER and TRUNCATE, so the backend
// masks by ABI rather than this package guessing the kernel.
const AccessWriteSet = AccessWriteFile | AccessRemoveDir | AccessRemoveFile |
	AccessMakeChar | AccessMakeDir | AccessMakeReg | AccessMakeSock | AccessMakeFifo |
	AccessMakeBlock | AccessMakeSym | AccessRefer | AccessTruncate | AccessIoctlDev

// AccessAll is every right this package knows.
const AccessAll = AccessReadSet | AccessWriteSet | AccessResolveUnix

var accessNames = []struct {
	bit  AccessSet
	name string
	abi  int
}{
	{AccessExecute, "execute", 1},
	{AccessWriteFile, "write_file", 1},
	{AccessReadFile, "read_file", 1},
	{AccessReadDir, "read_dir", 1},
	{AccessRemoveDir, "remove_dir", 1},
	{AccessRemoveFile, "remove_file", 1},
	{AccessMakeChar, "make_char", 1},
	{AccessMakeDir, "make_dir", 1},
	{AccessMakeReg, "make_reg", 1},
	{AccessMakeSock, "make_sock", 1},
	{AccessMakeFifo, "make_fifo", 1},
	{AccessMakeBlock, "make_block", 1},
	{AccessMakeSym, "make_sym", 1},
	{AccessRefer, "refer", 2},
	{AccessTruncate, "truncate", 3},
	{AccessIoctlDev, "ioctl_dev", 5},
	{AccessResolveUnix, "resolve_unix", 9},
}

// MinABI returns the lowest Landlock ABI that supports every bit in the set;
// 0 for an empty set.
func (a AccessSet) MinABI() int {
	abi := 0
	for _, n := range accessNames {
		if a&n.bit != 0 && n.abi > abi {
			abi = n.abi
		}
	}
	return abi
}

// ForABI drops every bit the given ABI does not support.
func (a AccessSet) ForABI(abi int) AccessSet {
	var out AccessSet
	for _, n := range accessNames {
		if a&n.bit != 0 && n.abi <= abi {
			out |= n.bit
		}
	}
	return out
}

// Has reports whether every bit of want is set.
func (a AccessSet) Has(want AccessSet) bool { return a&want == want }

// String lists the set bits by their landlock.h names in lower case, joined
// by "|"; "-" for an empty set.
func (a AccessSet) String() string {
	if a == 0 {
		return "-"
	}
	parts := make([]string, 0, 8)
	for _, n := range accessNames {
		if a&n.bit != 0 {
			parts = append(parts, n.name)
		}
	}
	if rest := a &^ AccessAll; rest != 0 {
		parts = append(parts, "unknown")
	}
	return strings.Join(parts, "|")
}
