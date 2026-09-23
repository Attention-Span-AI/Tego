// SPDX-License-Identifier: Apache-2.0

package landlock

// accessFS mirrors LANDLOCK_ACCESS_FS_* from uapi/linux/landlock.h bit for bit: the superset across
// ABI 1–9. Bit positions are the kernel's, so an agent.AccessSet converts by a plain cast.
type accessFS uint64

// Filesystem access rights; the ABI each bit needs is in the comment.
const (
	accessExecute     accessFS = 1 << iota // ABI 1
	accessWriteFile                        // ABI 1
	accessReadFile                         // ABI 1
	accessReadDir                          // ABI 1
	accessRemoveDir                        // ABI 1
	accessRemoveFile                       // ABI 1
	accessMakeChar                         // ABI 1
	accessMakeDir                          // ABI 1
	accessMakeReg                          // ABI 1
	accessMakeSock                         // ABI 1
	accessMakeFifo                         // ABI 1
	accessMakeBlock                        // ABI 1
	accessMakeSym                          // ABI 1
	accessRefer                            // ABI 2 (5.19)
	accessTruncate                         // ABI 3 (6.2)
	accessIoctlDev                         // ABI 5 (6.10)
	accessResolveUnix                      // ABI 9 (7.1), R21
)

// accessFSv1 is the ABI-1 base set (bits 0–12).
const accessFSv1 = accessMakeSym<<1 - 1

// fileRights are the rights valid on a non-directory: a directory right on a file is EINVAL (R3).
const fileRights = accessExecute | accessWriteFile | accessReadFile | accessTruncate | accessIoctlDev | accessResolveUnix

// readSet is the base read set a sibling directory receives (R3); EXECUTE joins it only while exec is
// unrestricted, see builder.readSet.
const readSet = accessReadFile | accessReadDir

// netAccess mirrors LANDLOCK_ACCESS_NET_* (ABI 4+). The kernel numbers BIND_TCP first; the spec's
// sketch listed CONNECT first — the header wins.
type netAccess uint64

// Network access rights.
const (
	accessNetBindTCP        netAccess = 1 << iota // ABI 4 (6.7)
	accessNetConnectTCP                           // ABI 4 (6.7)
	accessNetBindUDP                              // ABI 10 (7.2), R22
	accessNetConnectSendUDP                       // ABI 10 (7.2), R22
)

// scope mirrors LANDLOCK_SCOPE_* (ABI 6+): the kernel numbers ABSTRACT_UNIX_SOCKET first.
type scope uint64

// Scope flags (R7).
const (
	scopeAbstractUnixSocket scope = 1 << iota // ABI 6 (6.12)
	scopeSignal                               // ABI 6 (6.12)
)

// abiProfile is the set of rights an ABI lets a ruleset handle (R2).
type abiProfile struct {
	Version int
	FS      accessFS
	Net     netAccess
	Scope   scope
}

// maxKnownABI is the highest profile row; anything newer clamps to it (E25).
const maxKnownABI = 11

// profileFor is the best-effort degrade table (R2): the handled masks for a probed ABI. ABI 0 or
// negative yields an empty profile (unreachable in practice: Prepare refuses first, R1).
func profileFor(abi int) abiProfile {
	if abi > maxKnownABI {
		abi = maxKnownABI // E25: clamp, never guess an encoding
	}
	p := abiProfile{Version: abi}
	if abi < 1 {
		return p
	}
	p.FS = accessFSv1 // ABI 1: base FS rights
	if abi >= 2 {
		p.FS |= accessRefer // ABI 2: REFER
	}
	if abi >= 3 {
		p.FS |= accessTruncate // ABI 3: TRUNCATE
	}
	if abi >= 4 {
		p.Net = accessNetBindTCP | accessNetConnectTCP // ABI 4: TCP port rules (R6)
	}
	if abi >= 5 {
		p.FS |= accessIoctlDev // ABI 5: IOCTL_DEV
	}
	if abi >= 6 {
		p.Scope = scopeSignal | scopeAbstractUnixSocket // ABI 6: scopes (R7)
	}
	// ABI 7 (audit flags) changes nothing here: flags are always 0 (R20).
	// ABI 8 (TSYNC) is not used: NEW_LISTENER excludes it structurally (R13).
	if abi >= 9 {
		p.FS |= accessResolveUnix // ABI 9: pathname unix rules (R21)
	}
	if abi >= 10 {
		p.Net |= accessNetBindUDP | accessNetConnectSendUDP // ABI 10: UDP port rules (R22)
	}
	// ABI 11 (NO_NEW_PRIVS fold) lives entirely in the child stage (sys.RestrictSelf, R18).
	return p
}

// mask drops every bit the profile does not handle.
func (p abiProfile) mask(a accessFS) accessFS { return a & p.FS }
