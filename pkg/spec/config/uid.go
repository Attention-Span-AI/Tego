// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"strconv"
)

// InvokingUID applies the SUDO_UID rule (R19): when the real uid is 0 of the initial user namespace and
// SUDO_UID is set and parses as an unsigned integer, the invoking uid is SUDO_UID and viaSudo is true;
// otherwise the real uid. A corrupted SUDO_UID counts as unset (E8). SUDO_USER is never consulted. In a
// child user namespace (`unshare -r`, a rootless container) SUDO_UID is ignored: the real uid there is 0
// and the variable is the caller's to set (ADR 0042 (5)(d)). So it is when the namespace is unknown (an
// unreadable uid map): only the initial namespace's uid 0 is root.
func InvokingUID() (uid int, viaSudo bool) {
	return invokingUID(os.Getuid(), os.Getenv("SUDO_UID"), InitialUserNamespace())
}

// invokingUID is InvokingUID over explicit inputs.
func invokingUID(realUID int, sudoUID string, initialNS bool) (int, bool) {
	if realUID != 0 || sudoUID == "" || !initialNS {
		return realUID, false
	}
	// uid_t is 32-bit unsigned; 4294967295 is the (uid_t)-1 "no owner" sentinel and is never a real user.
	n, err := strconv.ParseUint(sudoUID, 10, 32)
	if err != nil || n == 0xffffffff {
		return realUID, false
	}
	return int(n), true
}
