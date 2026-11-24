// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// PROC_PID_INIT_INO, include/linux/proc_ns.h: root-tier maps and records use
// the kernel's PID identities (ADR 0025), not a distribution's local numbers.
const initialPIDNamespace = uint64(0xEFFFFFFC)

const rootTierNamespaceFix = "run Tego without sudo for tier landlock; root tiers require the machine's own process-id namespace"

func ownPIDNamespace() (uint64, error) {
	var st unix.Stat_t
	if err := unix.Stat("/proc/self/ns/pid", &st); err != nil {
		return 0, err
	}
	return st.Ino, nil
}

func currentPIDNamespaceWhy() string { return pidNamespaceWhy(ownPIDNamespace()) }

func pidNamespaceWhy(inode uint64, err error) string {
	if err != nil {
		return fmt.Sprintf("root tiers (cgroup, bpflsm) are unavailable: cannot read this process-id namespace: %v", err)
	}
	if inode != initialPIDNamespace {
		return "root tiers (cgroup, bpflsm) are unavailable in a private process-id namespace"
	}
	return ""
}
