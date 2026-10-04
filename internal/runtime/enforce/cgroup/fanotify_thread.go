// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"os"
	"strconv"
	"strings"
)

// threadGroupOf resolves FAN_REPORT_TID's thread to its process for ledger attribution.
// Membership and exec deduplication use the thread itself, never this best-effort lookup.
func threadGroupOf(tid int) int {
	b, err := os.ReadFile("/proc/" + strconv.Itoa(tid) + "/status")
	if err != nil {
		return 0
	}
	for line := range strings.SplitSeq(string(b), "\n") {
		if value, ok := strings.CutPrefix(line, "Tgid:"); ok {
			pid, err := strconv.Atoi(strings.TrimSpace(value))
			if err == nil && pid > 0 {
				return pid
			}
			return 0
		}
	}
	return 0
}
