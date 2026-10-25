// SPDX-License-Identifier: Apache-2.0

package doctor

import "testing"

// TestMemlockNeeded: the limit is lifted only where BPF memory still counts against it, below 5.11, and where the
// release cannot be read (cilium/ebpf/rlimit lifted it whenever its zero-limit map create failed).
func TestMemlockNeeded(t *testing.T) {
	for release, want := range map[string]bool{
		"6.17.0-41-generic": false,
		"5.11.0":            false,
		"5.14.21-150500":    false,
		"5.10.209":          true,
		"4.19.0":            true,
		"garbage":           true,
	} {
		if got := memlockNeeded(release); got != want {
			t.Errorf("memlockNeeded(%q) = %v, want %v", release, got, want)
		}
	}
}
