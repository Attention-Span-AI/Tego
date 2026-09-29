// SPDX-License-Identifier: Apache-2.0

package landlock

import "testing"

// TestFilterRefusesClone3 holds the filter to answering clone3 with ENOSYS on both arches. clone3's flags
// live in user memory the filter cannot read, and CLONE_INTO_CGROUP is checked by the kernel with
// inode_permission, which Landlock does not hook, so an allowed clone3 lets a process of the run start a
// child in any cgroup its uid may write (at tier 1, every leaf of user@<uid>.service). ENOSYS makes glibc
// and Go fall back to clone(2), which has no cgroup argument. It was allowed before this filter arm existed.
func TestFilterRefusesClone3(t *testing.T) {
	for _, tc := range []struct {
		arch Arch
		nr   uint32
	}{{ArchX86_64, 435}, {ArchARM64, 435}} {
		for _, full := range []bool{false, true} {
			got := runFilter(t, tc.arch, full, seccompData(tc.arch, tc.nr))
			if got != retENOSYS {
				t.Errorf("%s full=%v: clone3 -> %#x, want ENOSYS %#x", tc.arch, full, got, retENOSYS)
			}
		}
	}
}
