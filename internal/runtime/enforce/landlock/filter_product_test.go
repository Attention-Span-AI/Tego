// SPDX-License-Identifier: Apache-2.0

//go:build !tegotesthooks

package landlock

import "testing"

// TestAProductBuildLeavesNothingOutOfTheFilter: without -tags tegotesthooks nothing sets the filter's test seam, so
// no syscall of the notify arm or the root-tier arm is ever left out, whatever the environment says
// (filter_testhook.go is the only file that sets it, and it is not in this build).
//
// Spec: docs/p0/enforce-landlock.md R11.
func TestAProductBuildLeavesNothingOutOfTheFilter(t *testing.T) {
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		tab, err := tableFor(arch)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range append(append([]sysNR(nil), tab.Notify...), tab.RootDeny...) {
			if filterTestOmit(s.Name) {
				t.Errorf("%s: the product filter leaves %s out", arch, s.Name)
			}
		}
	}
}
