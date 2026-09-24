// SPDX-License-Identifier: Apache-2.0

package enforce

import (
	"net/netip"
	"slices"
	"testing"
)

// TestCgroupRunCarriesWhatOnlyTier2Reads: the adapter is the one place a RunRef becomes the tier-2
// backend's Run, and the two fields only tier 2 reads go wrong, silently, when dropped there. Without the
// resolvers the kernel had no port-53 row, so every DNS query the supervisor admitted and relayed was refused
// with EPERM while the ledger recorded it allowed (enforce-cgroup-observe §5 R5); without the stage binary a
// launcher whose stage is not its own image would have the tier's detached helpers exec the wrong file.
func TestCgroupRunCarriesWhatOnlyTier2Reads(t *testing.T) {
	ref := RunRef{
		ID: "run-1", Agent: "a", CgroupID: 42, RunDir: "/ledger/run-1", Contract: "/ledger/run-1/contract.yaml",
		CgroupPath: "/tego.slice/run-1.scope", CgroupMount: "/sys/fs/cgroup",
		Resolvers: []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53"), netip.MustParseAddrPort("[2001:db8::53]:53")},
		StageExe:  "/opt/tego/bin/tego",
	}
	got := cgroupRun(ref)
	if !slices.Equal(got.Resolvers, ref.Resolvers) {
		t.Errorf("Resolvers %v, want the run's %v", got.Resolvers, ref.Resolvers)
	}
	if got.StageExe != ref.StageExe {
		t.Errorf("StageExe %q, want %q", got.StageExe, ref.StageExe)
	}
	if got.ID != ref.ID || got.Agent != ref.Agent || got.CgroupID != ref.CgroupID || got.Dir != ref.RunDir ||
		got.Contract != ref.Contract || got.CgroupPath != ref.CgroupPath || got.CgroupMount != ref.CgroupMount {
		t.Errorf("cgroupRun(%+v) = %+v", ref, got)
	}
}
