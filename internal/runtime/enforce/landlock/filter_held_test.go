// SPDX-License-Identifier: Apache-2.0

package landlock

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/policy/gate"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestHeldCompletionRefusesNestedLandlockDomains: under gate.completion: held the run's open deputy makes every held
// open in the run's Landlock domain, the one the child stage made. A process of the run that made a domain of its own
// beneath it (landlock_restrict_self, allowed under no_new_privs) was held only to the outer domain for those opens:
// `setpriv --landlock-access fs:read-file` with read rules on /usr, /lib and /etc alone was refused a read of the
// worktree under the copied completion and had its bytes delivered under held. The filter of
// such a run answers the three Landlock syscalls ENOSYS on both architectures, as R10 answers openat2, so no process
// of the run is in a domain the deputy does not share; a run without held completion leaves them to the kernel.
func TestHeldCompletionRefusesNestedLandlockDomains(t *testing.T) {
	if len(landlockSet) != 3 {
		t.Fatalf("landlockSet %v: want the three Landlock syscalls", landlockSet)
	}
	for _, arch := range []Arch{ArchX86_64, ArchARM64} {
		for _, s := range landlockSet {
			if got := planeVerdict(t, arch, filterOpts{abi: 10}, s.NR); got != retAllow {
				t.Errorf("%s %s without held completion: %#x, want allow", arch, s.Name, got)
			}
			if got := planeVerdict(t, arch, filterOpts{abi: 10, heldOpens: true}, s.NR); got != retENOSYS {
				t.Errorf("%s %s under held completion: %#x, want ENOSYS", arch, s.Name, got)
			}
		}
	}
	g, err := gate.New([]gate.Rule{{Predicate: gate.ReadMatches, Argument: "*.env", Score: 90}}, 50, 80)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		gate *gate.Policy
		want bool
	}{{"held", g.WithHeldCompletion(), true}, {"copied", g, false}} {
		h, _ := prepare(t, 7, &agent.RuleTable{Contract: &agent.Contract{}, Gate: tc.gate})
		if h.filterOpts.heldOpens != tc.want {
			t.Errorf("%s: Prepare's filter holds nested domains off %v, want %v", tc.name, h.filterOpts.heldOpens, tc.want)
		}
		want := uint32(retAllow)
		if tc.want {
			want = retENOSYS
		}
		if got := planeVerdict(t, NativeArch(), h.filterOpts, landlockSet[2].NR); got != want {
			t.Errorf("%s: landlock_restrict_self %#x, want %#x", tc.name, got, want)
		}
	}
}
