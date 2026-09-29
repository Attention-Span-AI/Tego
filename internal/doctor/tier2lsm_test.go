// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestTierTwoDoesNotDependOnTheBPFLSM is enforce-cgroup-observe.md §6 E3: bpf being an active LSM on a tier-2
// host has no effect, since fentry is BPF_TRACE_FENTRY, orthogonal to LSM registration. Tier 2's tracing
// hooks are all fentry, raw tracepoint, cgroup or uprobe programs and none is an LSM program, and the
// derivation of tier cgroup gives the same answer whether or not the active LSM list carries bpf.
func TestTierTwoDoesNotDependOnTheBPFLSM(t *testing.T) {
	for _, h := range hooks {
		if h.Tier == backend.TierCgroup && h.kind != hookFEntry && h.kind != hookFExit && h.kind != hookRawTP && h.kind != hookCgroupAddr && h.kind != hookCgroupSock && h.kind != hookCgroupSockopt && h.kind != hookCgroupSKB && h.kind != hookSockOps && h.kind != hookTracepoint {
			t.Errorf("tier-2 hook %s is not a fentry, fexit, raw tracepoint or cgroup program, so tier 2 would depend on bpf being in the LSM list", h.Name)
		}
	}
	with := state(nil)
	without := state(func(st *probeState) {
		st.lsm = LSMState{Modules: []string{"capability", "landlock", "yama"}, Source: LSMSourceSyscall}
	})
	if !with.lsm.BPFActive || without.lsm.BPFActive {
		t.Fatal("the two states do not differ in bpf being active")
	}
	if a, b := with.missingFor(backend.TierCgroup), without.missingFor(backend.TierCgroup); !slices.Equal(a, b) {
		t.Errorf("tier cgroup's gaps depend on the LSM list: with bpf %q, without %q", a, b)
	}
	if !with.probe()[backend.TierCgroup] || !without.probe()[backend.TierCgroup] {
		t.Errorf("tier cgroup is offered %v with bpf in the LSM list and %v without, want both",
			with.probe()[backend.TierCgroup], without.probe()[backend.TierCgroup])
	}
	if without.probe()[backend.TierBPFLSM] {
		t.Error("tier bpflsm is offered without bpf in the LSM list")
	}
}
