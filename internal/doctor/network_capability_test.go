// SPDX-License-Identifier: Apache-2.0

package doctor

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/cilium/ebpf"
)

func TestOptionalNetworkProofDoesNotDemoteLegacyTier(t *testing.T) {
	legacy := HookResult{Hook: "cgroup/connect4", Tier: backend.TierCgroup, BTF: true, Loaded: true, Attached: true}
	requested := HookResult{Hook: "cgroup_skb/ingress", Tier: backend.TierCgroup, CapabilityOnly: true, BTF: true, Detail: "attach denied"}
	rows := []HookResult{legacy, requested}
	if result := programsVerdict(rows); !result.OK || !strings.Contains(result.Detail, "optional network controls: 0 of 1") {
		t.Fatalf("optional failure hides its result or disables legacy runs: %+v", result)
	}
	st := probeState{hooks: rows}
	if missing := st.missingHooks(backend.TierCgroup); len(missing) != 0 {
		t.Fatalf("optional controls demote legacy tier: %v", missing)
	}
	if got := st.tierRows(backend.TierCgroup); len(got) != 1 || got[0].Hook != legacy.Hook {
		t.Fatalf("legacy tier proof: %+v", got)
	}
	st.hooks = []HookResult{requested}
	if st.testedHooks(backend.TierCgroup) {
		t.Fatal("only optional controls substitute for required destination proof")
	}
	legacy.Attached = false
	if result := programsVerdict([]HookResult{legacy, requested}); result.OK {
		t.Fatal("optional control split accidentally ignores a required hook failure")
	}
}

func TestNetworkControlStandInsUseTheirActualProgramTypes(t *testing.T) {
	for _, tc := range []struct {
		kind    hookKind
		typ     ebpf.ProgramType
		attach  ebpf.AttachType
		neutral int64
	}{
		{hookCgroupSKB, ebpf.CGroupSKB, ebpf.AttachCGroupInetIngress, 1},
		{hookCgroupSKB, ebpf.CGroupSKB, ebpf.AttachCGroupInetEgress, 1},
		{hookSockOps, ebpf.SockOps, ebpf.AttachCGroupSockOps, 0},
		{hookCgroupSock, ebpf.CGroupSock, ebpf.AttachCgroupInetSockRelease, 1},
		{hookCgroupSock, ebpf.CGroupSock, ebpf.AttachCGroupInet4PostBind, 1},
		{hookCgroupSock, ebpf.CGroupSock, ebpf.AttachCGroupInet6PostBind, 1},
		{hookCgroupSockopt, ebpf.CGroupSockopt, ebpf.AttachCGroupSetsockopt, 1},
	} {
		ps := minimalProgram(hook{kind: tc.kind, attachType: tc.attach})
		if ps.Type != tc.typ || ps.AttachType != tc.attach || ps.Instructions[0].Constant != tc.neutral {
			t.Fatalf("wrong probe semantics: %+v", ps)
		}
	}
}

// TestRunCacheKeepsAnAnswerWithAFailedCapabilityOnlyRow: a capability-only network row reads into no tier
// (programsVerdict, missingHooks), so its failure is no reason to refuse the run-probe cache either. Before
// vouches skipped it, one such row failing (a kernel without syscall tracepoints, an attach refused) left tier
// cgroup offered but no answer ever kept, and every root run probed D7, the plane and D8 again with no note
// saying why. The entry keeps the failed row as probed, so the optional-control count a run reads is the same.
func TestRunCacheKeepsAnAnswerWithAFailedCapabilityOnlyRow(t *testing.T) {
	seen := 0
	for i, h := range tierHooks(backend.TierCgroup) {
		if !h.capabilityOnly {
			continue
		}
		seen++
		c, _ := testCache(t)
		k := testKey()
		_, rows, fan, fs := vouchingAnswer()
		rows[i] = HookResult{Hook: h.Name, Tier: h.Tier, CapabilityOnly: true, BTF: true, Loaded: true, Detail: "attach denied"}
		p := programsVerdict(rows)
		if !p.OK {
			t.Fatalf("%s: a failed capability-only row failed D7: %+v", h.Name, p)
		}
		c.record(k, p, rows, passingPlane(""), nil, fan, fs)
		e, ok := c.load(k)
		if !ok {
			t.Errorf("%s: an answer whose only failure is a capability-only row was not kept", h.Name)
			continue
		}
		if !reflect.DeepEqual(e.Hooks, rows) {
			t.Errorf("%s: the kept rows are not the probed ones: %+v", h.Name, e.Hooks)
		}
	}
	if seen == 0 {
		t.Fatal("tier cgroup has no capability-only hook to test")
	}

	// Through a run: the first probes and keeps its answer, the second reads it.
	c, _ := testCache(t)
	var n calls
	ch := passingChecks(&n)
	programs := ch.programs
	ch.programs = func(root bool, uid int, v Version, tier, capture []hook) (Result, []HookResult) {
		_, rows := programs(root, uid, v, tier, capture)
		for i, h := range tier {
			rows[i].CapabilityOnly = h.capabilityOnly
			if h.Name == "cgroup/sock_release" {
				rows[i].Attached, rows[i].Detail = false, "attach denied"
			}
		}
		return programsVerdict(rows), rows
	}
	for run := 1; run <= 2; run++ {
		st := scope{reach: backend.TierCgroup, root: true, checks: ch, cache: c}.run(context.Background())
		allBuilt(&st)
		if !st.probe()[backend.TierCgroup] {
			t.Fatalf("run %d: a failed capability-only row withdrew tier cgroup", run)
		}
		if run == 2 && st.cached == nil {
			t.Errorf("run 2 probed again: calls=%v", n.n)
		}
	}
	if n.n[CheckPrograms] != 1 || n.n[CheckFanotify] != 1 {
		t.Errorf("two runs probed D7 %d and D8 %d times, want once each", n.n[CheckPrograms], n.n[CheckFanotify])
	}
}
