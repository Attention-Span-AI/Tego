// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/cilium/ebpf"
)

func TestNetworkControlNilZeroAndFirstBindAttribution(t *testing.T) {
	if got, err := BuildNetworkControl(&agent.RuleTable{}, 1, 1, 1); err != nil || got != nil {
		t.Fatalf("legacy requested controls: %v %v", got, err)
	}
	zero := uint64(0)
	bytes := agent.ByteSize(0)
	listen, ingress, limits, err := agent.CompileListenerControl(&agent.Contract{Net: &agent.NetSection{
		Listen:  []string{"tcp://0.0.0.0:8080", "tcp://127.0.0.1:8080", "udp://127.0.0.1:0"},
		Ingress: []agent.IngressRule{{From: "127.0.0.1", To: "tcp://127.0.0.1:8080"}},
		Limits:  &agent.NetworkLimits{Connections: &zero, PendingConnects: &zero, DatagramsPerSecond: &zero, Bytes: &bytes}}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := BuildNetworkControl(&agent.RuleTable{Listen: listen, Ingress: ingress, NetLimits: limits}, 1, 4, 3)
	if err != nil {
		t.Fatal(err)
	}
	if out.Config.Flags != 63 || out.Config.Gen != 4 || out.Config.Bytes != 0 || out.Config.Connections != 0 {
		t.Fatalf("zero presence lost: %+v", out.Config)
	}
	key, _ := bpf.NewNetKey(1, bpf.ProtoTCP, netip.MustParseAddr("127.0.0.1"), 8080)
	found := false
	for _, row := range out.Binds {
		if row.Key == key {
			found = true
			if row.Val.RuleIdx != 3 {
				t.Fatalf("overlap changed first matching declaration: %+v", row)
			}
		}
	}
	if !found || out.Ingress[0].Key.BindRule != 3 || out.Ingress[0].Key.Local == ([16]byte{}) || out.Ingress[0].Key.Port != 8080 {
		t.Fatalf("ingress widened exact listener: %+v", out)
	}
}

func TestListenerGuaranteeRequiresCleanupAndActualPlaneHooks(t *testing.T) {
	attached := map[string]bool{}
	for _, name := range append(slices.Clone(bpf.CgroupPrograms), bpf.NetControlPrograms...) {
		attached[name] = true
	}
	k := &bpfKernel{netAttached: attached, networkFlags: bpf.NetControlListen | bpf.NetControlIngress, bindCleanup: true, listenCleanup: true}
	h := &Handle{prepared: true, kern: k, table: &agent.RuleTable{Listen: []agent.ListenRule{{Proto: agent.ProtoTCP}}}}
	if h.NetworkGuarantees().ListenerBind || h.NetworkGuarantees().IngressSources {
		t.Fatal("bind programs alone claim implicit listener admission")
	}
	p := &fakePlane{attached: map[string]bool{"socket_listen": true}}
	h.plane = p
	if !h.NetworkGuarantees().ListenerBind || !h.NetworkGuarantees().IngressSources {
		t.Fatal("actual IP listener admission missing")
	}
	h.table.Listen = append(h.table.Listen, agent.ListenRule{Proto: agent.ProtoUnix})
	if h.NetworkGuarantees().ListenerBind {
		t.Fatal("Unix listener declared without copied-name kernel proof")
	}
	p.attached["socket_bind"], p.attached["path_mknod"] = true, true
	if !h.NetworkGuarantees().ListenerBind {
		t.Fatal("actual Unix listener hooks not recognized")
	}
	if !h.BindOutcomes() || !h.ListenOutcomes() {
		t.Fatal("actual terminal producers and Unix hooks not recognized")
	}
	k.listenCleanup = false
	if h.NetworkGuarantees().ListenerBind || h.NetworkGuarantees().IngressSources || h.ListenOutcomes() {
		t.Fatal("terminal listen producer not required")
	}
	k.listenCleanup = true
	k.bindCleanup = false
	if h.NetworkGuarantees().ListenerBind || h.NetworkGuarantees().IngressSources {
		t.Fatal("stale per-task bind marker cleanup not required")
	}
}

func TestNetworkControlsSelectOnlyRequiredMechanisms(t *testing.T) {
	all := map[string]*ebpf.ProgramSpec{}
	for _, name := range append(slices.Clone(bpf.CgroupPrograms), bpf.NetControlPrograms...) {
		all[name] = &ebpf.ProgramSpec{Name: name}
	}
	for name := range bpf.ListenerTracepoints {
		all[name] = &ebpf.ProgramSpec{Name: name}
	}
	for _, tc := range []struct {
		flags uint32
		want  []string
	}{
		{0, nil},
		{bpf.NetControlListen, []string{bpf.ProgPostBind4, bpf.ProgPostBind6, bpf.ProgNetRelease, bpf.ProgNetSockOps}},
		{bpf.NetControlBytes, []string{bpf.ProgNetEgress}},
		{bpf.NetControlIngress, []string{bpf.ProgNetIngress, bpf.ProgNetEgress, bpf.ProgNetSockOps, bpf.ProgNetRelease, bpf.ProgPostBind4, bpf.ProgPostBind6}},
		{bpf.NetControlPending, []string{bpf.ProgNetIngress, bpf.ProgNetEgress, bpf.ProgNetSockOps, bpf.ProgNetRelease}},
	} {
		spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}}
		for name, value := range all {
			spec.Programs[name] = value
		}
		selectNetworkControlPrograms(spec, &NetworkControlMaps{Config: bpf.NetControl{Flags: tc.flags}})
		for name := range bpf.ListenerTracepoints {
			if (spec.Programs[name] != nil) != (tc.flags&bpf.NetControlListen != 0) {
				t.Fatalf("listener cleanup selection flags=%d program=%s", tc.flags, name)
			}
		}
		for _, name := range bpf.CgroupPrograms {
			if spec.Programs[name] == nil {
				t.Fatalf("optional selection removed required core %s", name)
			}
		}
		for _, name := range bpf.NetControlPrograms {
			if (spec.Programs[name] != nil) != slices.Contains(tc.want, name) {
				t.Fatalf("flags %d program %s", tc.flags, name)
			}
		}
	}
}

func TestExpiryRefreshDoesNotLoseNetworkControlsOrReuseTimeline(t *testing.T) {
	control := &NetworkControlMaps{RunIdx: 4, Config: bpf.NetControl{Gen: 2}}
	old := RuleMaps{Control: control, Timelines: []TimelineRow{{Key: bpf.NetTimelineKey{RunIdx: 4, Index: 3}}}}
	next := RuleMaps{Timelines: []TimelineRow{{Key: bpf.NetTimelineKey{RunIdx: 4, Index: 1}}}, Exact: []NetRow{{Val: bpf.NetVerdict{Timeline: 1}}}}
	high := uint32(3)
	if err := rebaseTimelines(&next, &high); err != nil {
		t.Fatal(err)
	}
	union := unionRows(old, next)
	if high != 4 || next.Exact[0].Val.Timeline != 4 || next.Timelines[0].Key.Index != 4 || len(union.Timelines) != 2 || union.Control != control {
		t.Fatalf("refresh reused/dropped live state: %+v high=%d", union, high)
	}
}
