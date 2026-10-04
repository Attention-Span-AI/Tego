// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"testing"

	bpfobj "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/cilium/ebpf"
)

func TestProbeMapSpecRequiresListenerAndKeepsProductionPinning(t *testing.T) {
	name := bpfobj.MapPlaneListenRows
	inner := &ebpf.MapSpec{Name: "listener_inner", Type: ebpf.Hash, KeySize: 128, ValueSize: 24, MaxEntries: 256}
	spec := &ebpf.CollectionSpec{Maps: map[string]*ebpf.MapSpec{name: {
		Name: name, Type: ebpf.ArrayOfMaps, KeySize: 4, ValueSize: 4, MaxEntries: 4096,
		Pinning: ebpf.PinByName, InnerMap: inner,
	}}}
	private, err := probeMapSpec(spec, name, true)
	if err != nil {
		t.Fatal(err)
	}
	if private.Pinning != ebpf.PinNone || private.InnerMap.KeySize != 128 || private.InnerMap.ValueSize != 24 {
		t.Fatalf("private listener shape: %+v", private)
	}
	private.InnerMap.MaxEntries = 1
	if spec.Maps[name].Pinning != ebpf.PinByName || inner.MaxEntries != 256 {
		t.Fatal("private probe changed the production definition")
	}
	spec.Maps[name].InnerMap = nil
	if _, err := probeMapSpec(spec, name, true); err == nil {
		t.Fatal("missing listener inner accepted")
	}
	delete(spec.Maps, name)
	if _, err := probeMapSpec(spec, name, true); err == nil {
		t.Fatal("missing listener outer accepted")
	}
}

func TestPlaneFillerRequiresOwnedListenerReplacement(t *testing.T) {
	// Validation precedes an ELF load or kernel operation, including untagged builds.
	for _, maps := range [][]*ebpf.Map{nil, {nil}, {nil, nil}} {
		if f, err := newPlaneFiller(bpfobj.ObjectPlaneFillProbe, nil, nil, maps...); err == nil || f != nil {
			t.Fatal("filler accepted a missing or ambiguous owned listener map")
		}
	}
}
