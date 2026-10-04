// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
)

// The production loader receives a spec that was copied after another caller
// changed maps, constants, attach targets and instruction metadata. Loading it
// proves the warm copy still contains usable BTF/CO-RE and original instructions.
func TestObjectSpecCacheLoadsFreshCopyOnThisKernel(t *testing.T) {
	requireBPF(t)
	first, err := Load(ObjectCgroupTrack)
	if err != nil {
		t.Fatal(err)
	}
	mutateEmbeddedSpec(t, first)
	fresh, err := Load(ObjectCgroupTrack)
	if err != nil {
		t.Fatal(err)
	}
	want, err := generated[ObjectCgroupTrack].load()
	if err != nil {
		t.Fatal(err)
	}
	assertParsedSpec(t, fresh, want)
	unpin(fresh)
	coll, err := ebpf.NewCollection(fresh)
	if err != nil {
		t.Fatalf("load warm independent spec: %+v", err)
	}
	defer coll.Close()
	for name, program := range coll.Programs {
		if program.FD() < 0 {
			t.Errorf("program %s has no descriptor", name)
		}
	}
	for name, m := range coll.Maps {
		if m.FD() < 0 {
			t.Errorf("map %s has no descriptor", name)
		}
	}
}
