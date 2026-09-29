// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"testing"

	"github.com/cilium/ebpf/asm"
)

// TestLostCounterIncrementIsAtomic: every program that counts a failed ring-buffer reserve in a lost counter
// does it with an atomic add (tego_lost_inc in bpf/include/common.h). The slot is per-CPU, but a BPF program
// runs with migration disabled, not preemption, so a second program on the same CPU can run between a plain
// increment's load and its store and one of the two increments is lost: a dropped record the ledger's gap never
// counts.
func TestLostCounterIncrementIsAtomic(t *testing.T) {
	lost := map[string]bool{MapLost: true, MapCaptureLost: true}
	checked := 0
	for _, o := range Objects() {
		spec, err := Load(o)
		if err != nil {
			t.Fatalf("Load(%s): %v", o, err)
		}
		for name, prog := range spec.Programs {
			counts, atomic := false, false
			for _, ins := range prog.Instructions {
				if ins.IsLoadFromMap() && lost[ins.Reference()] {
					counts = true
				}
				if ins.OpCode.AtomicOp() == asm.AddAtomic {
					atomic = true
				}
			}
			if !counts {
				continue
			}
			checked++
			if !atomic {
				t.Errorf("%s/%s counts lost records without an atomic add", o, name)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no program references a lost counter: the test checks nothing")
	}
}
