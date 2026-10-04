// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestDirWalkFencesItsSequenceReads is enforce-plane §2.15's ordering (never a wrong path): the directory walk reads
// each level's d_seq before its parent and name, and compares them on a second pass, a seqcount reader's protocol,
// which needs read_seqcount_begin's smp_rmb between the sequence and the data and read_seqcount_retry's between the
// data and the re-read. A BPF program has no barrier instruction, but an atomic with BPF_FETCH is fully ordered (the
// arm64 JIT emits ldaddal or an exclusive pair with dmb ish, x86 a lock xadd), so each fence is one fetch-add on the
// walk's stack. The compiled walk, in both builds, must carry one in the step (after a level's sequence) and one in
// tego_dir_walk (before the second pass): a plain add, which clang emits when the result goes unused, is relaxed
// on arm64 and orders nothing.
func TestDirWalkFencesItsSequenceReads(t *testing.T) {
	checked := 0
	builds := map[string]func() (*ebpf.CollectionSpec, error){"trace": loadTrace, "tracerd": loadTracerd}
	for o, load := range builds {
		spec, err := load()
		if err != nil {
			t.Fatalf("load %s: %v", o, err)
		}
		prog, ok := spec.Programs["tego_path_unlink"]
		if !ok {
			continue
		}
		checked++
		fences := map[string]int{}
		fn := ""
		for _, ins := range prog.Instructions {
			if s := ins.Symbol(); s != "" {
				fn = s
			}
			if op := ins.OpCode.AtomicOp(); op == asm.FetchAdd || op == asm.FetchOr || op == asm.Xchg {
				fences[fn]++
			}
		}
		for _, f := range []string{"tego_dir_step", "tego_dir_walk"} {
			if fences[f] == 0 {
				t.Errorf("%s: %s has no fully ordered atomic (a fetch): the sequence reads are unordered on arm64 (%v)",
					o, f, fences)
			}
		}
	}
	if checked != len(builds) {
		t.Fatalf("%d of %d builds have tego_path_unlink", checked, len(builds))
	}
}
