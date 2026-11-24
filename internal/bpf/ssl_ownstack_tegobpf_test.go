// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf && (386 || amd64 || arm64)

package bpf

import (
	"bytes"
	_ "embed"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

//go:embed uprobessl_x86_bpfel.o
var captureX86ELF []byte

//go:embed uprobessl_arm64_bpfel.o
var captureArm64ELF []byte

// TestCaptureProgramsKeepTheirOwnStack checks both ELF objects as a cheap first
// line. It does not prove that a kernel retains the call or excludes private
// stacks. The loader checks translated instructions and the matrix tests that
// invariant on each kernel. No branch may make the entry's call dead.
func TestCaptureProgramsKeepTheirOwnStack(t *testing.T) {
	for file, raw := range map[string][]byte{"uprobessl_x86_bpfel.o": captureX86ELF, "uprobessl_arm64_bpfel.o": captureArm64ELF} {
		t.Run(file, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(raw))
			if err != nil {
				t.Fatalf("LoadCollectionSpec: %v", err)
			}
			for _, name := range []string{MapSSLOwnStack, MapSSLOwnStackMulti} {
				m := spec.Maps[name]
				if m == nil {
					t.Errorf("no map %s", name)
					continue
				}
				if len(m.Contents) != 0 {
					t.Errorf("%s is not empty", name)
				}
				if m.Type != ebpf.ProgramArray || m.MaxEntries != 1 || m.Pinning != ebpf.PinByName {
					t.Errorf("%s is %v with %d entries, pinning %v; want a program array of 1 pinned by name", name,
						m.Type, m.MaxEntries, m.Pinning)
				}
			}
			for _, name := range SSLPrograms {
				prog := spec.Programs[name]
				if prog == nil {
					t.Errorf("no program %s", name)
					continue
				}
				// A program array holds programs of one expected attach type, so the multi pair has its own.
				want := MapSSLOwnStack
				if name == ProgSSLMultiEnter || name == ProgSSLMultiReturn {
					want = MapSSLOwnStackMulti
				}
				calls := 0
				arrays := map[string]bool{}
				beforeCall := true
				for _, ins := range prog.Instructions {
					if beforeCall && ins.OpCode.Class().IsJump() && !ins.IsBuiltinCall() {
						t.Errorf("%s branches before its live tail call", name)
					}
					if ins.IsBuiltinCall() && ins.Constant == int64(asm.FnTailCall) {
						calls++
						beforeCall = false
					}
					if ins.IsLoadFromMap() && (ins.Reference() == MapSSLOwnStack || ins.Reference() == MapSSLOwnStackMulti) {
						arrays[ins.Reference()] = true
					}
				}
				if calls != 1 || !arrays[want] || len(arrays) != 1 {
					t.Errorf("%s has %d tail calls, into %v, want one into %s alone: without one the verifier may give "+
						"it a per-CPU private stack that preempted tasks share", name, calls, arrays, want)
				}
			}
		})
	}
}
