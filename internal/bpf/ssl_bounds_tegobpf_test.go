// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf && (386 || amd64 || arm64)

package bpf

import (
	"slices"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// TestSSLUserReadSizeIsClampedAtTheCall holds the compiled shape the verifiers of 6.1 and 6.8 need from every
// bpf_probe_read_user in the capture object: its size is a constant, or a register the instructions right before
// the call clamp to a size class with nothing in between that could lose the bound. The kernel matrix of
// 2026-09-29 found clang had dropped the source's clamp as dead (the caller's class branches already proved it) and
// passed a copy of the length from another stack slot than the one the branches tested; 6.12+ carries the bound
// across the two slots, 5.14 happened to pass, and 6.1 and 6.8 refused tego_ssl_write, tego_ssl_write_ex
// ("R2 unbounded memory access") and tego_ssl_read_return ("invalid access to memory, mem_size=592 off=80
// size=32768"), which left capture unavailable on the CI distro. No runner kernel shows it, so the object is checked
// here: the clamp must be `if ... rX goto +1; rX = CLASS`, then `r2 = rX` and the call, with no helper call, no
// write to rX and no other jump landing between the clamp and the call (bpf/uprobe_ssl.bpf.c tego_ssl_emit_class).
//
// Both architectures' objects are read from this directory, so an amd64 run checks the arm64 build too.
func TestSSLUserReadSizeIsClampedAtTheCall(t *testing.T) {
	for _, file := range []string{"uprobessl_x86_bpfel.o", "uprobessl_arm64_bpfel.o"} {
		t.Run(file, func(t *testing.T) {
			spec, err := ebpf.LoadCollectionSpec(file)
			if err != nil {
				t.Fatalf("LoadCollectionSpec: %v", err)
			}
			checkSSLUserReadSizes(t, spec)
		})
	}
}

func checkSSLUserReadSizes(t *testing.T, spec *ebpf.CollectionSpec) {
	classes := []int64{SSLClassSmall, SSLClassMedium, SSLChunkMax}
	calls := 0
	for name, prog := range spec.Programs {
		type slot struct {
			off int
			ins asm.Instruction
		}
		var insns []slot
		targets := map[int]int{} // raw offset -> how many jumps land there
		iter := prog.Instructions.Iterate()
		for iter.Next() {
			off, ins := int(iter.Offset), *iter.Ins
			insns = append(insns, slot{off, ins})
			if op := ins.OpCode.JumpOp(); ins.OpCode.Class().IsJump() && op != asm.Call && op != asm.Exit {
				targets[off+int(ins.Offset)+1]++
			}
		}
		isCall := func(ins asm.Instruction) bool { return ins.OpCode.JumpOp() == asm.Call }
		for i, s := range insns {
			if !isCall(s.ins) || !s.ins.IsBuiltinCall() || s.ins.Constant != int64(asm.FnProbeReadUser) {
				continue
			}
			calls++
			// The last write to R2 before the call, looking back no further than the previous call.
			w2 := -1
			for j := i - 1; j >= 0 && !isCall(insns[j].ins); j-- {
				if insns[j].ins.Dst == asm.R2 && writesDst(insns[j].ins) {
					w2 = j
					break
				}
			}
			if w2 < 0 {
				t.Errorf("%s: bpf_probe_read_user at %d: its size is not set after the previous call", name, s.off)
				continue
			}
			mov := insns[w2].ins
			if mov.OpCode.ALUOp() != asm.Mov {
				t.Errorf("%s: bpf_probe_read_user at %d: R2 comes from %v, not a move", name, s.off, mov)
				continue
			}
			if mov.OpCode.Source() == asm.ImmSource {
				if mov.Constant <= 0 || mov.Constant > SSLChunkMax {
					t.Errorf("%s: bpf_probe_read_user at %d: constant size %d", name, s.off, mov.Constant)
				}
				continue
			}
			src := mov.Src
			wx := -1
			for j := w2 - 1; j >= 0 && !isCall(insns[j].ins); j-- {
				if insns[j].ins.Dst == src && writesDst(insns[j].ins) {
					wx = j
					break
				}
			}
			ok := wx > 0
			if ok {
				clamp, jump := insns[wx].ins, insns[wx-1].ins
				// The jump tests rX itself, or a register rX was copied from right before it: a register move
				// shares the scalar's id, so the verifier narrows both (5.11+).
				tests := func(r asm.Register) bool {
					return jump.Dst == r || (jump.OpCode.Source() == asm.RegSource && jump.Src == r)
				}
				tested := tests(src)
				if !tested && wx >= 2 {
					cp := insns[wx-2].ins
					tested = cp.OpCode.ALUOp() == asm.Mov && cp.OpCode.Class() == asm.ALU64Class &&
						cp.OpCode.Source() == asm.RegSource && cp.Dst == src && tests(cp.Src) &&
						targets[insns[wx-1].off] == 0
				}
				ok = clamp.OpCode.ALUOp() == asm.Mov && clamp.OpCode.Source() == asm.ImmSource &&
					slices.Contains(classes, clamp.Constant) &&
					jump.OpCode.Class().IsJump() && jump.Offset == 1 && tested
			}
			if ok {
				// Nothing may jump into the stretch past the clamp but the clamp's own skip.
				for j := wx + 1; j <= i; j++ {
					want := 0
					if j == wx+1 {
						want = 1
					}
					if targets[insns[j].off] != want {
						ok = false
					}
				}
			}
			if !ok {
				t.Errorf("%s: bpf_probe_read_user at %d: its size register %v is not clamped to a size class right "+
					"before the call; 6.1 and 6.8 verifiers refuse this (barrier_var(n) and the clamp in "+
					"tego_ssl_emit_class)", name, s.off, src)
			}
		}
	}
	// Three classes, four chunks, three capturing programs, plus SSL_read_ex's *readbytes.
	if calls < 3*len(classes) {
		t.Fatalf("found %d bpf_probe_read_user calls in the capture object; the check looked at the wrong thing", calls)
	}
}

// writesDst reports whether ins assigns its destination register: an ALU operation or a load.
func writesDst(ins asm.Instruction) bool {
	c := ins.OpCode.Class()
	return c == asm.ALUClass || c == asm.ALU64Class || c == asm.LdClass || c == asm.LdXClass
}
