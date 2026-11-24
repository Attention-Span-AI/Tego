// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"errors"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

func TestCaptureStackReadback(t *testing.T) {
	read := captureInstructions
	t.Cleanup(func() { captureInstructions = read })
	denied := errors.New("program info: permission denied")
	for _, tc := range []struct {
		name  string
		insns asm.Instructions
		err   error
		want  string
	}{
		{"retained", asm.Instructions{asm.FnTailCall.Call(), asm.Return()}, nil, ""},
		{"removed", asm.Instructions{asm.Mov.Imm(asm.R0, 0), asm.Return()}, nil, "no tail call"},
		{"unreadable", nil, denied, "read translated instructions"},
		{"hardened readback", nil, ebpf.ErrRestrictedKernel, "read translated instructions"},
		{"empty", nil, nil, "no tail call"},
		{"other helper", asm.Instructions{asm.FnMapLookupElem.Call(), asm.Return()}, nil, "no tail call"},
		{"local call numbered twelve", asm.Instructions{asm.Instruction{OpCode: asm.Call.Op(asm.ImmSource), Src: asm.PseudoCall, Constant: 12}, asm.Return()}, nil, "no tail call"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			captureInstructions = func(*ebpf.Program) (asm.Instructions, error) { return tc.insns, tc.err }
			err := CheckCaptureStack(ProgSSLWrite, nil)
			if tc.want == "" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) || !strings.Contains(err.Error(), ProgSSLWrite) {
				t.Fatalf("readback error %v, want %s naming the program", err, tc.want)
			}
			if tc.err != nil && !errors.Is(err, tc.err) {
				t.Fatalf("lost readback cause: %v", err)
			}
		})
	}
}
