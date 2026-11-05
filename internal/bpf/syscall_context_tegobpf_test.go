// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf

package bpf

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/cilium/ebpf/btf"
)

// Individual syscalls use perf_call_bpf_exit's syscall_tp_t, not the
// raw_syscalls event. RHEL's larger trace_entry separates their ret offsets.
// Relocate the compiled context reads against both layouts without requiring
// root or a RHEL host, including the reader used under confidentiality lockdown.
func TestSyscallResultContextRelocation(t *testing.T) {
	for _, headerSize := range []uint32{8, 12} {
		t.Run(fmt.Sprintf("trace_entry_%d", headerSize), func(t *testing.T) {
			long := &btf.Int{Name: "long int", Size: 8, Encoding: btf.Signed}
			integer := &btf.Int{Name: "int", Size: 4, Encoding: btf.Signed}
			header := &btf.Struct{Name: "trace_entry", Size: headerSize}
			rawID := (headerSize + 7) &^ 7
			types := []btf.Type{
				&btf.Struct{Name: "trace_event_raw_sys_exit", Size: rawID + 16, Members: []btf.Member{
					{Name: "ent", Type: header},
					{Name: "id", Type: long, Offset: btf.Bits(rawID * 8)},
					{Name: "ret", Type: long, Offset: btf.Bits((rawID + 8) * 8)},
				}},
				&btf.Struct{Name: "syscall_trace_exit", Size: 24, Members: []btf.Member{
					{Name: "ent", Type: header},
					{Name: "nr", Type: integer, Offset: btf.Bits(headerSize * 8)},
					{Name: "ret", Type: long, Offset: 16 * 8},
				}},
			}
			builder, err := btf.NewBuilder(types, nil)
			if err != nil {
				t.Fatal(err)
			}
			data, err := builder.Marshal(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			target, err := btf.LoadSpecFromReader(bytes.NewReader(data))
			if err != nil {
				t.Fatal(err)
			}
			for _, reader := range Readers {
				spec, err := LoadReader(ObjectTraceProc, reader)
				if err != nil {
					t.Fatal(err)
				}
				for _, name := range []string{ProgExecResult, ProgExecatResult, ProgBindResult, ProgListenResult} {
					t.Run(string(reader)+"/"+name, func(t *testing.T) {
						reads := 0
						for _, ins := range spec.Programs[name].Instructions {
							relo := btf.CORERelocationMetadata(&ins)
							if relo == nil || (!strings.Contains(relo.String(), `Struct:"trace_event_raw_sys_exit"`) &&
								!strings.Contains(relo.String(), `Struct:"syscall_trace_exit"`)) {
								continue
							}
							fixups, err := btf.CORERelocate([]*btf.CORERelocation{relo}, []*btf.Spec{target}, spec.ByteOrder, spec.Types.TypeID)
							if err != nil {
								t.Fatal(err)
							}
							if err := fixups[0].Apply(&ins); err != nil {
								t.Fatal(err)
							}
							if ins.Offset != 16 {
								t.Errorf("%s reads context offset %d; perf_call_bpf_exit supplies ret at 16", relo, ins.Offset)
							}
							reads++
						}
						if reads == 0 {
							t.Fatal("no relocated syscall result read found")
						}
					})
				}
			}
		})
	}
}
