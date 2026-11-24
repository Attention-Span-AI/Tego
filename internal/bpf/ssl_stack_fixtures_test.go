// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// These are read-back inputs from real kernels, including their translated
// helper offsets. They exercise the scanner without loading a program on the host.
func TestCapturedKernelStackReadback(t *testing.T) {
	root := filepath.Join("testdata", "capture-stack")
	manifest, err := os.ReadFile(filepath.Join(root, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []struct {
		Row                 string `json:"row"`
		Program             string `json:"program"`
		Bytes               int    `json:"bytes"`
		SHA256              string `json:"sha256"`
		TailCallInstruction uint64 `json:"tail_call_instruction"`
		Fixture             string `json:"fixture"`
	}
	if err := json.Unmarshal(manifest, &fixtures); err != nil {
		t.Fatal(err)
	}
	rows := []string{"rhel-9", "al2023", "ubuntu-24.04", "debian-13", "al2023-6.12", "ubuntu-25.10", "fedora-7.0", "fedora-7.2"}
	want := make(map[string]bool)
	for _, row := range rows {
		for _, program := range SSLPrograms {
			want[row+"/"+program+".bin"] = true
		}
	}
	if len(fixtures) != len(want) {
		t.Fatalf("manifest has %d fixtures, want %d", len(fixtures), len(want))
	}
	read := captureInstructions
	t.Cleanup(func() { captureInstructions = read })
	for _, fixture := range fixtures {
		key := fixture.Row + "/" + fixture.Program + ".bin"
		if fixture.Fixture != key || !want[key] {
			t.Fatalf("unexpected or duplicate fixture: %+v", fixture)
		}
		delete(want, key)
		t.Run(fixture.Row+"/"+fixture.Program, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(fixture.Fixture)))
			if err != nil {
				t.Fatal(err)
			}
			if len(raw) != fixture.Bytes {
				t.Fatalf("fixture has %d bytes, manifest records %d", len(raw), fixture.Bytes)
			}
			digest := sha256.Sum256(raw)
			if got := hex.EncodeToString(digest[:]); got != fixture.SHA256 {
				t.Fatalf("fixture SHA256 %s, manifest records %s", got, fixture.SHA256)
			}
			insns, err := asm.AppendInstructions(nil, bytes.NewReader(raw), binary.LittleEndian, "linux")
			if err != nil {
				t.Fatalf("decode kernel instructions: %v", err)
			}
			tailCalls, tailIndex := 0, -1
			iter := insns.Iterate()
			for iter.Next() {
				if iter.Ins.IsBuiltinCall() && iter.Ins.Constant == int64(asm.FnTailCall) {
					tailCalls++
					tailIndex = iter.Index
					if uint64(iter.Offset) != fixture.TailCallInstruction {
						t.Fatalf("tail call at raw instruction %d, manifest records %d", iter.Offset, fixture.TailCallInstruction)
					}
				}
			}
			if tailCalls != 1 {
				t.Fatalf("fixture has %d tail calls, want one", tailCalls)
			}
			captureInstructions = func(*ebpf.Program) (asm.Instructions, error) { return insns, nil }
			if err := CheckCaptureStack(fixture.Program, nil); err != nil {
				t.Fatalf("retained kernel call rejected: %v", err)
			}
			// Keep all other translated instructions so a false match against a
			// different kernel helper cannot satisfy the negative control.
			withoutCall := append(asm.Instructions(nil), insns[:tailIndex]...)
			withoutCall = append(withoutCall, insns[tailIndex+1:]...)
			captureInstructions = func(*ebpf.Program) (asm.Instructions, error) { return withoutCall, nil }
			err = CheckCaptureStack(fixture.Program, nil)
			if err == nil || !strings.Contains(err.Error(), "no tail call") || !strings.Contains(err.Error(), fixture.Program) {
				t.Fatalf("removed kernel call error %v, want no tail call naming %s", err, fixture.Program)
			}
		})
	}
}
