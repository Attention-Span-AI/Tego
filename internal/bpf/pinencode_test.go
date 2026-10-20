// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/attention-span-ai/tego/internal/execpin"
)

// The supervisor encodes a pin with internal/execpin and the plane's adapter writes those bytes as the map value: the
// encoding must be struct tego_exec_pin's layout, which ExecPin mirrors (TestStructSizes, the tegobpf parity rows),
// and its forms, flags, bounds and key halves the plane's.
func TestExecPinEncodingIsTheMapsLayout(t *testing.T) {
	p := execpin.Pin{Form: 2, Flags: 3, NChain: 4, K: 5, Argc: 6, LenCov: 7, LenTail: 8, LenPath: 9,
		Image: execpin.Ident{Dev: 10, Ino: 11}, MACCov: 12, MACTail: 13, MACName: 14, MACPath: 15}
	for i := range p.Chain {
		p.Chain[i] = execpin.Ident{Dev: uint64(20 + 2*i), Ino: uint64(21 + 2*i)}
	}
	b := p.Encode()
	execpin.SetGenSeq(b, 31, 32)
	var got ExecPin
	if err := binary.Read(bytes.NewReader(b), binary.LittleEndian, &got); err != nil {
		t.Fatal(err)
	}
	want := ExecPin{Gen: 31, Seq: 32, Form: 2, Flags: 3, NChain: 4, K: 5, Argc: 6, LenCov: 7, LenTail: 8, LenPath: 9,
		Image: PinIdent{Dev: 10, Ino: 11}, MACCov: 12, MACTail: 13, MACName: 14, MACPath: 15}
	for i := range want.Chain {
		want.Chain[i] = PinIdent{Dev: uint64(20 + 2*i), Ino: uint64(21 + 2*i)}
	}
	if got != want || len(b) != binary.Size(want) {
		t.Fatalf("decoded %+v from %d bytes, want %+v", got, len(b), want)
	}
	if execpin.FormDirect != PinFormDirect || execpin.FormScript != PinFormScript || execpin.FormUnknown != PinFormUnknown ||
		execpin.FlagGuard != PinGuard || execpin.FlagInterpOK != PinInterpOK || execpin.FlagArgv0Filename != PinArgv0Filename ||
		execpin.ChainMax != PinChainMax {
		t.Fatal("execpin's forms, flags or chain bound differ from the plane's")
	}
	k := execpin.Key{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	k0, k1 := k.Halves()
	var kv PinKeyval
	if err := binary.Read(bytes.NewReader(append(make([]byte, 8), k[:]...)), binary.LittleEndian, &kv); err != nil || kv.K0 != k0 || kv.K1 != k1 {
		t.Fatalf("key halves %#x %#x, the keyval reads %#x %#x (%v)", k0, k1, kv.K0, kv.K1, err)
	}
}
