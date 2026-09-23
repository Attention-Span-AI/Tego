// SPDX-License-Identifier: Apache-2.0

//go:build tegobpf && (386 || amd64 || arm64)

package bpf

import (
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
)

// TestSSLLayoutParity is TestLayoutParity for the capture structs. It lives apart because bpf2go emits the
// uprobessl mirrors only for the architectures gen.go compiles that object for, the same set this file's
// build constraint names.
func TestSSLLayoutParity(t *testing.T) {
	cases := []struct {
		name      string
		mine, gen uintptr
	}{
		{name: "SSLEvent", mine: unsafe.Sizeof(SSLEvent{}), gen: unsafe.Sizeof(uprobesslTegoEvSslChunk{})},
		{name: "SSLKey", mine: unsafe.Sizeof(SSLKey{}), gen: unsafe.Sizeof(uprobesslTegoSslKey{})},
		{name: "SSLScratch", mine: unsafe.Sizeof(SSLScratch{}), gen: unsafe.Sizeof(uprobesslTegoSslScratch{})},
		{name: "SSLClose", mine: unsafe.Sizeof(SSLClose{}), gen: unsafe.Sizeof(uprobesslTegoEvSslClose{})},
	}
	for _, tc := range cases {
		if tc.mine != tc.gen {
			t.Errorf("%s: types.go says %d bytes, bpf2go's BTF mirror says %d", tc.name, tc.mine, tc.gen)
		}
	}
	// Offsets a size comparison cannot catch: DecodeSSLChunk reads Skipped at its offset, and two fields
	// swapped keep the size.
	var (
		mine SSLEvent
		gen  uprobesslTegoEvSslChunk
	)
	fields := []struct {
		name      string
		mine, gen uintptr
	}{
		{"SSLMeta.Truncated", unsafe.Offsetof(mine.Meta.Truncated), unsafe.Offsetof(gen.Meta.Truncated)},
		{"SSLMeta.Hole", unsafe.Offsetof(mine.Meta.Hole), unsafe.Offsetof(gen.Meta.Hole)},
		{"SSLMeta.Seq", unsafe.Offsetof(mine.Meta.Seq), unsafe.Offsetof(gen.Meta.Seq)},
		{"SSLMeta.Skipped", unsafe.Offsetof(mine.Meta.Skipped), unsafe.Offsetof(gen.Meta.Skipped)},
		{"SSLEvent.Data", unsafe.Offsetof(mine.Data), unsafe.Offsetof(gen.Data)},
	}
	for _, tc := range fields {
		if tc.mine != tc.gen {
			t.Errorf("%s at %d in ssl.go, %d in bpf2go's mirror", tc.name, tc.mine, tc.gen)
		}
	}
}

// TestCaptureLostShape: capture's own lost counter has the record's counter's shape, one u64 per run_idx, which
// the capture source reads at its slot, and is pinned by name beside the ring outer (ADR 0026 (4)).
func TestCaptureLostShape(t *testing.T) {
	spec, err := Load(ObjectUprobeSSL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := spec.Maps[MapCaptureLost]
	if m == nil {
		t.Fatalf("%s declares no %s", ObjectUprobeSSL, MapCaptureLost)
	}
	if m.Type != ebpf.Array || m.KeySize != 4 || m.ValueSize != 8 || m.MaxEntries != MaxSlots || m.Pinning != ebpf.PinByName {
		t.Errorf("%s: %s key %d value %d entries %d pinning %v, want a pinned array of one u64 per run_idx",
			MapCaptureLost, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Pinning)
	}
}

// TestSSLSeqShape: each connection's chunk counter is keyed by SSLKey, the connection as httpstream keys it,
// holds a u32, and has SSLSeqMax rows in an LRU map.
func TestSSLSeqShape(t *testing.T) {
	spec, err := Load(ObjectUprobeSSL)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	m := spec.Maps[MapSSLSeq]
	if m == nil {
		t.Fatalf("%s declares no %s", ObjectUprobeSSL, MapSSLSeq)
	}
	if m.Type != ebpf.LRUHash || m.KeySize != uint32(unsafe.Sizeof(SSLKey{})) || m.ValueSize != 4 ||
		m.MaxEntries != SSLSeqMax || m.Pinning != ebpf.PinByName {
		t.Errorf("%s: %s key %d value %d entries %d pinning %v, want a pinned LRU of %d SSLKey -> u32 rows",
			MapSSLSeq, m.Type, m.KeySize, m.ValueSize, m.MaxEntries, m.Pinning, SSLSeqMax)
	}
}
