// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"
)

// BenchmarkDecodeHeader measures the per-record cost of the ring-buffer drain path, which docs/P0-DESIGN.md
// §9 budgets by throughput: every record pays this once before dispatch.
func BenchmarkDecodeHeader(b *testing.B) {
	rec, err := binary.Append(nil, binary.NativeEndian,
		ExecEvent{Hdr: Header{Version: EventsVersion, Kind: uint16(KindExec), Size: uint32(unsafe.Sizeof(ExecEvent{}))}})
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := DecodeHeader(rec); err != nil {
			b.Fatalf("DecodeHeader: %v", err)
		}
	}
}

// BenchmarkDecodeExec measures the whole-record decode of the largest event.
func BenchmarkDecodeExec(b *testing.B) {
	rec, err := binary.Append(nil, binary.NativeEndian,
		ExecEvent{Hdr: Header{Version: EventsVersion, Kind: uint16(KindExec), Size: uint32(unsafe.Sizeof(ExecEvent{}))}})
	if err != nil {
		b.Fatalf("encode: %v", err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if _, err := Decode[ExecEvent](rec); err != nil {
			b.Fatalf("Decode: %v", err)
		}
	}
}

// BenchmarkArgv measures the split of a typical agent command line.
func BenchmarkArgv(b *testing.B) {
	var e ExecEvent
	raw := "python3\x00-m\x00pytest\x00-q\x00tests/\x00"
	copy(e.Argv[:], raw)
	e.ArgvLen = uint32(len(raw))
	b.ReportAllocs()
	for b.Loop() {
		_ = Argv(&e)
	}
}

// BenchmarkNetKeys measures rule-table compilation into map rows, which Prepare pays once per run per entry.
func BenchmarkNetKeys(b *testing.B) {
	addr := netip.MustParseAddr("203.0.113.7")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NetKeys(1, ProtoTCP, addr, 443); err != nil {
			b.Fatalf("NetKeys: %v", err)
		}
	}
}

// BenchmarkNetLPMKeys measures the CIDR half of the same path.
func BenchmarkNetLPMKeys(b *testing.B) {
	p := netip.MustParsePrefix("10.0.0.0/8")
	b.ReportAllocs()
	for b.Loop() {
		if _, err := NetLPMKeys(1, ProtoTCP, p, 443); err != nil {
			b.Fatalf("NetLPMKeys: %v", err)
		}
	}
}
