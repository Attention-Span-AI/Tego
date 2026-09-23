// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"testing"
	"unicode/utf8"
	"unsafe"
)

// FuzzDecodeHeader exercises the one reader of kernel-supplied bytes in this package (§8 I11). A ring-buffer
// record arrives from the kernel with no length negotiation, so the decoder's only contract is that it never
// panics and never reports success for a record it cannot fully account for.
func FuzzDecodeHeader(f *testing.F) {
	seeds := []any{
		ExecEvent{Hdr: header(KindExec, uint32(unsafe.Sizeof(ExecEvent{})))},
		ExitEvent{Hdr: header(KindExit, uint32(unsafe.Sizeof(ExitEvent{})))},
		ExecResultEvent{Hdr: header(KindExecResult, uint32(unsafe.Sizeof(ExecResultEvent{}))), StartNS: 7, Ret: -26},
		FSEvent{Hdr: header(KindOpen, uint32(unsafe.Sizeof(FSEvent{})))},
		FSOpEvent{Hdr: header(KindUnlink, uint32(unsafe.Sizeof(FSOpEvent{})))},
		NetEvent{Hdr: header(KindConnect, uint32(unsafe.Sizeof(NetEvent{})))},
		CgroupEvent{Hdr: header(KindCgroupMkdir, uint32(unsafe.Sizeof(CgroupEvent{})))},
		SockEvent{Hdr: header(KindSockCreate, uint32(unsafe.Sizeof(SockEvent{}))), Family: 2, Type: 1, Protocol: 262},
		SockoptEvent{Hdr: header(KindSockopt, uint32(unsafe.Sizeof(SockoptEvent{}))), Level: 6, Optname: 31, Optlen: 4,
			Name: [16]byte{'s', 'm', 'c'}},
	}
	for _, s := range seeds {
		b, err := binary.Append(nil, binary.NativeEndian, s)
		if err != nil {
			f.Fatalf("seed: %v", err)
		}
		f.Add(b)
	}
	f.Add([]byte{})
	f.Add(make([]byte, HeaderSize))

	f.Fuzz(func(t *testing.T, b []byte) {
		h, err := DecodeHeader(b)
		if err != nil {
			return
		}
		size, ok := RecordSize(Kind(h.Kind))
		if !ok {
			t.Fatalf("accepted unknown kind %d", h.Kind)
		}
		if int(h.Size) != size || len(b) < size {
			t.Fatalf("accepted kind %s with size %d against %d bytes (struct %d)", Kind(h.Kind), h.Size, len(b), size)
		}
		if h.Version != EventsVersion {
			t.Fatalf("accepted version %d", h.Version)
		}
		// A header the decoder accepted must decode into its record without error.
		switch Kind(h.Kind) {
		case KindExec:
			e, err := Decode[ExecEvent](b)
			if err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
			Argv(&e)
			GoString(e.Path[:])
			GoString(e.Comm[:])
		case KindExit:
			e, err := Decode[ExitEvent](b)
			if err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
			ExitStatus(&e)
		case KindExecResult:
			if _, err := Decode[ExecResultEvent](b); err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
		case KindOpen:
			e, err := Decode[FSEvent](b)
			if err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
			GoString(e.Path[:])
		case KindUnlink, KindRename, KindMkdir:
			e, err := Decode[FSOpEvent](b)
			if err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
			GoString(e.Name[:])
			GoString(e.Name2[:])
		case KindConnect, KindSendmsg, KindBind:
			e, err := Decode[NetEvent](b)
			if err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
			// An unknown family is a reported error, never a panic.
			_, _ = AddrFrom(e.Family, e.Addr)
		case KindCgroupMkdir, KindCgroupRmdir:
			if _, err := Decode[CgroupEvent](b); err != nil {
				t.Fatalf("Decode after accepted header: %v", err)
			}
		}
	})
}

// FuzzArgv drives the argv splitter directly: ArgvLen is kernel-supplied and may disagree with the buffer.
func FuzzArgv(f *testing.F) {
	f.Add([]byte("python3\x00-c\x00print(1)\x00"), uint32(19))
	f.Add([]byte{}, uint32(0))
	f.Add([]byte{0xff, 0xfe, 0}, uint32(3))
	f.Add([]byte("a"), uint32(1<<31))

	f.Fuzz(func(t *testing.T, raw []byte, n uint32) {
		var e ExecEvent
		copy(e.Argv[:], raw)
		e.ArgvLen = n
		out := Argv(&e)
		// The buffer holds at most one argument per byte, and an argument at most as many runes as the
		// buffer has bytes. Byte length is deliberately not asserted: replacing an invalid byte with U+FFFD
		// makes the string longer than the bytes it came from, which is correct and is what the corpus entry
		// under testdata records.
		if len(out) > ArgvMax {
			t.Fatalf("%d arguments from a %d-byte buffer", len(out), ArgvMax)
		}
		for _, a := range out {
			if utf8.RuneCountInString(a) > ArgvMax {
				t.Fatalf("argument of %d runes from a %d-byte buffer", utf8.RuneCountInString(a), ArgvMax)
			}
			if !utf8.ValidString(a) {
				t.Fatalf("argument is not valid UTF-8: %q", a)
			}
		}
	})
}

// FuzzGoString drives the fixed-buffer string decoder: kernel paths and names are raw bytes, not UTF-8.
func FuzzGoString(f *testing.F) {
	f.Add([]byte("/etc/passwd\x00"))
	f.Add([]byte{0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		s := GoString(b)
		if !utf8.ValidString(s) {
			t.Fatalf("GoString returned invalid UTF-8 for %q", b)
		}
		// Each replaced byte becomes one three-byte U+FFFD, so this is the tightest true bound.
		if len(s) > 3*len(b) {
			t.Fatalf("GoString grew %d bytes into %d", len(b), len(s))
		}
	})
}
