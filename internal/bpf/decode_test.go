// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"encoding/binary"
	"errors"
	"testing"
	"unsafe"
)

// encode marshals a record the way the kernel writes it: native byte order, no padding of its own.
func encode(t *testing.T, v any) []byte {
	t.Helper()
	b, err := binary.Append(nil, binary.NativeEndian, v)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	return b
}

func header(kind Kind, size uint32) Header {
	return Header{Version: EventsVersion, Kind: uint16(kind), Size: size, TSMonoNS: 42, CgroupID: 99,
		PID: 1234, TID: 1235, PPID: 1, RunIdx: 3, Verdict: uint8(VerdictObserved)}
}

// TestDecodeHeaderEveryKind decodes a well-formed record of every kind this component produces.
func TestDecodeHeaderEveryKind(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind Kind
		rec  any
	}{
		{KindExec, ExecEvent{Hdr: header(KindExec, uint32(unsafe.Sizeof(ExecEvent{})))}},
		{KindExit, ExitEvent{Hdr: header(KindExit, uint32(unsafe.Sizeof(ExitEvent{})))}},
		{KindExecResult, ExecResultEvent{Hdr: header(KindExecResult, uint32(unsafe.Sizeof(ExecResultEvent{})))}},
		{KindPlaneControl, PlaneEvent{Hdr: header(KindPlaneControl, uint32(unsafe.Sizeof(PlaneEvent{})))}},
		{KindBindResult, BindResultEvent{Hdr: header(KindBindResult, uint32(unsafe.Sizeof(BindResultEvent{})))}},
		{KindListenResult, BindResultEvent{Hdr: header(KindListenResult, uint32(unsafe.Sizeof(BindResultEvent{})))}},
		{KindOpen, FSEvent{Hdr: header(KindOpen, uint32(unsafe.Sizeof(FSEvent{})))}},
		{KindUnlink, FSOpEvent{Hdr: header(KindUnlink, uint32(unsafe.Sizeof(FSOpEvent{})))}},
		{KindRename, FSOpEvent{Hdr: header(KindRename, uint32(unsafe.Sizeof(FSOpEvent{})))}},
		{KindMkdir, FSOpEvent{Hdr: header(KindMkdir, uint32(unsafe.Sizeof(FSOpEvent{})))}},
		{KindConnect, NetEvent{Hdr: header(KindConnect, uint32(unsafe.Sizeof(NetEvent{})))}},
		{KindSendmsg, NetEvent{Hdr: header(KindSendmsg, uint32(unsafe.Sizeof(NetEvent{})))}},
		{KindBind, NetEvent{Hdr: header(KindBind, uint32(unsafe.Sizeof(NetEvent{})))}},
		{KindCgroupMkdir, CgroupEvent{Hdr: header(KindCgroupMkdir, uint32(unsafe.Sizeof(CgroupEvent{})))}},
		{KindCgroupRmdir, CgroupEvent{Hdr: header(KindCgroupRmdir, uint32(unsafe.Sizeof(CgroupEvent{})))}},
		{KindPlaneFS, PlaneEvent{Hdr: header(KindPlaneFS, uint32(unsafe.Sizeof(PlaneEvent{})))}},
		{KindSockCreate, SockEvent{Hdr: header(KindSockCreate, uint32(unsafe.Sizeof(SockEvent{})))}},
		{KindSockopt, SockoptEvent{Hdr: header(KindSockopt, uint32(unsafe.Sizeof(SockoptEvent{})))}},
		{KindPlaneExecKill, ExecKillEvent{Hdr: header(KindPlaneExecKill, uint32(unsafe.Sizeof(ExecKillEvent{})))}},
		{KindPlaneExecHeld, ExecHeldEvent{Hdr: header(KindPlaneExecHeld, uint32(unsafe.Sizeof(ExecHeldEvent{})))}},
	}
	for _, tc := range cases {
		t.Run(tc.kind.String(), func(t *testing.T) {
			b := encode(t, tc.rec)
			h, err := DecodeHeader(b)
			if err != nil {
				t.Fatalf("DecodeHeader: %v", err)
			}
			if Kind(h.Kind) != tc.kind {
				t.Fatalf("kind = %s, want %s", Kind(h.Kind), tc.kind)
			}
			if h.PID != 1234 || h.CgroupID != 99 || h.RunIdx != 3 || h.TSMonoNS != 42 {
				t.Fatalf("header fields wrong: %+v", h)
			}
			want, ok := RecordSize(tc.kind)
			if !ok || int(h.Size) != want || len(b) != want {
				t.Fatalf("size %d, RecordSize %d (ok=%v), encoded %d", h.Size, want, ok, len(b))
			}
		})
	}
}

func TestDecodeExecKeepsOriginalThreadID(t *testing.T) {
	t.Parallel()
	for _, oldTID := range []uint32{1234, 1235} {
		e := ExecEvent{Hdr: header(KindExec, uint32(unsafe.Sizeof(ExecEvent{}))), OldTID: oldTID,
			ExecStartNS: 900, ParentStartNS: 700, Interpreted: 1}
		// After a nonleader exec, the executing thread has taken the group leader's id. The old id is the
		// join key of its seccomp attempt; replacing it with the post-exec Hdr.TID loses that attempt.
		e.Hdr.TID = e.Hdr.PID
		copy(e.Path[:], "/tools/program")
		got, err := Decode[ExecEvent](encode(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if got.OldTID != oldTID || got.Hdr.TID != e.Hdr.PID || got.ExecStartNS != 900 ||
			got.ParentStartNS != 700 || got.Interpreted != 1 || GoString(got.Path[:]) != "/tools/program" {
			t.Fatalf("exec identity and path changed during decode: %+v", got)
		}
	}
}

func TestDecodeOpenKeepsExecIntent(t *testing.T) {
	t.Parallel()
	for _, execOpen := range []uint8{0, 1} {
		e := FSEvent{Hdr: header(KindOpen, uint32(unsafe.Sizeof(FSEvent{}))), ExecOpen: execOpen,
			PathOk: 1, RetOk: 1, Ret: -13, StartNS: 700}
		copy(e.Path[:], "/tools/program")
		got, err := Decode[FSEvent](encode(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if got.ExecOpen != execOpen || got.RetOk != 1 || got.Ret != -13 || got.StartNS != 700 ||
			GoString(got.Path[:]) != "/tools/program" {
			t.Fatalf("image-open intent, result or path changed during decode: %+v", got)
		}
	}
}

func TestDecodeExecResultKeepsSignedFailureAndIdentity(t *testing.T) {
	t.Parallel()
	for _, ret := range []int64{-2, -8, -13, -26} {
		e := ExecResultEvent{Hdr: header(KindExecResult, uint32(unsafe.Sizeof(ExecResultEvent{}))),
			StartNS: 900, Ret: ret}
		got, err := Decode[ExecResultEvent](encode(t, e))
		if err != nil {
			t.Fatal(err)
		}
		if got.Ret != ret || got.StartNS != 900 || got.Hdr.PID != 1234 || got.Hdr.TID != 1235 {
			t.Fatalf("signed exec failure or attempt identity changed during decode: %+v", got)
		}
		// ExitEvent has the same wire width but represents process termination, never an exec attempt.
		if _, err := Decode[ExitEvent](encode(t, e)); !errors.Is(err, ErrKind) {
			t.Fatalf("exec failure decoded as process exit: %v", err)
		}
	}
}

// An older pinned build's exec width must fail decoding, rather than shift its pathname into the new identity
// fields. The build hash isolates such rings in production; the decoder also enforces the current wire shape.
func TestDecodeExecRejectsOldWireSize(t *testing.T) {
	t.Parallel()
	b := encode(t, ExecEvent{Hdr: header(KindExec, 872)})[:872]
	if _, err := Decode[ExecEvent](b); !errors.Is(err, ErrShortRecord) {
		t.Fatalf("old exec wire width decoded: %v", err)
	}
}

// TestDecodeHeaderMalformed covers every way a record can be wrong: short, wrong version, unknown kind, a
// size the kind does not match, and a size larger than the buffer. None of them may panic.
func TestDecodeHeaderMalformed(t *testing.T) {
	t.Parallel()
	good := encode(t, NetEvent{Hdr: header(KindConnect, uint32(unsafe.Sizeof(NetEvent{})))})

	cases := []struct {
		name string
		make func() []byte
		want error
	}{
		{"empty", func() []byte { return nil }, ErrShortRecord},
		{"one byte", func() []byte { return []byte{1} }, ErrShortRecord},
		{"header minus one", func() []byte { return good[:HeaderSize-1] }, ErrShortRecord},
		{"bad version", func() []byte {
			b := append([]byte(nil), good...)
			binary.NativeEndian.PutUint16(b[0:2], 99)
			return b
		}, ErrVersion},
		{"unknown kind", func() []byte {
			b := append([]byte(nil), good...)
			binary.NativeEndian.PutUint16(b[2:4], 4242)
			return b
		}, ErrKind},
		{"size mismatch", func() []byte {
			b := append([]byte(nil), good...)
			binary.NativeEndian.PutUint32(b[4:8], 7)
			return b
		}, ErrShortRecord},
		{"truncated body", func() []byte { return good[:HeaderSize] }, ErrShortRecord},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := DecodeHeader(tc.make())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestDecodeInto round-trips a full record and rejects a malformed one before touching the body.
func TestDecodeInto(t *testing.T) {
	t.Parallel()
	want := FSOpEvent{Hdr: header(KindRename, uint32(unsafe.Sizeof(FSOpEvent{}))), Dev: 66, DirIno: 777,
		Dev2: 66, DirIno2: 888, Op: uint8(FSOpRename), NameOk: 1, Name2Ok: 1}
	copy(want.Name[:], "old.txt")
	copy(want.Name2[:], "new.txt")

	got, err := Decode[FSOpEvent](encode(t, want))
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if got != want {
		t.Fatalf("round trip differs")
	}
	if GoString(got.Name[:]) != "old.txt" || GoString(got.Name2[:]) != "new.txt" {
		t.Fatalf("names = %q %q", GoString(got.Name[:]), GoString(got.Name2[:]))
	}
	if _, err := Decode[FSOpEvent]([]byte{1, 2, 3}); !errors.Is(err, ErrShortRecord) {
		t.Fatalf("Decode(short) = %v", err)
	}
}

// TestDecodeRejectsMismatchedKind pins the one pair of records that share a width: a cgroup record must
// never decode as a net record just because both are 72 bytes.
func TestDecodeRejectsMismatchedKind(t *testing.T) {
	t.Parallel()
	cg := encode(t, CgroupEvent{Hdr: header(KindCgroupMkdir, uint32(unsafe.Sizeof(CgroupEvent{}))),
		ParentCgroupID: 1, ChildCgroupID: 2})
	if _, err := Decode[NetEvent](cg); !errors.Is(err, ErrKind) {
		t.Fatalf("Decode[NetEvent](cgroup record) = %v, want ErrKind", err)
	}
	if _, err := Decode[CgroupEvent](cg); err != nil {
		t.Fatalf("Decode[CgroupEvent]: %v", err)
	}
	net := encode(t, NetEvent{Hdr: header(KindConnect, uint32(unsafe.Sizeof(NetEvent{})))})
	if _, err := Decode[CgroupEvent](net); !errors.Is(err, ErrKind) {
		t.Fatalf("Decode[CgroupEvent](net record) = %v, want ErrKind", err)
	}
	exec := encode(t, ExecEvent{Hdr: header(KindExec, uint32(unsafe.Sizeof(ExecEvent{})))})
	if _, err := Decode[ExitEvent](exec); !errors.Is(err, ErrKind) {
		t.Fatalf("Decode[ExitEvent](exec record) = %v, want ErrKind", err)
	}
}

// TestDecodeSockCreate is cgroup/sock_create's record (KindSockCreate, struct tego_ev_sock): it round-trips with
// the whole protocol number (MPTCP's 262 is not TCP's 6), a short or over-long record is refused, and it shares its
// 64-byte width with the exit and exec-result records without ever decoding as either of them.
func TestDecodeSockCreate(t *testing.T) {
	t.Parallel()
	size := uint32(unsafe.Sizeof(SockEvent{}))
	want := SockEvent{Hdr: header(KindSockCreate, size), Family: 10, Type: 1, Protocol: 262}
	want.Hdr.Verdict, want.Hdr.Reason, want.Hdr.Gen = uint8(VerdictRefused), uint8(ReasonNetNotAllowed), 77
	b := encode(t, want)
	got, err := Decode[SockEvent](b)
	if err != nil || got != want {
		t.Fatalf("Decode[SockEvent] = %+v, %v; want %+v", got, err, want)
	}
	if _, err := Decode[SockEvent](b[:len(b)-1]); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a short sock_create record decoded: %v", err)
	}
	long := encode(t, SockEvent{Hdr: header(KindSockCreate, size+8)})
	if _, err := Decode[SockEvent](append(long, make([]byte, 8)...)); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a sock_create record declaring %d bytes decoded: %v", size+8, err)
	}
	if _, err := Decode[ExitEvent](b); !errors.Is(err, ErrKind) {
		t.Errorf("Decode[ExitEvent](sock_create record) = %v, want ErrKind", err)
	}
	if _, err := Decode[ExecResultEvent](b); !errors.Is(err, ErrKind) {
		t.Errorf("Decode[ExecResultEvent](sock_create record) = %v, want ErrKind", err)
	}
	exit := encode(t, ExitEvent{Hdr: header(KindExit, uint32(unsafe.Sizeof(ExitEvent{})))})
	if _, err := Decode[SockEvent](exit); !errors.Is(err, ErrKind) {
		t.Errorf("Decode[SockEvent](exit record) = %v, want ErrKind", err)
	}
}

// TestDecodeSockopt is cgroup/setsockopt's record (KindSockopt, struct tego_ev_sockopt; ADR 0018 (7)): it
// round-trips with its option, value length and name bytes, a short or over-long record is refused, and it shares
// its 80-byte width with the network record without ever decoding as one.
func TestDecodeSockopt(t *testing.T) {
	t.Parallel()
	size := uint32(unsafe.Sizeof(SockoptEvent{}))
	want := SockoptEvent{Hdr: header(KindSockopt, size), Level: 6, Optname: 31, Optlen: 4}
	copy(want.Name[:], "smc")
	want.Hdr.Verdict, want.Hdr.Reason, want.Hdr.Gen = uint8(VerdictRefused), uint8(ReasonNetNotAllowed), 77
	b := encode(t, want)
	got, err := Decode[SockoptEvent](b)
	if err != nil || got != want {
		t.Fatalf("Decode[SockoptEvent] = %+v, %v; want %+v", got, err, want)
	}
	if _, err := Decode[SockoptEvent](b[:len(b)-1]); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a short sockopt record decoded: %v", err)
	}
	long := encode(t, SockoptEvent{Hdr: header(KindSockopt, size+8)})
	if _, err := Decode[SockoptEvent](append(long, make([]byte, 8)...)); !errors.Is(err, ErrShortRecord) {
		t.Errorf("a sockopt record declaring %d bytes decoded: %v", size+8, err)
	}
	if _, err := Decode[NetEvent](b); !errors.Is(err, ErrKind) {
		t.Errorf("Decode[NetEvent](sockopt record) = %v, want ErrKind", err)
	}
	conn := encode(t, NetEvent{Hdr: header(KindConnect, uint32(unsafe.Sizeof(NetEvent{})))})
	if _, err := Decode[SockoptEvent](conn); !errors.Is(err, ErrKind) {
		t.Errorf("Decode[SockoptEvent](connect record) = %v, want ErrKind", err)
	}
}

// TestGoString covers NUL termination, a full buffer with no NUL, an empty buffer and invalid UTF-8 (§6 E18).
func TestGoString(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		in   []byte
		want string
	}{
		{"terminated", []byte{'a', 'b', 0, 'x'}, "ab"},
		{"unterminated", []byte{'a', 'b', 'c'}, "abc"},
		{"empty", nil, ""},
		{"only nul", []byte{0}, ""},
		{"invalid utf8", []byte{'a', 0xff, 'b', 0}, "a�b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := GoString(tc.in); got != tc.want {
				t.Fatalf("GoString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// TestArgv covers a complete vector, a truncated one, an empty one and an over-long ArgvLen.
func TestArgv(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		raw  string
		n    uint32
		want []string
	}{
		{"complete", "python3\x00-c\x00print(1)\x00", 19, []string{"python3", "-c", "print(1)"}},
		{"single", "ls\x00", 3, []string{"ls"}},
		{"truncated mid argument", "python3\x00--very-long", 19, []string{"python3", "--very-long"}},
		{"empty", "", 0, nil},
		{"len beyond buffer", "ls\x00", uint32(ArgvMax + 100), []string{"ls"}},
		{"embedded empty argument", "a\x00\x00b\x00", 5, []string{"a", "", "b"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var e ExecEvent
			copy(e.Argv[:], tc.raw)
			e.ArgvLen = tc.n
			got := Argv(&e)
			if len(got) != len(tc.want) {
				t.Fatalf("Argv = %q, want %q", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("Argv[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// TestExitStatus splits the two halves the kernel packs into exit_code.
func TestExitStatus(t *testing.T) {
	t.Parallel()
	code, sig := ExitStatus(&ExitEvent{Code: 3, Signal: 0})
	if code != 3 || sig != 0 {
		t.Fatalf("ExitStatus = %d,%d want 3,0", code, sig)
	}
	code, sig = ExitStatus(&ExitEvent{Code: 0, Signal: 9})
	if code != 0 || sig != 9 {
		t.Fatalf("ExitStatus = %d,%d want 0,9", code, sig)
	}
}

// TestRecordSizeUnknown asserts an unknown kind is reported, never guessed.
func TestRecordSizeUnknown(t *testing.T) {
	t.Parallel()
	for _, k := range []Kind{0, KindSSLChunk, 250} {
		if _, ok := RecordSize(k); ok {
			t.Fatalf("RecordSize(%s) claimed to know the kind", k)
		}
	}
}
