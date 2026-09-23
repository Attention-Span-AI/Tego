// SPDX-License-Identifier: Apache-2.0

package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unsafe"
)

// Sentinel errors of record decoding. Every one of them describes bytes the kernel produced, so a decoder
// that hits one records a gap and keeps draining; none of them is fatal to a run (§7).
var (
	// ErrShortRecord is returned when a record is smaller than the struct its kind names.
	ErrShortRecord = errors.New("bpf: short record")
	// ErrVersion is returned for a header whose version is not EventsVersion.
	ErrVersion = errors.New("bpf: unknown event version")
	// ErrKind is returned for a header whose kind this build does not know.
	ErrKind = errors.New("bpf: unknown event kind")
)

// HeaderSize is the wire width of an event header.
const HeaderSize = int(unsafe.Sizeof(Header{}))

// RecordSize returns the wire width of the record a kind names, and whether the kind is known.
func RecordSize(k Kind) (int, bool) {
	switch k {
	case KindExec:
		return int(unsafe.Sizeof(ExecEvent{})), true
	case KindExit:
		return int(unsafe.Sizeof(ExitEvent{})), true
	case KindExecResult:
		return int(unsafe.Sizeof(ExecResultEvent{})), true
	case KindBindResult, KindListenResult:
		return int(unsafe.Sizeof(BindResultEvent{})), true
	case KindOpen:
		return int(unsafe.Sizeof(FSEvent{})), true
	case KindUnlink, KindRename, KindMkdir, KindMknod, KindRmdir, KindLink, KindSymlink, KindTruncate:
		return int(unsafe.Sizeof(FSOpEvent{})), true
	case KindConnect, KindSendmsg, KindBind:
		return int(unsafe.Sizeof(NetEvent{})), true
	case KindCgroupMkdir, KindCgroupRmdir:
		return int(unsafe.Sizeof(CgroupEvent{})), true
	case KindPlaneExec, KindPlaneAttr, KindPlaneSocket, KindPlaneMap, KindPlaneFS, KindPlaneControl:
		return int(unsafe.Sizeof(PlaneEvent{})), true
	case KindSockCreate:
		return int(unsafe.Sizeof(SockEvent{})), true
	case KindSockopt:
		return int(unsafe.Sizeof(SockoptEvent{})), true
	case KindPlaneExecKill:
		return int(unsafe.Sizeof(ExecKillEvent{})), true
	case KindPlaneExecHeld:
		return int(unsafe.Sizeof(ExecHeldEvent{})), true
	default:
		return 0, false
	}
}

// DecodeHeader reads the common header off a ring-buffer record and validates what a reader must trust
// before it dispatches: the version, a known kind, and a Size that neither exceeds the record nor falls
// below the struct the kind names. It never panics and never allocates.
func DecodeHeader(b []byte) (Header, error) {
	h, err := parseHeader(b)
	if err != nil {
		return h, err
	}
	if h.Version != EventsVersion {
		return h, fmt.Errorf("%w: %d", ErrVersion, h.Version)
	}
	want, ok := RecordSize(Kind(h.Kind))
	if !ok {
		return h, fmt.Errorf("%w: %d", ErrKind, h.Kind)
	}
	if int(h.Size) != want {
		return h, fmt.Errorf("%w: kind %s declares %d bytes, struct is %d", ErrShortRecord, Kind(h.Kind), h.Size, want)
	}
	if len(b) < want {
		return h, fmt.Errorf("%w: kind %s needs %d bytes, got %d", ErrShortRecord, Kind(h.Kind), want, len(b))
	}
	return h, nil
}

// PeekKind is the kind a record's header names, or 0 for a record too short to have one, for a reader of a
// ring that carries more than one kind to choose a decoder by; the decoder validates the rest.
func PeekKind(b []byte) Kind {
	if len(b) < HeaderSize {
		return 0
	}
	return Kind(binary.NativeEndian.Uint16(b[2:4]))
}

// parseHeader copies the header's fields off a record without judging them. It is the half of DecodeHeader
// that a variable-width record — the SSL chunk, whose Size is not the width of a fixed struct — shares;
// every caller applies its own version, kind and size rules on top.
func parseHeader(b []byte) (Header, error) {
	var h Header
	if len(b) < HeaderSize {
		return h, fmt.Errorf("%w: %d bytes, header needs %d", ErrShortRecord, len(b), HeaderSize)
	}
	// Decoded field by field rather than through reflection: this runs once per ring-buffer record on the
	// budgeted drain path (§9), and the layout is fixed by bpf/include/events.h.
	o := binary.NativeEndian
	h.Version = o.Uint16(b[0:2])
	h.Kind = o.Uint16(b[2:4])
	h.Size = o.Uint32(b[4:8])
	h.TSMonoNS = o.Uint64(b[8:16])
	h.CgroupID = o.Uint64(b[16:24])
	h.PID = o.Uint32(b[24:28])
	h.TID = o.Uint32(b[28:32])
	h.PPID = o.Uint32(b[32:36])
	h.RunIdx = o.Uint32(b[36:40])
	h.Verdict = b[40]
	h.Reason = b[41]
	h.RuleIdx = o.Uint16(b[42:44])
	h.Gen = o.Uint32(b[44:48])
	return h, nil
}

// EventRecord is the closed set of ring-buffer record types Decode understands. Every one of them has a
// fixed, host-native layout asserted against bpf/include/events.h by types_test.go and against bpf2go's own
// BTF-derived mirror by parity_tegobpf_test.go, which is what lets Decode copy the bytes straight in.
type EventRecord interface {
	ExecEvent | ExitEvent | ExecResultEvent | BindResultEvent | FSEvent | FSOpEvent | NetEvent | CgroupEvent | PlaneEvent |
		SockEvent | SockoptEvent | ExecKillEvent | ExecHeldEvent
}

// Decode validates a ring-buffer record's header and copies the record into a value of T. It rejects a
// record whose kind does not belong to T, so two records of one width — a NetEvent and a CgroupEvent were
// once — can never be read as each other.
//
// The copy is a memmove rather than a reflective walk because this runs once per record on the budgeted
// drain path (§9): a reflective decode of the exec record costs two orders of magnitude more.
func Decode[T EventRecord](b []byte) (T, error) {
	var out T
	h, err := DecodeHeader(b)
	if err != nil {
		return out, err
	}
	size := int(unsafe.Sizeof(out))
	if !acceptsKind(&out, Kind(h.Kind)) {
		return out, fmt.Errorf("%w: kind %s is not a %T", ErrKind, Kind(h.Kind), out)
	}
	if len(b) < size {
		return out, fmt.Errorf("%w: %T needs %d bytes, got %d", ErrShortRecord, out, size, len(b))
	}
	copy(unsafe.Slice((*byte)(unsafe.Pointer(&out)), size), b[:size])
	return out, nil
}

// acceptsKind reports whether a record type may carry a given kind.
func acceptsKind(v any, k Kind) bool {
	switch v.(type) {
	case *ExecEvent:
		return k == KindExec
	case *ExitEvent:
		return k == KindExit
	case *ExecResultEvent:
		return k == KindExecResult
	case *BindResultEvent:
		return k == KindBindResult || k == KindListenResult
	case *FSEvent:
		return k == KindOpen
	case *FSOpEvent:
		return k.IsFSOp()
	case *NetEvent:
		return k == KindConnect || k == KindSendmsg || k == KindBind
	case *CgroupEvent:
		return k == KindCgroupMkdir || k == KindCgroupRmdir
	case *PlaneEvent:
		return k == KindPlaneExec || k == KindPlaneAttr || k == KindPlaneSocket || k == KindPlaneMap || k == KindPlaneFS || k == KindPlaneControl
	case *SockEvent:
		return k == KindSockCreate
	case *SockoptEvent:
		return k == KindSockopt
	case *ExecKillEvent:
		return k == KindPlaneExecKill
	case *ExecHeldEvent:
		return k == KindPlaneExecHeld
	default:
		return false
	}
}

// GoString turns a fixed-width, NUL-padded kernel buffer into a Go string, replacing invalid UTF-8 so the
// result is safe to print and log. It is for display only: the kernel decided on the raw bytes, and a
// verdict userspace infers by matching the string against a contract's entries (the recorder's, R9) must
// match those raw bytes too, since a replaced byte can make a path under a deny_read entry name none (§6
// E18). The recorder keeps the raw bytes for that reason and leaves the replacement
// to encoding/json when the line is written.
func GoString(b []byte) string {
	if i := bytes.IndexByte(b, 0); i >= 0 {
		b = b[:i]
	}
	return strings.ToValidUTF8(string(b), "�")
}
