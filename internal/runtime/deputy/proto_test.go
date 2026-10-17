// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

// TestRequestRoundTrip: every field of a request survives its encoding, the pathname byte for byte.
func TestRequestRoundTrip(t *testing.T) {
	in := request{op: opPinOpen, walk: walkNofollow | walkCreate, tid: 1234, tgid: 1200, dirfd: -100, flags: unix.O_RDONLY | unix.O_CLOEXEC,
		mode: 0o640, umask: 0o077, seq: 1 << 40, path: "a/\xffb/../c", leaf: "leaf"}
	msg, err := in.encode(make([]byte, maxRequest))
	if err != nil {
		t.Fatal(err)
	}
	out, err := decodeRequest(msg)
	if err != nil {
		t.Fatal(err)
	}
	if out != in {
		t.Fatalf("decoded %+v, sent %+v", out, in)
	}
}

// TestPinQueryWalkBitsReachTheWalk: each of a pin's walk flags travels as its own bit and reaches the walk the deputy
// runs as the same field (handle's PinQuery), one at a time and all together. Directory, the open's need of a
// directory, is how a final symlink O_NOFOLLOW leaves is answered ENOTDIR rather than ELOOP, as the kernel answers
// O_DIRECTORY|O_NOFOLLOW and O_TMPFILE|O_NOFOLLOW (the differential matrix found the held path answering ELOOP).
func TestPinQueryWalkBitsReachTheWalk(t *testing.T) {
	all := PinQuery{Nofollow: true, Create: true, Empty: true, Excl: true, Directory: true}
	for _, q := range []PinQuery{
		{Nofollow: true}, {Create: true}, {Empty: true}, {Excl: true}, {Directory: true}, all, {},
	} {
		q.TID, q.TGID, q.DirFD, q.Path = 7, 7, -100, "x"
		msg, err := (&request{op: opPin, walk: q.walkBits(), tid: int32(q.TID), tgid: int32(q.TGID), dirfd: q.DirFD, path: q.Path}).encode(make([]byte, maxRequest))
		if err != nil {
			t.Fatal(err)
		}
		req, err := decodeRequest(msg)
		if err != nil {
			t.Fatal(err)
		}
		var got PinQuery
		handle(req, -1, func(w PinQuery) (Pinned, error) { got = w; return Pinned{FD: -1}, unix.ENOENT })
		if got != q {
			t.Errorf("the walk was given %+v, the pin asked %+v", got, q)
		}
	}
}

// TestReplyRoundTrip: a reply's errno, opened and by-descriptor flags, open errno, pid and leaf survive, each flag
// on its own.
func TestReplyRoundTrip(t *testing.T) {
	for _, in := range []reply{
		{op: opPinOpen, seq: 7, pid: 99, leaf: "x", opened: true, openErrno: unix.EACCES},
		{op: opPin, seq: 8, byFD: true},
		{op: opPinOpen, seq: 9, opened: true, byFD: true},
	} {
		msg, err := in.encode(make([]byte, maxReply))
		if err != nil {
			t.Fatal(err)
		}
		out, err := decodeReply(msg)
		if err != nil {
			t.Fatal(err)
		}
		if out != in {
			t.Fatalf("decoded %+v, sent %+v", out, in)
		}
	}
}

// TestDecodeRefusesMalformed: a short, oversized, wrong-version or length-inconsistent message is ErrProtocol.
func TestDecodeRefusesMalformed(t *testing.T) {
	good, err := (&request{op: opPin, path: "/x"}).encode(make([]byte, maxRequest))
	if err != nil {
		t.Fatal(err)
	}
	for name, b := range map[string][]byte{
		"short":    good[:10],
		"trailing": append(append([]byte(nil), good...), 0),
		"version":  append([]byte{2, 0}, good[2:]...),
	} {
		if _, err := decodeRequest(b); !errors.Is(err, ErrProtocol) {
			t.Errorf("%s: %v, want ErrProtocol", name, err)
		}
	}
	if _, err := (&request{path: strings.Repeat("a", maxPath)}).encode(make([]byte, maxRequest)); !errors.Is(err, ErrProtocol) {
		t.Errorf("a pathname of PATH_MAX bytes encoded: %v", err)
	}
	if _, err := decodeReply(good[:repHeader-1]); !errors.Is(err, ErrProtocol) {
		t.Errorf("short reply: %v", err)
	}
}

// TestParseControlReturnsEveryDescriptor: a message carrying more descriptors than the protocol has keeps them all,
// so the receiver closes them rather than leaking one.
func TestParseControlReturnsEveryDescriptor(t *testing.T) {
	oob := make([]byte, oobSize)
	c := parseControl(putRights2(oob, 7, 9), nil)
	if c.fd != 7 || len(c.extra) != 1 || c.extra[0] != 9 {
		t.Fatalf("parsed %+v, want fd 7 and extra [9]", c)
	}
	if c := parseControl(putRights(oob, 5), nil); c.fd != 5 || len(c.extra) != 0 {
		t.Fatalf("parsed %+v, want fd 5", c)
	}
}

// TestFilterKillsByDefault: the filter checks the architecture first, and its last instruction kills the process.
func TestFilterKillsByDefault(t *testing.T) {
	raw, err := Filter(FilterSpec{TGID: 42, EventFD: 5})
	if err != nil {
		t.Fatal(err)
	}
	insts, ok := bpf.Disassemble(raw)
	if !ok {
		t.Fatal("the filter does not disassemble")
	}
	if l, ok := insts[0].(bpf.LoadAbsolute); !ok || l.Off != offArch {
		t.Fatalf("first instruction %v, want the architecture load", insts[0])
	}
	if r, ok := insts[len(insts)-1].(bpf.RetConstant); !ok || r.Val != retKill {
		t.Fatalf("last instruction %v, want SECCOMP_RET_KILL_PROCESS", insts[len(insts)-1])
	}
	if len(raw) > unix.BPF_MAXINSNS {
		t.Fatalf("%d instructions", len(raw))
	}
}
