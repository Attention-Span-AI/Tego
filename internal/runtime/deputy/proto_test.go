// SPDX-License-Identifier: Apache-2.0

package deputy

import (
	"encoding/binary"
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

// seccompData is a seccomp_data record (nr, arch, then the arguments' words the filter loads) as the x/net/bpf VM
// reads it: the VM loads a word big-endian, where the kernel loads it in the host's order, so each word is written
// big-endian here.
func seccompData(arch, nr, arg0, arg1 uint32) []byte {
	b := make([]byte, 64)
	binary.BigEndian.PutUint32(b[offNr:], nr)
	binary.BigEndian.PutUint32(b[offArch:], arch)
	binary.BigEndian.PutUint32(b[offArg0:], arg0)
	binary.BigEndian.PutUint32(b[offArg1:], arg1)
	return b
}

// TestFilterRefusesAReadItDoesNotKillFor: a read of the runtime poller's eventfd is allowed and a read of any other
// descriptor refused EPERM, never fatal: a cgo build's glibc reads /sys/devices/system/cpu/online when one of the
// deputy's threads first needs a ninth malloc arena, and the kill there ended the deputy as concurrent requests made
// it start its tenth thread (the race job's TestDeputyPinsAndOpens on Ubuntu 24.04). A write anywhere but the eventfd
// and standard error, and a syscall outside the list, still kill.
func TestFilterRefusesAReadItDoesNotKillFor(t *testing.T) {
	arch, err := nativeArch()
	if err != nil {
		t.Skip(err)
	}
	for _, efd := range []int{5, -1} {
		raw, err := Filter(FilterSpec{TGID: 42, EventFD: efd})
		if err != nil {
			t.Fatal(err)
		}
		insts, ok := bpf.Disassemble(raw)
		if !ok {
			t.Fatal("the filter does not disassemble")
		}
		vm, err := bpf.NewVM(insts)
		if err != nil {
			t.Fatal(err)
		}
		pollerRead := uint32(retAllow)
		if efd < 0 {
			pollerRead = retEPERM // no poller eventfd: no descriptor may be read
		}
		for _, c := range []struct {
			name           string
			nr, arg0, want uint32
		}{
			{"read of the poller's eventfd", unix.SYS_READ, 5, pollerRead},
			{"read of a file", unix.SYS_READ, 9, retEPERM},
			{"read of standard input", unix.SYS_READ, 0, retEPERM},
			{"write to standard error", unix.SYS_WRITE, 2, retAllow},
			{"write to a file", unix.SYS_WRITE, 9, retKill},
			{"socket", unix.SYS_SOCKET, unix.AF_INET, retKill},
		} {
			got, err := vm.Run(seccompData(arch, c.nr, c.arg0, 0))
			if err != nil {
				t.Fatalf("eventfd %d, %s: %v", efd, c.name, err)
			}
			if uint32(got) != c.want {
				t.Errorf("eventfd %d, %s: the filter answers %#x, want %#x", efd, c.name, uint32(got), c.want)
			}
		}
	}
}
