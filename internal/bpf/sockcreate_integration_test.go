// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"errors"
	"os"
	"strconv"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/uring"
)

// ADR 0018 PR 2's kernel cells for cgroup/sock_create (docs/p0/enforce-cgroup-observe.md §5 R4, R5): the program,
// attached to a scratch cgroup with its owner storage written as Attach writes it, decides every socket a process
// there creates, with no seccomp filter in front of it, which stands for any path the filter misses. The agent is
// planeHelper (plane_decide_integration_test.go), this test binary re-executed into the cgroup.
//
// Each triple is created once by this process, outside the cgroup, and once by the helper. Where the kernel itself
// refuses it outside (a protocol it lacks, a ping socket outside ping_group_range), the program never runs and the
// two answers agree. Where it succeeds outside, an inet triple's answer inside is ADR 0018 (1)'s: SocketAllowed's,
// the Go spelling of bpf/include/socket_allow.h, so this is the C function's parity with the table, run in the
// kernel; a refusal is the kernel's EPERM with exactly one record on the run's ring. A non-inet family is not seen
// at all (ADR 0018 (5)'s residual), so its answer inside is the one outside.

// sockCreateCell is one socket(2) the helper makes.
type sockCreateCell struct {
	family, typ, protocol int32
}

func (c sockCreateCell) args() []string {
	return []string{"socket", strconv.Itoa(int(c.family)), strconv.Itoa(int(c.typ)), strconv.Itoa(int(c.protocol))}
}

// outside is the cell's answer in this process, which no program decides: "0" or an errno number.
func (c sockCreateCell) outside() string {
	fd, err := unix.Socket(int(c.family), int(c.typ)|unix.SOCK_CLOEXEC, int(c.protocol))
	if err == nil {
		_ = unix.Close(fd)
	}
	return errnoString(err)
}

// resolved is the cell as the kernel holds a socket made of it outside the run: protocol 0 resolved to the protocol
// inet_create picked for the type (SO_PROTOCOL), which is the sk_protocol cgroup/sock_create reads and records. With
// the sctp module loaded a SOCK_SEQPACKET of protocol 0 is SCTP (132), and its record names 132. A cell the kernel
// refuses outside is returned as it is.
func (c sockCreateCell) resolved() sockCreateCell {
	fd, err := unix.Socket(int(c.family), int(c.typ)|unix.SOCK_CLOEXEC, int(c.protocol))
	if err != nil {
		return c
	}
	defer unix.Close(fd)
	if p, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PROTOCOL); err == nil {
		c.protocol = int32(p)
	}
	return c
}

func sockCreateCells() []sockCreateCell {
	const (
		ipprotoSCTP, ipprotoUDPLite, ipprotoMPTCP, ipprotoSMC = 132, 136, 262, 256
		afPacket, afTIPC, afVsock                             = 17, 30, 40
	)
	var cells []sockCreateCell
	for _, family := range []int32{unix.AF_INET, unix.AF_INET6} {
		for _, typ := range []int32{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_RAW, unix.SOCK_SEQPACKET} {
			for _, protocol := range []int32{0, unix.IPPROTO_TCP, unix.IPPROTO_UDP, unix.IPPROTO_ICMP, unix.IPPROTO_ICMPV6,
				ipprotoUDPLite, ipprotoSCTP, ipprotoMPTCP, ipprotoSMC} {
				cells = append(cells, sockCreateCell{family, typ, protocol})
			}
		}
	}
	for _, family := range []int32{unix.AF_UNIX, unix.AF_NETLINK, afPacket, afTIPC, afVsock} {
		for _, typ := range []int32{unix.SOCK_STREAM, unix.SOCK_DGRAM, unix.SOCK_RAW, unix.SOCK_SEQPACKET} {
			cells = append(cells, sockCreateCell{family, typ, 0})
		}
	}
	return cells
}

// sockCreateFixture is the loaded program attached to a scratch cgroup, its owner storage, a ring at the slot and
// a helper in the cgroup.
type sockCreateFixture struct {
	coll   *ebpf.Collection
	cgid   uint64
	rd     *ringbuf.Reader
	helper *planeHelper
}

const sockCreateRunIdx, sockCreateGen = 11, 0x5eed

func newSockCreateFixture(t *testing.T) *sockCreateFixture {
	t.Helper()
	requireBPF(t)
	spec, err := Load(ObjectCgroupNet)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	for name := range spec.Programs {
		if name != ProgSockCreate {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s: %+v", ProgSockCreate, ve)
		}
		t.Fatalf("load %s: %v", ProgSockCreate, err)
	}
	t.Cleanup(coll.Close)
	if info, err := coll.Programs[ProgSockCreate].Info(); err == nil {
		if n, ok := info.VerifiedInstructions(); ok {
			t.Logf("%s: %d instructions verified", ProgSockCreate, n)
		}
	}
	ring, err := NewRing(RingRecord, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	if err := InsertRing(coll.Maps[MapEvents], sockCreateRunIdx, ring); err != nil {
		t.Fatal(err)
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rd.Close() })

	dir, cgfd, cgid := planeChildCgroup(t, "sockcreate-"+t.Name())
	l, err := link.AttachCgroup(link.CgroupOptions{Path: dir, Attach: ebpf.AttachCGroupInetSockCreate,
		Program: coll.Programs[ProgSockCreate]})
	if err != nil {
		t.Fatalf("attach %s to %s: %v", ProgSockCreate, dir, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &sockCreateFixture{coll: coll, cgid: cgid, rd: rd, helper: startPlaneHelper(t, cgfd)}
}

// configure writes the owner storage as Attach does: the kernel created the value, zeroed, at the attach, so only
// an existing value is overwritten.
func (f *sockCreateFixture) configure(t *testing.T, flags uint32) {
	t.Helper()
	owner := NetOwner{CgroupID: f.cgid, RunIdx: sockCreateRunIdx, Flags: flags, Gen: sockCreateGen}
	if err := f.coll.Maps[MapNetOwners].Update(&f.cgid, &owner, ebpf.UpdateExist); err != nil {
		t.Fatalf("configure %s: %v", MapNetOwners, err)
	}
}

// record reads the next record off the slot's ring, or fails after a bound.
func (f *sockCreateFixture) record(t *testing.T, what string) SockEvent {
	t.Helper()
	f.rd.SetDeadline(time.Now().Add(2 * time.Second))
	raw, err := f.rd.Read()
	if err != nil {
		t.Fatalf("%s: no record on the run's ring: %v", what, err)
	}
	e, err := Decode[SockEvent](raw.RawSample)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	return e
}

// none asserts the ring holds nothing more.
func (f *sockCreateFixture) none(t *testing.T, what string) {
	t.Helper()
	f.rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if raw, err := f.rd.Read(); err == nil {
		e, _ := Decode[SockEvent](raw.RawSample)
		t.Errorf("%s: an unexpected record %+v", what, e)
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%s: %v", what, err)
	}
}

// expect checks one refusal's record: the run's own identity, never the caller's, and the triple as the kernel holds
// it (sk_type has no SOCK_CLOEXEC).
func (f *sockCreateFixture) expect(t *testing.T, c sockCreateCell, what string) {
	t.Helper()
	e := f.record(t, what)
	h := e.Hdr
	if Kind(h.Kind) != KindSockCreate || h.Size != uint32(unsafe.Sizeof(SockEvent{})) || h.Version != EventsVersion ||
		Verdict(h.Verdict) != VerdictRefused || ReasonCode(h.Reason) != ReasonNetNotAllowed ||
		h.RunIdx != sockCreateRunIdx || h.Gen != sockCreateGen || h.CgroupID != f.cgid ||
		h.PID != uint32(f.helper.cmd.Process.Pid) || h.PPID != 0 || h.TSMonoNS == 0 {
		t.Errorf("%s: header %+v", what, h)
	}
	if e.Family != c.family || e.Type != c.typ || e.Protocol != c.protocol || e.Pad != 0 {
		t.Errorf("%s: record names (%d, %d, %d), want (%d, %d, %d)", what, e.Family, e.Type, e.Protocol, c.family, c.typ,
			c.protocol)
	}
}

// TestSockCreateRefusesInetSocketsOutsideTheAllowlist is the table: every cell, without and with the owner's ICMP
// flag, against SocketAllowed. Ping sockets are opened to the test's group for the run of the test
// (net.ipv4.ping_group_range), so the ICMP cells reach the program rather than the kernel's own EACCES.
func TestSockCreateRefusesInetSocketsOutsideTheAllowlist(t *testing.T) {
	f := newSockCreateFixture(t)
	const pingRange = "/proc/sys/net/ipv4/ping_group_range"
	if old, err := os.ReadFile(pingRange); err == nil {
		if err := os.WriteFile(pingRange, []byte("0 2147483647"), 0); err != nil {
			t.Logf("ping sockets stay closed here (%v): the ICMP cells take the kernel's own refusal", err)
		} else {
			t.Cleanup(func() { _ = os.WriteFile(pingRange, old, 0) })
		}
	}

	// An attachment Attach has not configured refuses, unrecorded (§5 R1), even TCP.
	tcp := sockCreateCell{unix.AF_INET, unix.SOCK_STREAM, 0}
	if got := f.helper.do(t, tcp.args()...); got != strconv.Itoa(int(unix.EPERM)) {
		t.Errorf("a TCP socket under an unconfigured attachment: %s, want EPERM", got)
	}
	f.none(t, "the unconfigured attachment's refusal")

	refused, admitted, kernel := 0, 0, 0
	for _, icmp := range []bool{false, true} {
		var flags uint32
		if icmp {
			flags = NetOwnerICMP
		}
		f.configure(t, flags)
		for _, c := range sockCreateCells() {
			what := "icmp=" + strconv.FormatBool(icmp) + " " + strconv.Itoa(int(c.family)) + "/" + strconv.Itoa(int(c.typ)) +
				"/" + strconv.Itoa(int(c.protocol))
			outside, inside := c.outside(), f.helper.do(t, c.args()...)
			inet := c.family == unix.AF_INET || c.family == unix.AF_INET6
			switch {
			case outside != "0" || !inet:
				// The kernel refused it before inet_create's hook, or the family is one the program cannot see.
				kernel++
				if inside != outside {
					t.Errorf("%s: %s inside the run's cgroup, %s outside; the program cannot have decided it", what, inside,
						outside)
				}
			case SocketAllowed(c.family, c.typ, c.resolved().protocol, icmp):
				// The program decides the protocol inet_create resolved, not the 0 the caller may have passed.
				admitted++
				if inside != "0" {
					t.Errorf("%s: %s, the allowlist admits it", what, inside)
				}
			default:
				refused++
				if inside != strconv.Itoa(int(unix.EPERM)) {
					t.Errorf("%s: %s, want EPERM from cgroup/sock_create", what, inside)
					continue
				}
				f.expect(t, c.resolved(), what)
			}
		}
		f.none(t, "after the table")
	}
	t.Logf("%d refused by the program, %d admitted, %d answered by the kernel alone", refused, admitted, kernel)
	if refused == 0 || admitted == 0 {
		t.Fatalf("the table reached the program %d times to refuse and %d to admit", refused, admitted)
	}

	// MPTCP (262) is not TCP and IPPROTO_SMC (256) is not protocol 0: where the kernel has them, the whole
	// protocol number is what was decided.
	for _, c := range []sockCreateCell{{unix.AF_INET, unix.SOCK_STREAM, 262}, {unix.AF_INET6, unix.SOCK_STREAM, 256}} {
		if c.outside() == "0" {
			t.Logf("protocol %d exists here and was refused by the program", c.protocol)
		} else {
			t.Logf("protocol %d does not exist here (%s): its truncation cell is the source test's", c.protocol, c.outside())
		}
	}
}

// TestSockCreateRefusesThroughIOURing is ADR 0018 (5)'s "any path to inet_create": io_uring's IORING_OP_SOCKET,
// which no seccomp filter sees, reaches the program, which refuses an SCTP or MPTCP socket and records it, and
// passes TCP.
func TestSockCreateRefusesThroughIOURing(t *testing.T) {
	if res, err := uring.Socket(unix.AF_INET, unix.SOCK_STREAM, 0); err != nil || res == -int32(unix.EINVAL) {
		t.Skipf("no io_uring IORING_OP_SOCKET here (%d, %v)", res, err)
	}
	f := newSockCreateFixture(t)
	f.configure(t, 0)
	tcp := []string{"uring-socket", strconv.Itoa(unix.AF_INET), strconv.Itoa(unix.SOCK_STREAM), "0"}
	if got := f.helper.do(t, tcp...); got != "0" {
		t.Errorf("io_uring TCP: %s", got)
	}
	reached := 0
	for _, c := range []sockCreateCell{{unix.AF_INET, unix.SOCK_STREAM, 132}, {unix.AF_INET6, unix.SOCK_STREAM, 262},
		{unix.AF_INET, unix.SOCK_DGRAM, 136}} {
		if c.outside() != "0" {
			continue
		}
		reached++
		args := c.args()
		args[0] = "uring-socket"
		if got := f.helper.do(t, args...); got != strconv.Itoa(int(unix.EPERM)) {
			t.Errorf("io_uring %v: %s, want EPERM from cgroup/sock_create", c, got)
			continue
		}
		f.expect(t, c, "io_uring")
	}
	f.none(t, "after the io_uring cells")
	if reached == 0 {
		t.Skip("none of SCTP, MPTCP and UDP-Lite exists in this kernel")
	}
}

// TestSockCreateCountsALostRecord is §8 I7: a refusal whose record cannot be written, a run with no ring at its slot,
// still refuses, and counts the loss at the run's slot.
func TestSockCreateCountsALostRecord(t *testing.T) {
	f := newSockCreateFixture(t)
	f.configure(t, 0)
	sctp := sockCreateCell{unix.AF_INET, unix.SOCK_STREAM, 132}
	if sctp.outside() != "0" {
		sctp = sockCreateCell{unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_ICMP}
	}
	if err := f.coll.Maps[MapEvents].Delete(uint32(sockCreateRunIdx)); err != nil {
		t.Fatal(err)
	}
	before, err := SlotCount(f.coll.Maps[MapLost], sockCreateRunIdx)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.helper.do(t, sctp.args()...); got != strconv.Itoa(int(unix.EPERM)) {
		t.Fatalf("%v with no ring: %s, want EPERM", sctp, got)
	}
	after, err := SlotCount(f.coll.Maps[MapLost], sockCreateRunIdx)
	if err != nil || after != before+1 {
		t.Errorf("tego_lost at the run's slot: %d then %d (%v), want one more", before, after, err)
	}
	if other, err := SlotCount(f.coll.Maps[MapLost], sockCreateRunIdx+1); err != nil || other != 0 {
		t.Errorf("tego_lost at another slot: %d (%v)", other, err)
	}
}
