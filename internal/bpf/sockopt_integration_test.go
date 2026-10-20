// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package bpf

import (
	"encoding/hex"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/testutil/uring"
)

// ADR 0018 (7)'s kernel cells for cgroup/setsockopt: the program, attached to a scratch cgroup with
// its owner storage written as Attach writes it, decides every setsockopt a process there makes, with no seccomp
// filter in front of it, which stands for io_uring's SOCKET_URING_OP_SETSOCKOPT and any other path the filter misses.
// The agent is planeHelper, this test binary re-executed into the cgroup.

// sockoptFixture is the loaded program attached to a scratch cgroup, its owner storage, a ring at the slot and a
// helper in the cgroup.
type sockoptFixture struct {
	coll   *ebpf.Collection
	cgid   uint64
	rd     *ringbuf.Reader
	helper *planeHelper
}

const sockoptRunIdx, sockoptGen = 12, 0x50c0

func newSockoptFixture(t *testing.T) *sockoptFixture {
	t.Helper()
	requireBPF(t)
	spec, err := Load(ObjectCgroupNet)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	unpin(spec)
	for name := range spec.Programs {
		if name != ProgSetsockopt {
			delete(spec.Programs, name)
		}
	}
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			t.Fatalf("load %s: %+v", ProgSetsockopt, ve)
		}
		t.Fatalf("load %s: %v", ProgSetsockopt, err)
	}
	t.Cleanup(coll.Close)
	if info, err := coll.Programs[ProgSetsockopt].Info(); err == nil {
		if n, ok := info.VerifiedInstructions(); ok {
			t.Logf("%s: %d instructions verified", ProgSetsockopt, n)
		}
	}
	ring, err := NewRing(RingRecord, 1<<16)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ring.Close() })
	if err := InsertRing(coll.Maps[MapEvents], sockoptRunIdx, ring); err != nil {
		t.Fatal(err)
	}
	rd, err := ringbuf.NewReader(ring)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = rd.Close() })

	dir, cgfd, cgid := planeChildCgroup(t, "sockopt-"+t.Name())
	l, err := link.AttachCgroup(link.CgroupOptions{Path: dir, Attach: ebpf.AttachCGroupSetsockopt,
		Program: coll.Programs[ProgSetsockopt]})
	if err != nil {
		t.Fatalf("attach %s to %s: %v", ProgSetsockopt, dir, err)
	}
	t.Cleanup(func() { _ = l.Close() })
	return &sockoptFixture{coll: coll, cgid: cgid, rd: rd, helper: startPlaneHelper(t, cgfd)}
}

// configure writes the owner storage as Attach does.
func (f *sockoptFixture) configure(t *testing.T) {
	t.Helper()
	owner := NetOwner{CgroupID: f.cgid, RunIdx: sockoptRunIdx, Gen: sockoptGen}
	if err := f.coll.Maps[MapNetOwners].Update(&f.cgid, &owner, ebpf.UpdateExist); err != nil {
		t.Fatalf("configure %s: %v", MapNetOwners, err)
	}
}

// none asserts the ring holds nothing more.
func (f *sockoptFixture) none(t *testing.T, what string) {
	t.Helper()
	f.rd.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if raw, err := f.rd.Read(); err == nil {
		e, _ := Decode[SockoptEvent](raw.RawSample)
		t.Errorf("%s: an unexpected record %+v", what, e)
	} else if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Errorf("%s: %v", what, err)
	}
}

// expect checks one refusal's record: the run's identity, never the caller's, TCP_ULP, the caller's optlen, and the
// name's bytes as the kernel copied them.
func (f *sockoptFixture) expect(t *testing.T, what string, optlen int32, name string) {
	t.Helper()
	f.rd.SetDeadline(time.Now().Add(2 * time.Second))
	raw, err := f.rd.Read()
	if err != nil {
		t.Fatalf("%s: no record on the run's ring: %v", what, err)
	}
	e, err := Decode[SockoptEvent](raw.RawSample)
	if err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	h := e.Hdr
	if Kind(h.Kind) != KindSockopt || h.Size != uint32(unsafe.Sizeof(SockoptEvent{})) || h.Version != EventsVersion ||
		Verdict(h.Verdict) != VerdictRefused || ReasonCode(h.Reason) != ReasonNetNotAllowed ||
		h.RunIdx != sockoptRunIdx || h.Gen != sockoptGen || h.CgroupID != f.cgid ||
		h.PID != uint32(f.helper.cmd.Process.Pid) || h.TSMonoNS == 0 {
		t.Errorf("%s: header %+v", what, h)
	}
	got := string(e.Name[:])
	if i := strings.IndexByte(got, 0); i >= 0 {
		got = got[:i]
	}
	if e.Level != unix.SOL_TCP || e.Optname != unix.TCP_ULP || e.Optlen != optlen || e.Pad != 0 ||
		!strings.HasPrefix(name, got) || len(got) > ULPNameMax || len(got) < min(len(name), ULPNameMax) {
		t.Errorf("%s: record names level %d option %d optlen %d name %q; want TCP_ULP, %d, %q", what, e.Level, e.Optname,
			e.Optlen, got, optlen, name)
	}
}

// ulp is the helper's setsockopt of TCP_ULP name (NUL-terminated, optlen its length with the NUL).
func ulp(op, name string, extra ...string) []string {
	val := append([]byte(name), 0)
	return append([]string{op, strconv.Itoa(unix.SOL_TCP), strconv.Itoa(unix.TCP_ULP), hex.EncodeToString(val),
		strconv.Itoa(len(val))}, extra...)
}

// TestSetsockoptRefusesEveryTCPULP is the program's table on setsockopt(2) itself, which in a run the seccomp filter
// answers first: TCP_ULP of any name, "smc" (which with the smc module loaded turned the socket into AF_SMC) and
// "tls" included, is refused with the kernel's EPERM, the socket stays AF_INET, and exactly one record names it;
// other options pass, an option value longer than the kernel shows a program (SO_KEEPALIVE with 8 KiB) included,
// which a 5.11 to 6.4 kernel answers EFAULT unless the program hands it back; and an attachment Attach has not
// configured refuses, unrecorded.
func TestSetsockoptRefusesEveryTCPULP(t *testing.T) {
	f := newSockoptFixture(t)
	refused := strconv.Itoa(int(unix.EPERM)) + " " + strconv.Itoa(unix.AF_INET)
	nodelay := []string{"setsockopt", strconv.Itoa(unix.IPPROTO_TCP), strconv.Itoa(unix.TCP_NODELAY), "01000000", "4"}
	if got := f.helper.do(t, nodelay...); got != refused {
		t.Errorf("TCP_NODELAY under an unconfigured attachment: %q, want %q", got, refused)
	}
	f.none(t, "the unconfigured attachment's refusal")

	f.configure(t)
	if got := f.helper.do(t, nodelay...); got != "0 2" {
		t.Errorf("TCP_NODELAY: %q, want it set", got)
	}
	big := []string{"setsockopt", strconv.Itoa(unix.SOL_SOCKET), strconv.Itoa(unix.SO_KEEPALIVE),
		"01000000" + strings.Repeat("00", 8192-4), "8192"}
	if got := f.helper.do(t, big...); got != "0 2" {
		t.Errorf("SO_KEEPALIVE with an 8 KiB value: %q, want it set as with no program attached", got)
	}
	for _, name := range []string{"smc", "tls", "espintcp", "abcdefghijklmnopqrstuvwxyz"} {
		if got := f.helper.do(t, ulp("setsockopt", name)...); got != refused {
			t.Errorf("TCP_ULP %q: %q, want %q", name, got, refused)
			continue
		}
		f.expect(t, "TCP_ULP "+name, int32(len(name)+1), name)
	}
	f.none(t, "after the table")
}

// TestSetsockoptRefusesTCPULPThroughIOURing is ADR 0018 (7)'s "any path": io_uring's SOCKET_URING_OP_SETSOCKOPT,
// which no seccomp filter sees, inline, from an io-wq worker and from the SQ thread, reaches the program, which
// refuses TCP_ULP "smc" and records it, and passes TCP_NODELAY.
func TestSetsockoptRefusesTCPULPThroughIOURing(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	res, err := uring.Setsockopt(uring.Inline, fd, unix.IPPROTO_TCP, unix.TCP_NODELAY, []byte{1, 0, 0, 0}, 4)
	_ = unix.Close(fd)
	if err != nil || res == -int32(unix.EOPNOTSUPP) || res == -int32(unix.EINVAL) {
		t.Skipf("no io_uring SOCKET_URING_OP_SETSOCKOPT here (%d, %v)", res, err)
	}
	f := newSockoptFixture(t)
	f.configure(t)
	refused := strconv.Itoa(int(unix.EPERM)) + " " + strconv.Itoa(unix.AF_INET)
	for _, mode := range []uring.Mode{uring.Inline, uring.Async, uring.SQPoll} {
		nodelay := []string{"uring-setsockopt", strconv.Itoa(unix.IPPROTO_TCP), strconv.Itoa(unix.TCP_NODELAY), "01000000",
			"4", mode.String()}
		if got := f.helper.do(t, nodelay...); got != "0 2" {
			t.Errorf("%s: TCP_NODELAY through io_uring: %q, want it set", mode, got)
		}
		if got := f.helper.do(t, ulp("uring-setsockopt", "smc", mode.String())...); got != refused {
			t.Errorf("%s: TCP_ULP smc through io_uring: %q, want %q", mode, got, refused)
			continue
		}
		f.expect(t, "io_uring "+mode.String(), 4, "smc")
	}
	f.none(t, "after the io_uring cells")
}

// TestSetsockoptCountsALostRecord is §8 I7: a refusal whose record cannot be written, a run with no ring at its slot,
// still refuses, and counts the loss at the run's slot.
func TestSetsockoptCountsALostRecord(t *testing.T) {
	f := newSockoptFixture(t)
	f.configure(t)
	if err := f.coll.Maps[MapEvents].Delete(uint32(sockoptRunIdx)); err != nil {
		t.Fatal(err)
	}
	before, err := SlotCount(f.coll.Maps[MapLost], sockoptRunIdx)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.helper.do(t, ulp("setsockopt", "smc")...); !strings.HasPrefix(got, strconv.Itoa(int(unix.EPERM))+" ") {
		t.Fatalf("TCP_ULP smc with no ring: %q, want EPERM", got)
	}
	after, err := SlotCount(f.coll.Maps[MapLost], sockoptRunIdx)
	if err != nil || after != before+1 {
		t.Errorf("tego_lost at the run's slot: %d then %d (%v), want one more", before, after, err)
	}
}
