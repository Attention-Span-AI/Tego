// SPDX-License-Identifier: Apache-2.0

//go:build integration

package observe

import (
	"context"
	"net"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unixThenTCP connects a unix socket to argv[1] and a TCP socket to 127.0.0.1:argv[2].
const unixThenTCP = `import socket, sys
u = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
u.connect(sys.argv[1])
u.close()
t = socket.create_connection(("127.0.0.1", int(sys.argv[2])))
t.close()
`

// TestIntegrationUnixConnectIsLeftToTheSupervisor is security_socket_connect's record on the real objects, as root: a
// unix connect carries no address at that hook, and the kernel record wrote it as `proto=raw dst=family1:0`, beside
// the inherited tier-1 supervisor's line, which names the socket. The kernel record leaves unix connects to the
// supervisor and records the TCP connect beside it.
func TestIntegrationUnixConnectIsLeftToTheSupervisor(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	const hash = "unixconn"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "unixconn")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	sockPath := filepath.Join(t.TempDir(), "s.sock")
	ul, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer ul.Close()
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	for _, l := range []net.Listener{ul, tl} {
		go func() {
			for {
				c, err := l.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
	}

	rec, err := New(Options{Rules: &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup},
		BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-unix", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	cmd := exec.Command(python, "-c", unixThenTCP, sockPath, strconv.Itoa(tl.Addr().(*net.TCPAddr).Port))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("python3 in the run's cgroup: %v: %s", err, out)
	}
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	var tcp int
	for _, ev := range sink.byKind(record.KindNet) {
		p := payload[record.NetPayload](t, ev)
		switch {
		case p.Proto == "tcp" && p.Dst == tl.Addr().String():
			tcp++
		case p.Proto != "tcp" && p.Proto != "udp":
			t.Errorf("the kernel record wrote a connect it has no address for: proto=%s dst=%s rule=%s", p.Proto, p.Dst,
				ev.Rule)
		}
	}
	if tcp != 1 {
		t.Errorf("%d records of the TCP connect, want 1: %+v", tcp, sink.byKind(record.KindNet))
	}
}

// shortThenTCP calls connect(2) through libc with addresses shorter than their family's (the AF_INET family word
// alone, an AF_INET address of 8 bytes, an AF_INET6 one of 16), each of which fails EINVAL, then makes a TCP
// connect to 127.0.0.1:argv[1]. It prints each short call's errno.
const shortThenTCP = `import ctypes, socket, sys
libc = ctypes.CDLL(None, use_errno=True)
def short(fam, raw, n):
    s = socket.socket(fam, socket.SOCK_STREAM)
    buf = ctypes.create_string_buffer(bytes(raw) + bytes(32 - len(raw)), 32)
    r = libc.connect(s.fileno(), buf, n)
    print(fam, n, r, ctypes.get_errno())
    s.close()
short(socket.AF_INET, [2, 0], 2)
short(socket.AF_INET, [2, 0, 0x10, 0xe1, 10, 9, 8, 6], 8)
try:
    short(socket.AF_INET6, [10, 0, 0x10, 0xe1], 16)
except OSError as e:
    print("no inet6:", e)
t = socket.create_connection(("127.0.0.1", int(sys.argv[1])))
t.close()
`

// TestIntegrationShortConnectIsNotRecorded is security_socket_connect's record on the real objects, as root: the
// hook runs before the protocol's own length check, so a connect whose addrlen is at least the family word but
// shorter than its family's address reached it, and the record, zeroed, wrote a line naming 0.0.0.0:0 (or [::]:0)
// for a call that fails EINVAL and named nothing. The kernel record leaves those to the supervisor and records the
// full TCP connect beside them.
func TestIntegrationShortConnectIsNotRecorded(t *testing.T) {
	if !bpf.Available() {
		t.Skipf("needs the compiled objects: %v", bpf.ErrNotGenerated)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	const hash = "shortconn"
	root, maps := pinRoot(t, hash)
	coll := loadTraceProc(t, maps)
	_, fd, cg := childCgroup(t, "shortconn")
	row := bpf.Run{RunIdx: 1, Descendants: 1, Tier: 2, Record: uint8(bpf.RecordFull)}
	placeRunRings(t, coll, row.RunIdx)
	if err := coll.Maps[bpf.MapRunSet].Update(&cg, &row, ebpf.UpdateAny); err != nil {
		t.Fatal(err)
	}
	tl, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tl.Close()
	go func() {
		for {
			c, err := tl.Accept()
			if err != nil {
				return
			}
			_ = c.Close()
		}
	}()

	rec, err := New(Options{Rules: &agent.RuleTable{Record: agent.RecordFull, Tier: backend.TierCgroup},
		BPFHash: hash, PinRoot: root, FlushInterval: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	sink := &fakeSink{}
	if err := rec.Start(context.Background(), source.RunRef{ID: "r-short", Agent: "a", CgroupID: cg}, sink); err != nil {
		t.Fatal(err)
	}
	defer rec.Stop()
	cmd := exec.Command(python, "-c", shortThenTCP, strconv.Itoa(tl.Addr().(*net.TCPAddr).Port))
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: fd}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("python3 in the run's cgroup: %v: %s", err, out)
	}
	t.Logf("helper: %s", out)
	waitDrained(t, rec)
	if err := rec.Stop(); err != nil {
		t.Fatal(err)
	}
	var tcp int
	for _, ev := range sink.byKind(record.KindNet) {
		p := payload[record.NetPayload](t, ev)
		if p.Proto == "tcp" && p.Dst == tl.Addr().String() {
			tcp++
			continue
		}
		t.Errorf("the kernel record wrote a short connect as proto=%s dst=%s, a destination the call never named",
			p.Proto, p.Dst)
	}
	if tcp != 1 {
		t.Errorf("%d records of the TCP connect, want 1: %+v", tcp, sink.byKind(record.KindNet))
	}
}
