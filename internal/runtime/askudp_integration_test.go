// SPDX-License-Identifier: Apache-2.0

//go:build integration

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/testutil"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// udpAskProbe sends argv[3] datagrams "q<i>" to argv[1]:argv[2], one after another, each followed by a wait for the
// listener's answer "a<i>", and writes each outcome to out/rc<i>: "ok" once the answer arrived, else the errno's name.
// argv[4] is how: "same" sends every datagram on one socket, "fresh" makes a socket for each, and "connect" makes a
// socket for each, connects it and sends without an address.
const udpAskProbe = `import errno, socket, sys
host, port, n, how = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
one = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(1, n + 1):
    s = one if how == "same" else socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    msg = b"q%d" % i
    try:
        if how == "connect":
            s.connect((host, port))
            s.send(msg)
        else:
            s.sendto(msg, (host, port))
        s.settimeout(10)
        got = s.recv(16)
        r = "ok" if got == b"a%d" % i else "short:" + repr(got)
    except OSError as e:
        r = errno.errorcode.get(e.errno, str(e.errno))
    if s is not one:
        s.close()
    with open("out/rc%d" % i, "w") as f:
        f.write(r)
`

// listenUDP answers each datagram "q<i>" from its sender with "a<i>" on a loopback port until the test ends, and
// counts the datagrams it received.
func listenUDP(t *testing.T) (*net.UDPConn, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	got := new(atomic.Int32)
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 64)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			got.Add(1)
			if q, ok := bytes.CutPrefix(buf[:n], []byte("q")); ok {
				_, _ = conn.WriteToUDP(append([]byte("a"), q...), from)
			}
		}
	}()
	t.Cleanup(func() { _ = conn.Close(); <-done })
	return conn, got
}

// newAskUDPScene is a run whose agent, a Python probe, sends datagrams to dst, which only the contract's net.ask
// entry scope names, at tier with the tego binary bin: each is held for a person (supervisor R13d, ADR 0008).
func newAskUDPScene(t *testing.T, bin, tier, timeout, scope, dst string, sends int, how string) *askReadScene {
	t.Helper()
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin}
	contract := fmt.Sprintf(`version: 0
name: iaskudp
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  ask: [%q]
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: %s
limits:
  pids: 64
record: summary
`, python, resolved, scope, timeout)
	s.f = newFixture(t, contract)
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"))
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(udpAskProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	host, port, err := net.SplitHostPort(dst)
	if err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py %q %s %d %s\n", python, host, port, sends, how)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	return s
}

// askUDPCase is one cell of the UDP ask's end-to-end tests.
type askUDPCase struct {
	name, timeout string
	bare          bool     // the scope is a bare host:port, which names TCP and UDP, not udp://
	how           string   // the probe's sockets: same, fresh or connect
	sends         int      // datagrams the probe sends
	asks          int      // requests a person sees
	answer        []string // the verb and flags a person answers with; nil for nobody
	rc            string   // every datagram's outcome
	reason        string   // the refusal's reason, "" for an approval
	by            string   // the first answer's by, a prefix
}

var askUDPCases = []askUDPCase{
	{name: "approve covers the socket", timeout: "30s", how: "same", sends: 3, asks: 1, answer: []string{"approve"}, rc: "ok", by: "uid:"},
	{name: "approve a bare host:port", timeout: "30s", bare: true, how: "same", sends: 1, asks: 1, answer: []string{"approve"}, rc: "ok", by: "uid:"},
	{name: "deny", timeout: "30s", how: "same", sends: 1, asks: 1, answer: []string{"deny"}, rc: "EACCES", reason: "ask-denied", by: "uid:"},
	{name: "nobody answers", timeout: "2s", how: "same", sends: 1, asks: 1, rc: "EACCES", reason: "ask-timeout", by: "timeout"},
	{name: "approve a connect", timeout: "30s", how: "connect", sends: 1, asks: 1, answer: []string{"approve"}, rc: "ok", by: "uid:"},
	{name: "approve --always", timeout: "30s", how: "fresh", sends: 2, asks: 2, answer: []string{"approve", "--always"}, rc: "ok", by: "uid:"},
	{name: "refuse_always on timeout", timeout: "2s\n  on_timeout: refuse_always", how: "fresh", sends: 2, asks: 2, rc: "EACCES", reason: "ask-timeout", by: "timeout always"},
}

// The net.ask UDP scope end to end at tier landlock (ASK-UDP, supervisor R13d): the real tego binary runs a contract
// whose agent sends datagrams to a loopback port only that scope names; a person answers from separate tego
// processes over the run's real broker socket, or nobody answers. An approval sends the held datagram, and the
// socket's later datagrams to that port go unasked; a UDP connect is held the same way; a denial or a timeout refuses
// with that reason and the listener sees nothing; --always and ask.on_timeout: refuse_always stand for the next
// socket's datagram, as they do for a TCP connect. Everything is unprivileged.
func TestIntegrationAskUDPApproveDenyAndTimeout(t *testing.T) {
	bin := tegoBinary(t)
	for _, tc := range askUDPCases {
		t.Run(tc.name, func(t *testing.T) { runAskUDPCase(t, bin, "landlock", tc) })
	}
}

// TestRootAskUDP is the UDP ask end to end at the root tiers (ASK-UDP), from a root launcher with the agent dropped to
// the invoking user: at tier cgroup and, where doctor says the machine has it, tier bpflsm, the run's sendmsg4/6 and
// connect4/6 refuse the scope's destination, which no row admits, so an approved datagram or connect leaves only by
// the one-shot grant the supervisor makes for it (Handle.GrantDatagram, Handle.GrantConnect with proto udp).
func TestRootAskUDP(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root: tiers cgroup and bpflsm")
	}
	if _, _, ok := agentUID(t); !ok {
		t.Skip("needs SUDO_UID naming the invoking user, as `sudo go test` and test/vm/root-suites.sh give")
	}
	bin := tegoBPFBinary(t)
	for _, tier := range []string{"cgroup", "bpflsm"} {
		t.Run(tier, func(t *testing.T) {
			probe := newAskUDPScene(t, bin, tier, "30s", "udp://127.0.0.1:9", "127.0.0.1:9", 1, "same")
			testutil.RequireTier(t, probe.tego(t, "doctor", "--require", tier), tier)
			for _, tc := range askUDPCases {
				if tc.how == "fresh" {
					continue // --always and refuse_always are the broker's, the same at every tier
				}
				t.Run(tc.name, func(t *testing.T) { runAskUDPCase(t, bin, tier, tc) })
			}
			t.Run("pending frame", func(t *testing.T) { runAskUDPCorked(t, bin, tier) })
		})
	}
}

// udpCorkProbe tries every syscall that can leave a UDP frame pending (supervisor R13's pending frames), each once,
// and writes each outcome, "ok" or the errno's name, to a file in out/. On one unconnected UDP socket (out/rc): "x"
// with MSG_MORE to the admitted port argv[1], "y" to the asked port argv[2], setsockopt(UDP_CORK), "z" to argv[1] and
// "w" to argv[2]. On a second socket connected to the bare-admitted port argv[3] (out/rc2): the connect, an unaddressed
// sendmsg with MSG_MORE, a send() with MSG_MORE, and a sendfile of probe.py into the socket. On a
// third socket connected to argv[1] (out/rc3): a sendmmsg with MSG_MORE whose first message has no address and whose
// second names the admitted abstract name argv[4].
const udpCorkProbe = `import ctypes, errno, os, socket, struct, sys
a, c, b, name = int(sys.argv[1]), int(sys.argv[2]), int(sys.argv[3]), sys.argv[4]
def outcome(f):
    try:
        f()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
def send(data, flags, port):
    return outcome(lambda: s.sendto(data, flags, ("127.0.0.1", port)))
rc = [send(b"x", socket.MSG_MORE, a), send(b"y", 0, c), outcome(lambda: s.setsockopt(17, 1, 1)),
      send(b"z", 0, a), send(b"w", 0, c)]
with open("out/rc", "w") as f:
    f.write(" ".join(rc))
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
src = open("probe.py", "rb")
rc2 = [outcome(lambda: u.connect(("127.0.0.1", b))), outcome(lambda: u.sendmsg([b"m"], [], socket.MSG_MORE)),
       outcome(lambda: u.send(b"n", socket.MSG_MORE)), outcome(lambda: os.sendfile(u.fileno(), src.fileno(), 0, 1 << 20))]
with open("out/rc2", "w") as f:
    f.write(" ".join(rc2))
libc = ctypes.CDLL(None, use_errno=True)
class iovec(ctypes.Structure):
    _fields_ = [("base", ctypes.c_void_p), ("len", ctypes.c_size_t)]
class msghdr(ctypes.Structure):
    _fields_ = [("name", ctypes.c_void_p), ("namelen", ctypes.c_uint32), ("iov", ctypes.POINTER(iovec)),
                ("iovlen", ctypes.c_size_t), ("control", ctypes.c_void_p), ("controllen", ctypes.c_size_t),
                ("flags", ctypes.c_int)]
class mmsghdr(ctypes.Structure):
    _fields_ = [("hdr", msghdr), ("len", ctypes.c_uint)]
v = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
v.connect(("127.0.0.1", a))
b0 = ctypes.create_string_buffer(b"q"); b1 = ctypes.create_string_buffer(b"r")
iov0 = iovec(ctypes.cast(b0, ctypes.c_void_p), 1); iov1 = iovec(ctypes.cast(b1, ctypes.c_void_p), 1)
sun = struct.pack("=H", socket.AF_UNIX) + b"\x00" + name.encode()
sunbuf = ctypes.create_string_buffer(sun, len(sun))
arr = (mmsghdr * 2)()
arr[0].hdr = msghdr(None, 0, ctypes.pointer(iov0), 1, None, 0, 0)
arr[1].hdr = msghdr(ctypes.cast(sunbuf, ctypes.c_void_p), len(sun), ctypes.pointer(iov1), 1, None, 0, 0)
n = libc.sendmmsg(v.fileno(), arr, 2, socket.MSG_MORE)
with open("out/rc3", "w") as f:
    f.write(str(n) if n >= 0 else errno.errorcode.get(ctypes.get_errno(), "?"))
`

// TestIntegrationAskUDPPendingFrame end to end at tier landlock: a UDP socket's
// pending frame takes every later datagram before the kernel reads its address, so an approved datagram relayed onto a
// socket that held a frame to an admitted port went there, under a person's allow line naming the asked port.
func TestIntegrationAskUDPPendingFrame(t *testing.T) {
	runAskUDPCorked(t, tegoBinary(t), "landlock")
}

// runAskUDPCorked runs udpCorkProbe at tier against a contract that admits one loopback port (A), a second by a bare
// host:port (B) and an abstract unix name, and asks for a third (C). Every operation that could leave a frame pending
// is refused datagram-corked, decided on the socket alone (supervisor R13's pending frames): the MSG_MORE datagram to A,
// the cork, B's unaddressed sendmsg and send() with MSG_MORE and its sendfile, and the batch whose first address is the
// unix name on a socket connected to A, which was continued before the design round and left a frame the next
// approved datagram joined. So no frame is ever pending: the approved "y" and the approval's later "w" reach C as
// their own datagrams, under the person's allow, "z" reaches A, B receives nothing, and every line names where its
// bytes went.
func runAskUDPCorked(t *testing.T, bin, tier string) {
	t.Helper()
	connA, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	gotA := make(chan string, 8)
	go func() {
		buf := make([]byte, 64)
		for {
			n, _, err := connA.ReadFromUDP(buf)
			if err != nil {
				close(gotA)
				return
			}
			gotA <- string(buf[:n])
		}
	}()
	t.Cleanup(func() { _ = connA.Close() })
	connC, receivedC := listenUDP(t)
	connB, receivedB := listenUDP(t)
	a, c := connA.LocalAddr().(*net.UDPAddr).Port, connC.LocalAddr().(*net.UDPAddr).Port
	b := connB.LocalAddr().(*net.UDPAddr).Port
	bus := fmt.Sprintf("tego-it-frames-%d", a)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: bin}
	contract := fmt.Sprintf(`version: 0
name: iaskudpcork
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  allow: ["udp://127.0.0.1:%d", "127.0.0.1:%d", "unix:@%s"]
  ask: ["udp://127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME"]
ask:
  timeout: 30s
limits:
  pids: 64
record: full
`, python, resolved, a, b, bus, c)
	s.f = newFixture(t, contract)
	if tier != "landlock" {
		pinned := strings.Replace(contract, "tier: landlock\n", "tier: "+tier+"\n", 1)
		if err := os.WriteFile(filepath.Join(s.f.dir, "agent.yaml"), []byte(pinned), 0o600); err != nil {
			t.Fatal(err)
		}
		agentOwns(t, filepath.Join(s.f.dir, "agent.yaml"))
	}
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(udpCorkProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py %d %d %d %s\n", python, a, c, b, bus)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	if req["op"] != "send" || req["target"] != fmt.Sprintf("udp://127.0.0.1:%d", c) {
		t.Fatalf("held request %v", req)
	}
	s.answer(t, "approve", filepath.Base(dir), req["ask_id"].(string))
	evs := s.finish(t, run, dir)
	netLines := lines(t, evs, record.KindNet)
	if rc := s.out("rc"); rc != "EACCES ok EACCES ok ok" {
		t.Fatalf("the probe's sends came to %q; want \"EACCES ok EACCES ok ok\"; net lines %v", rc, netLines)
	}
	if rc2 := s.out("rc2"); rc2 != "ok EACCES EACCES EACCES" {
		t.Fatalf("B's connect, sendmsg, send and sendfile came to %q; want \"ok EACCES EACCES EACCES\"; net lines %v", rc2, netLines)
	}
	if rc3 := s.out("rc3"); rc3 != "EACCES" {
		t.Fatalf("the batch came to %q; want EACCES; net lines %v", rc3, netLines)
	}
	_ = connA.SetReadDeadline(time.Now().Add(2 * time.Second))
	var atA []string
	for g := range gotA {
		atA = append(atA, g)
	}
	if len(atA) != 1 || atA[0] != "z" || receivedC.Load() != 2 || receivedB.Load() != 0 {
		t.Fatalf("A received %q, C %d datagrams, B %d; want \"z\" alone at A, \"y\" and \"w\" at C, nothing at B", atA, receivedC.Load(), receivedB.Load())
	}
	unaddressed, batch := 0, 0
	for _, l := range netLines {
		if l["_rule"] != "datagram-corked" || l["_verdict"] != "refused" {
			continue
		}
		switch l["dst"] {
		case "family(0)":
			unaddressed++ // B's sendmsg, send() and sendfile name no destination
		case "unix:@" + bus:
			batch++ // the batch's line names its first address
		}
	}
	if unaddressed != 3 || batch != 1 {
		t.Fatalf("%d refused datagram-corked lines with no destination and %d naming the unix name, want 3 and 1: %v", unaddressed, batch, netLines)
	}
	corks := 0
	for _, l := range lines(t, evs, record.KindRefused) {
		if l["op"] == "setsockopt" && l["_rule"] == "datagram-corked" && l["target"] == "setsockopt level 17 option 1" {
			corks++
		}
	}
	if corks != 1 {
		t.Fatalf("%d refused setsockopt(UDP_CORK) lines, want 1", corks)
	}
	want := []struct{ dst, verdict, rule, authority string }{
		{fmt.Sprintf("127.0.0.1:%d", a), "refused", "datagram-corked", ""},
		{fmt.Sprintf("127.0.0.1:%d", c), "allow", fmt.Sprintf("net[udp://127.0.0.1:%d]", c), "human"},
		{fmt.Sprintf("127.0.0.1:%d", a), "allow", fmt.Sprintf("net[udp://127.0.0.1:%d]", a), ""},
		{fmt.Sprintf("127.0.0.1:%d", c), "allow", fmt.Sprintf("net[udp://127.0.0.1:%d]", c), "human"},
		{fmt.Sprintf("127.0.0.1:%d", a), "allow", fmt.Sprintf("net[udp://127.0.0.1:%d]", a), ""}, // the batch's socket's connect
	}
	var got []map[string]any
	for _, l := range netLines {
		if d := l["dst"]; d == want[0].dst || d == want[1].dst {
			got = append(got, l)
		}
	}
	if len(got) != len(want) {
		t.Fatalf("%d net lines for the two ports, want %d: %v", len(got), len(want), got)
	}
	for i, w := range want {
		l := got[i]
		if l["dst"] != w.dst || l["_verdict"] != w.verdict || l["_rule"] != w.rule || (w.authority != "" && l["_authority"] != w.authority) {
			t.Fatalf("net line %d %v; want dst %s %s rule %s authority %q", i, l, w.dst, w.verdict, w.rule, w.authority)
		}
	}
}

// nonDumpableCopyProbe copies probe.py into out/copy1 with sendfile, makes itself non-dumpable (prctl PR_SET_DUMPABLE
// 0, as ssh-agent does), copies it into out/copy2 the same way, and writes both outcomes and copy2's descriptor to
// out/rc. Every file is opened before the prctl, so nothing after it but the second sendfile is notified.
const nonDumpableCopyProbe = `import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
src, d1, d2, rc = open("probe.py", "rb"), open("out/copy1", "wb"), open("out/copy2", "wb"), open("out/rc", "w")
def copy(dst):
    try:
        os.sendfile(dst.fileno(), src.fileno(), 0, 1 << 16)
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
first = copy(d1)
libc.prctl(4, 0, 0, 0, 0)
rc.write("%s %s %d" % (first, copy(d2), d2.fileno()))
`

// TestIntegrationNonDumpableFileCopy end to end at tier landlock. In a run that decides datagrams
// the filter notifies every sendfile (enforce-landlock R11d), and the supervisor reads the output descriptor's kind on a
// pidfd_getfd duplicate, which an unprivileged tier 1 is refused (EPERM) for a process that made itself non-dumpable.
// Such a copy may be into a UDP socket, so it is refused, fail-closed, as the failure table's row says; but the line
// is what happened: a refused line, op sendfile, target the descriptor, rule fd-unreadable, never a net line claiming a
// refused TCP operation and a descriptor race. The same copy while the process was dumpable is continued with no line,
// and under a root launcher, whose supervisor may duplicate a non-dumpable task's descriptors, so is the second.
func TestIntegrationNonDumpableFileCopy(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: tegoBinary(t)}
	s.f = newFixture(t, fmt.Sprintf(`version: 0
name: inondumpcopy
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  allow: ["tcp://127.0.0.1:1"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
`, python, resolved))
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(nonDumpableCopyProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\nexec %q probe.py\n", python)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	evs := s.runToEnd(t)
	var fd int
	if os.Geteuid() == 0 {
		// A root launcher's supervisor keeps CAP_SYS_PTRACE, which pidfd_getfd's access check lets past a
		// non-dumpable target: it reads the descriptor, a file, and continues the copy with no line.
		if _, err := fmt.Sscanf(s.out("rc"), "ok ok %d", &fd); err != nil {
			t.Fatalf("the copies came to %q; want \"ok ok <fd>\" under a root supervisor (%v)", s.out("rc"), err)
		}
		for _, l := range lines(t, evs, record.KindRefused) {
			if l["op"] == "sendfile" {
				t.Errorf("refused line %v; want no sendfile refused", l)
			}
		}
		for _, l := range netLinesBesideNSS(t, evs) {
			t.Errorf("net line %v; a file copy is no network operation", l)
		}
		return
	}
	if _, err := fmt.Sscanf(s.out("rc"), "ok EACCES %d", &fd); err != nil {
		t.Fatalf("the copies came to %q; want \"ok EACCES <fd>\" (%v); refused lines %v", s.out("rc"), err, lines(t, evs, record.KindRefused))
	}
	for _, l := range netLinesBesideNSS(t, evs) {
		t.Errorf("net line %v; a file copy is no network operation", l)
	}
	var copies []map[string]any
	for _, l := range lines(t, evs, record.KindRefused) {
		if l["op"] == "sendfile" {
			copies = append(copies, l)
		}
	}
	if len(copies) != 1 || copies[0]["_rule"] != "fd-unreadable" || copies[0]["target"] != fmt.Sprintf("fd %d", fd) ||
		copies[0]["_reason"] != string(record.ReasonNetNotAllowed) {
		t.Fatalf("refused sendfile lines %v; want one, rule fd-unreadable, target fd %d, reason net-not-allowed", copies, fd)
	}
}

// nssSockets are the sockets glibc's NSS connects to for a user lookup: nscd's, and sssd's for "passwd: sss" in
// nsswitch.conf (the RHEL family's default).
var nssSockets = map[string]bool{"unix:/var/run/nscd/socket": true, "unix:/var/lib/sss/pipes/nss": true}

// netLinesBesideNSS is the run's net lines but its connects to an NSS daemon's socket, which it logs. Where /bin/sh is
// bash (the RHEL family), the agent's shell looks its user up at start, and on a host whose nsswitch.conf names sss
// that lookup connects to nscd's and sssd's sockets, which the contract does not allow: the run refuses and records
// them, true lines of the shell's (AlmaLinux 9.8: two to nscd's socket, one to sssd's, 2026-11-10). They are no
// line about the copy, whose descriptor is a file; every other net line still is.
func netLinesBesideNSS(t *testing.T, evs []*record.Event) []map[string]any {
	t.Helper()
	var out []map[string]any
	for _, l := range lines(t, evs, record.KindNet) {
		if dst, _ := l["dst"].(string); l["proto"] == "unix" && nssSockets[dst] {
			t.Logf("net line %v: the shell's user lookup through NSS, not the copy", l)
			continue
		}
		out = append(out, l)
	}
	return out
}

// nssConnect reports whether e is a net line of a connect to an NSS daemon's socket (nssSockets).
func nssConnect(e *record.Event) bool {
	if e.Kind != record.KindNet {
		return false
	}
	var p struct {
		Dst   string `json:"dst"`
		Proto string `json:"proto"`
	}
	return json.Unmarshal(e.Payload, &p) == nil && p.Proto == "unix" && nssSockets[p.Dst]
}

// nonDumpableTwiceProbe makes itself non-dumpable, copies probe.py into out/<argv[1]> with sendfile twice, and writes
// both outcomes to out/rc-<argv[1]>.
const nonDumpableTwiceProbe = `import ctypes, errno, os, sys
libc = ctypes.CDLL(None, use_errno=True)
src, dst, rc = open("probe.py", "rb"), open("out/" + sys.argv[1], "wb"), open("out/rc-" + sys.argv[1], "w")
def copy():
    try:
        os.sendfile(dst.fileno(), src.fileno(), 0, 1 << 16)
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
libc.prctl(4, 0, 0, 0, 0)
rc.write("%s %s" % (copy(), copy()))
`

// TestIntegrationObserveRecordsEachNonDumpableProcess end to end at tier
// landlock: an observe run continues a sendfile whose output descriptor it could not read and records it gap
// what=record why=fd-unreadable-sendfile once per binary (supervisor R30). A non-dumpable process hides its binary
// behind the same ptrace check that refuses its pidfd_getfd, so the line names none; keyed by that empty name, the run
// wrote one line for its first such process and none for the second. Each process now gets its own line, carrying its
// pid, and its repeat shares it (supervisor R31). Under a root launcher the supervisor reads the descriptors (it keeps
// CAP_SYS_PTRACE), so there is nothing unread to record.
func TestIntegrationObserveRecordsEachNonDumpableProcess(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	s := &askReadScene{bin: tegoBinary(t)}
	s.f = newFixture(t, fmt.Sprintf(`version: 0
name: iobservenondump
command: ["/bin/sh"]
tier: landlock
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  allow: ["tcp://127.0.0.1:1"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
`, python, resolved))
	if err := os.WriteFile(filepath.Join(s.f.dir, "probe.py"), []byte(nonDumpableTwiceProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	script := fmt.Sprintf("#!/bin/sh\n%q probe.py a\n%q probe.py b\n", python, python)
	if err := os.WriteFile(filepath.Join(s.f.dir, "agent.sh"), []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(s.f.dir, "agent.sh"), filepath.Join(s.f.dir, "probe.py"))
	s.env = isolatedEnv(t, s.f)
	run := s.tego(t, "run", "--observe", filepath.Join(s.f.dir, "agent.yaml"), "--", "/bin/sh", "agent.sh")
	run.Dir = s.f.dir
	out, err := run.CombinedOutput()
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("tego run --observe exited %d:\n%s", code, out)
	}
	if a, b := s.out("rc-a"), s.out("rc-b"); a != "ok ok" || b != "ok ok" {
		t.Fatalf("the copies came to %q and %q; want \"ok ok\" each: an observe run refuses nothing", a, b)
	}
	dirs := runDirs(t, s.f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	anchored(t, dirs[0])
	evs := events(t, dirs[0])
	byPID := map[int]int{}
	for _, e := range evs {
		var p record.GapPayload
		if e.Kind != record.KindGap || e.DecodePayload(&p) != nil || p.Why != "fd-unreadable-sendfile" {
			continue
		}
		if p.What != record.GapRecord || p.Binary != "" {
			t.Errorf("gap %+v; want what=record naming no binary: a non-dumpable process's exe cannot be read", p)
		}
		byPID[e.PID]++
	}
	want := 2
	if os.Geteuid() == 0 {
		want = 0
	}
	if len(byPID) != want {
		t.Fatalf("fd-unreadable-sendfile gaps by pid %v; want one for each of %d processes", byPID, want)
	}
	for pid, n := range byPID {
		if n != 1 {
			t.Errorf("process %d: %d gap lines, want one for its two copies", pid, n)
		}
	}
	if refused := lines(t, evs, record.KindRefused); len(refused) != 0 {
		t.Errorf("refused lines %v in an observe run, which refused nothing", refused)
	}
}

// observeFrameProbe makes the three pending-frame operations an enforcing run refuses that name no destination on a
// UDP socket connected to argv[1]: a sendfile of probe.py into it, a send() with MSG_MORE, and setsockopt(UDP_CORK);
// it writes each outcome to out/rc, "ok" or the errno's name.
const observeFrameProbe = `import errno, os, socket, sys
u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
u.connect(("127.0.0.1", int(sys.argv[1])))
src = open("probe.py", "rb")
def outcome(f):
    try:
        f()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
rc = [outcome(lambda: os.sendfile(u.fileno(), src.fileno(), 0, 64)), outcome(lambda: u.send(b"n", socket.MSG_MORE)),
      outcome(lambda: u.setsockopt(socket.SOL_UDP, 1, 1))]
with open("out/rc", "w") as f:
    f.write(" ".join(rc))
`

// TestIntegrationObserveRecordsPendingFrames end to end: an observe run of a contract that decides
// datagrams installs enforce-landlock R11d's pending-frame arms, as an enforcing run does, so its record holds a line for
// each operation the enforcing run would refuse datagram-corked, the unaddressed ones included, and the kernel performs
// each (supervisor R30). Before, the observe filter carried no such arm: the unaddressed send with MSG_MORE, the cork and
// the sendfile went unrecorded, and the record under-reported what enforcement would refuse. The cork, which no net line
// can name, is a gap what=record why=datagram-corked-setsockopt, never a refused line.
func TestIntegrationObserveRecordsPendingFrames(t *testing.T) {
	conn, _ := listenUDP(t)
	port := conn.LocalAddr().(*net.UDPAddr).Port
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skipf("no python3: %v", err)
	}
	resolved, err := filepath.EvalSymlinks(python)
	if err != nil {
		t.Fatal(err)
	}
	f := newFixture(t, fmt.Sprintf(`version: 0
name: iobserveframes
command: ["/bin/sh"]
fs:
  write: ["./out/"]
exec:
  allow: ["/bin/sh", %q, %q]
net:
  allow: ["udp://127.0.0.1:%d"]
env:
  pass: ["PATH", "HOME"]
limits:
  pids: 64
`, python, resolved, port))
	if err := os.WriteFile(filepath.Join(f.dir, "probe.py"), []byte(observeFrameProbe), 0o600); err != nil {
		t.Fatal(err)
	}
	agentOwns(t, filepath.Join(f.dir, "probe.py"))
	s := &askReadScene{bin: tegoBinary(t), f: f}
	s.env = isolatedEnv(t, f)
	run := s.tego(t, "run", "--observe", filepath.Join(f.dir, "agent.yaml"), "--", python, "probe.py", fmt.Sprint(port))
	run.Dir = f.dir
	out, err := run.CombinedOutput()
	if code := exitCodeOf(t, err); code != 0 {
		t.Fatalf("tego run --observe exited %d:\n%s", code, out)
	}
	if rc := s.out("rc"); rc != "ok ok ok" {
		t.Fatalf("the probe's operations came to %q; want \"ok ok ok\": an observe run refuses nothing", rc)
	}
	dirs := runDirs(t, f.root)
	if len(dirs) != 1 {
		t.Fatalf("run directories %v, want one", dirs)
	}
	evs := events(t, dirs[0])
	corked := 0
	for _, l := range lines(t, evs, record.KindNet) {
		if l["_rule"] == "datagram-corked" && l["dst"] == "family(0)" {
			corked++ // the sendfile and the send() name no destination
		}
	}
	cork := 0
	for _, l := range lines(t, evs, record.KindGap) {
		if l["what"] == record.GapRecord && l["why"] == "datagram-corked-setsockopt" && l["binary"] == resolved {
			cork++
		}
	}
	if corked != 2 || cork != 1 {
		t.Fatalf("%d datagram-corked net lines with no destination and %d cork gaps, want 2 and 1; net lines %v, gaps %v",
			corked, cork, lines(t, evs, record.KindNet), lines(t, evs, record.KindGap))
	}
	// Nothing was refused, so no refused line and no last-refusal.json, which TEGO_REASON would hand the agent as a
	// refusal.
	if refused := lines(t, evs, record.KindRefused); len(refused) != 0 {
		t.Errorf("refused lines %v in an observe run, which refused nothing", refused)
	}
	if _, err := os.Stat(filepath.Join(dirs[0], "last-refusal.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("last-refusal.json: %v, want none: nothing was refused", err)
	}
}

// runAskUDPCase runs tc with the tego binary bin at tier.
func runAskUDPCase(t *testing.T, bin, tier string, tc askUDPCase) {
	t.Helper()
	conn, received := listenUDP(t)
	dst := conn.LocalAddr().String()
	scope := "udp://" + dst
	if tc.bare {
		scope = dst
	}
	s := newAskUDPScene(t, bin, tier, tc.timeout, scope, dst, tc.sends, tc.how)
	run, dir := s.start(t)
	req := s.pending(t, filepath.Base(dir))
	op := map[bool]string{true: "connect", false: "send"}[tc.how == "connect"]
	if req["op"] != op || req["target"] != "udp://"+dst || req["rule"] != "net["+scope+"]" || req["hold"] != "connect" {
		t.Fatalf("held request %v", req)
	}
	if tc.answer != nil {
		s.answer(t, append([]string{tc.answer[0], filepath.Base(dir), req["ask_id"].(string)}, tc.answer[1:]...)...)
	}
	evs := s.finish(t, run, dir)
	for i := 1; i <= tc.sends; i++ {
		if rc := s.out(fmt.Sprintf("rc%d", i)); rc != tc.rc {
			t.Fatalf("datagram %d came to %q; want %q; the run's net lines: %v", i, rc, tc.rc, lines(t, evs, record.KindNet))
		}
	}
	if want := map[bool]int{true: 0, false: tc.sends}[tc.reason != ""]; received.Load() != int32(want) {
		t.Fatalf("the listener received %d datagrams; want %d", received.Load(), want)
	}
	answers := lines(t, evs, record.KindAnswer)
	if len(answers) != tc.asks || !strings.HasPrefix(answers[0]["by"].(string), tc.by) || (tc.reason != "" && answers[0]["answer_reason"] != tc.reason) {
		t.Fatalf("answer lines %v", answers)
	}
	for _, a := range answers[1:] {
		if a["by"] != "standing:"+req["ask_id"].(string) {
			t.Fatalf("a later socket's answer %v: want one by standing:%s", a, req["ask_id"])
		}
	}
	var got []map[string]any
	for _, l := range lines(t, evs, record.KindNet) {
		if l["dst"] == dst {
			got = append(got, l)
		}
	}
	if len(got) != tc.sends {
		t.Fatalf("%d net lines for the port, want %d: %v", len(got), tc.sends, got)
	}
	for _, l := range got {
		ok := l["_rule"] == "net["+scope+"]" && l["proto"] == "udp"
		if tc.reason == "" {
			ok = ok && l["_verdict"] == "allow" && l["_authority"] == "human"
		} else {
			ok = ok && l["_verdict"] == "refused" && l["_reason"] == tc.reason
		}
		if !ok {
			t.Fatalf("net line %v", l)
		}
	}
}
