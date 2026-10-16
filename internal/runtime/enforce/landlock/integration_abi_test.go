// SPDX-License-Identifier: Apache-2.0

//go:build integration

package landlock

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// What Landlock alone does with a pathname unix socket (R21, ABI 9, Linux 7.1) and a UDP port (R22, ABI 10, Linux 7.2),
// on a real kernel. The helper applies the ruleset Prepare built and nothing else: no seccomp filter is installed in it, so
// no supervisor answers any call, and a refusal below is the kernel's. That is what the matrix row fedora-7.2 exists
// for: every other row's kernel is below ABI 9, where the same helper must see Landlock leave both alone (the supervisor
// decides them at tier 1), and where the tests below therefore assert the other half.
const (
	helperUnixDeclared  = "TEGO_LANDLOCK_UNIX_DECLARED"
	helperUnixWritable  = "TEGO_LANDLOCK_UNIX_WRITABLE"
	helperUnixOther     = "TEGO_LANDLOCK_UNIX_OTHER"
	helperUnixElsewhere = "TEGO_LANDLOCK_UNIX_ELSEWHERE"
	helperUDPDeclared   = "TEGO_LANDLOCK_UDP_DECLARED"
	helperUDPOther      = "TEGO_LANDLOCK_UDP_OTHER"
	helperUDPFixed      = "TEGO_LANDLOCK_UDP_FIXED"

	// rowEnv is the kernel-matrix row root-suites.sh boots the suites on (its TEGO_VM_ROW, forwarded into the guest).
	rowEnv = "TEGO_VM_ROW"
)

// rowABIFloor is the Landlock ABI a kernel-matrix row is meant to have (test/vm/fetch-kernel.py: fedora-7.2 is the
// 7.2 series, ABI 10). On such a row a kernel below the floor fails the tests instead of taking the half that every
// other kernel takes: a row that lost its ABI (koji serving another series, a config without Landlock's newest rules)
// would otherwise go on passing while it tested nothing of what it exists for.
var rowABIFloor = map[string]int{"fedora-7.2": 10}

func requireRowABI(t *testing.T, abi int) {
	t.Helper()
	row := os.Getenv(rowEnv)
	if floor, ok := rowABIFloor[row]; ok && abi < floor {
		t.Fatalf("the %s row is meant to have Landlock ABI %d or more (test/vm/fetch-kernel.py), and this kernel reports %d", row, floor, abi)
	}
}

// shortTempDir is a scratch directory whose socket paths fit sockaddr_un's 108 bytes: t.TempDir() under a long $TMPDIR
// does not.
func shortTempDir(t *testing.T) string {
	t.Helper()
	if d := tempDir(t); len(d) <= 48 {
		return d
	}
	d, err := os.MkdirTemp("/tmp", "ll")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(d) })
	d, err = filepath.EvalSymlinks(d)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// listenUnix listens on a pathname socket and closes each connection it accepts.
func listenUnix(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
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

// listenUDP is a UDP socket on loopback, and its port.
func listenUDP(t *testing.T) (net.PacketConn, int) {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, c.LocalAddr().(*net.UDPAddr).Port
}

// gotDatagram reports whether c receives one within wait.
func gotDatagram(c net.PacketConn, wait time.Duration) bool {
	_ = c.SetReadDeadline(time.Now().Add(wait))
	buf := make([]byte, 8)
	n, _, err := c.ReadFrom(buf)
	return err == nil && n > 0
}

// wantRefused holds the helper's check name to Landlock's refusal (EACCES) or to being left alone.
func wantRefused(t *testing.T, r report, name string, refused bool) {
	t.Helper()
	c, ok := r.Checks[name]
	if !ok {
		t.Errorf("%s: the helper reported no result", name)
		return
	}
	switch {
	case refused && (c.OK || c.Out != "EACCES"):
		t.Errorf("%s = %+v, want EACCES: the kernel's Landlock refuses it", name, c)
	case !refused && !c.OK:
		t.Errorf("%s = %+v, want it allowed: this kernel's Landlock has no rule for it", name, c)
	}
}

// TestIntegrationUnixConnect is R21 on a real kernel. A contract with a `unix:` entry and a write entry gives the
// helper one socket per case. At ABI 9 and above Landlock alone refuses the connect to every pathname socket that has no
// rule (EACCES), while the declared socket, which Prepare held with RESOLVE_UNIX, and a socket inside a write entry, which
// gains the right, connect. Below ABI 9 Landlock has no unix right at all, so every one of the four connects goes through
// and the supervisor is the only decider: the refusal this test expects there is its absence.
//
// Spec: docs/p0/enforce-landlock.md R21.
func TestIntegrationUnixConnect(t *testing.T) {
	root := shortTempDir(t)
	mkTree(t, root, "socks/", "other/")
	declared := filepath.Join(root, "socks", "declared.sock")
	// Beside the declared one, in the same directory: only the declared inode has a rule, so a refusal here is not
	// the directory's.
	other := filepath.Join(root, "socks", "other.sock")
	elsewhere := filepath.Join(root, "other", "elsewhere.sock")
	writable := filepath.Join(root, "allowed", "write.sock")
	rt := integrationTable(t, root)
	for _, p := range []string{declared, other, elsewhere, writable} {
		listenUnix(t, p)
	}
	rt.Net = append(rt.Net, agent.NetRule{Raw: "unix:" + declared, Proto: agent.ProtoUnix, UnixPath: declared})
	h := realPrepare(t, rt)
	requireRowABI(t, h.abi)
	fd, _ := h.LandlockRuleset()
	r := runHelper(t, "net", fd, helperRoot+"="+root, helperUnixDeclared+"="+declared, helperUnixWritable+"="+writable,
		helperUnixOther+"="+other, helperUnixElsewhere+"="+elsewhere)
	refused := h.abi >= 9
	t.Logf("Landlock ABI %d: an undeclared pathname socket's connect is refused by the kernel: %v", h.abi, refused)
	wantRefused(t, r, "unix_declared", false)
	wantRefused(t, r, "unix_write_entry", false)
	wantRefused(t, r, "unix_undeclared_beside", refused)
	wantRefused(t, r, "unix_undeclared_elsewhere", refused)
}

// TestIntegrationUDPPorts is R22 on a real kernel. A contract that declares one host and port gives the helper a UDP socket
// with that port, another without. At ABI 10 and above Landlock alone refuses a send or a connect to the port that is
// not declared (EACCES, and nothing arrives), a bind to a fixed port (BIND_UDP is granted on port 0 only), and lets the
// declared port and an ephemeral bind through. Below ABI 10 UDP has no Landlock right: the send arrives and the connect
// succeeds, and a fixed bind may fail for a taken port but never with EACCES.
//
// Spec: docs/p0/enforce-landlock.md R22.
func TestIntegrationUDPPorts(t *testing.T) {
	root := tempDir(t)
	declared, declaredPort := listenUDP(t)
	other, otherPort := listenUDP(t)
	// A port nothing holds: the bind below is refused by Landlock before the kernel looks at whether it is free.
	fixed, fixedPort := listenUDP(t)
	_ = fixed.Close()
	rt := integrationTable(t, root, declaredPort)
	h := realPrepare(t, rt)
	requireRowABI(t, h.abi)
	fd, _ := h.LandlockRuleset()
	r := runHelper(t, "net", fd, helperRoot+"="+root, helperUDPDeclared+"="+strconv.Itoa(declaredPort), helperUDPOther+"="+strconv.Itoa(otherPort),
		helperUDPFixed+"="+strconv.Itoa(fixedPort))
	refused := h.abi >= 10
	t.Logf("Landlock ABI %d: a send to an undeclared UDP port is refused by the kernel: %v", h.abi, refused)
	wantRefused(t, r, "udp_send_declared", false)
	wantRefused(t, r, "udp_send_undeclared", refused)
	wantRefused(t, r, "udp_connect_undeclared", refused)
	wantRefused(t, r, "udp_bind_ephemeral", false)
	if refused {
		wantRefused(t, r, "udp_bind_fixed", true)
	} else if c := r.Checks["udp_bind_fixed"]; c.Out == "EACCES" {
		t.Errorf("udp_bind_fixed = %+v: a kernel with no UDP right refused a bind with Landlock's code", c)
	}
	if !gotDatagram(declared, time.Second) {
		t.Error("the datagram to the declared port never arrived")
	}
	if got := gotDatagram(other, 300*time.Millisecond); got == refused {
		t.Errorf("the undeclared port received a datagram: %v, want %v: a refused send delivers nothing, and an unrestricted one does", got, !refused)
	}
}

// netHelper is the "net" mode: the ruleset on fd 3, applied to every thread as the child stage would, then the connects, sends
// and binds of the two tests above, each reported with its errno's name. It installs no seccomp filter.
func netHelper() report {
	r := report{Checks: map[string]check{}}
	if err := applyAllThreads(rulesetFD); err != nil {
		if errors.Is(err, unix.ENOTSUP) {
			r.Skip = "AllThreadsSyscall needs CGO_ENABLED=0"
			return r
		}
		record(&r, "apply", err, "")
		return r
	}
	rec := func(name string, err error) { record(&r, name, err, errnoName(err)) }
	if p := os.Getenv(helperUnixDeclared); p != "" {
		rec("unix_declared", unixConnect(p))
		rec("unix_write_entry", unixConnect(os.Getenv(helperUnixWritable)))
		rec("unix_undeclared_beside", unixConnect(os.Getenv(helperUnixOther)))
		rec("unix_undeclared_elsewhere", unixConnect(os.Getenv(helperUnixElsewhere)))
	}
	if p := os.Getenv(helperUDPDeclared); p != "" {
		declared, other, fixed := port(p), port(os.Getenv(helperUDPOther)), port(os.Getenv(helperUDPFixed))
		rec("udp_send_declared", udpDo(declared, udpSend))
		rec("udp_send_undeclared", udpDo(other, udpSend))
		rec("udp_connect_undeclared", udpDo(other, udpConnect))
		rec("udp_bind_ephemeral", udpDo(0, udpBind))
		rec("udp_bind_fixed", udpDo(fixed, udpBind))
	}
	return r
}

// errnoName is the symbolic name of the errno in err ("EACCES"), "" for nil and for an error that carries none.
func errnoName(err error) string {
	var e syscall.Errno
	if errors.As(err, &e) {
		return unix.ErrnoName(e)
	}
	return ""
}

func unixConnect(path string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return unix.Connect(fd, &unix.SockaddrUnix{Name: path})
}

// udpDo runs op on a fresh UDP socket and the loopback address at port.
func udpDo(port int, op func(fd int, to *unix.SockaddrInet4) error) error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer func() { _ = unix.Close(fd) }()
	return op(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}})
}

func udpSend(fd int, to *unix.SockaddrInet4) error    { return unix.Sendto(fd, []byte("x"), 0, to) }
func udpConnect(fd int, to *unix.SockaddrInet4) error { return unix.Connect(fd, to) }
func udpBind(fd int, to *unix.SockaddrInet4) error    { return unix.Bind(fd, to) }

// port reads a port number the parent passed in the helper's environment; a value that is not one is 0, which no case
// of the helper treats as a declared port.
func port(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}
