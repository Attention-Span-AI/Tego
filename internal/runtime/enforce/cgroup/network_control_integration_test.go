// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/internal/policy/decide"
	"github.com/attention-span-ai/tego/internal/runtime/enforce/landlock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// TestNetworkControlsOnRealKernel verifies socket-cgroup bind ownership,
// packet source admission, exact reply state and real accepted-socket release.
// It belongs only in the disposable privileged integration guest.
func TestNetworkControlsOnRealKernel(t *testing.T) {
	one := uint64(1)
	c := &agent.Contract{Net: &agent.NetSection{Listen: []string{"tcp://127.0.0.1:0"}, Ingress: []agent.IngressRule{{From: "127.0.0.1", To: "tcp://127.0.0.1:0"}}, Limits: &agent.NetworkLimits{Connections: &one, PendingConnects: &one}}}
	listen, ingress, limits, err := agent.CompileListenerControl(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: c, Listen: listen, Ingress: ingress, NetLimits: limits, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, _ := realControlRun(t, "network-control", rt)
	g := h.NetworkGuarantees()
	if !g.ListenerBind || !g.IngressSources || !g.NetworkConnections || !g.NetworkPending {
		t.Fatalf("actual mechanism proof missing: %+v", g)
	}
	fd := controlSocket(t, dir, "tcp4")
	if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
		t.Fatalf("declared ephemeral bind: %v", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	port := bound.(*unix.SockaddrInet4).Port
	if port == 0 {
		t.Fatal("kernel did not allocate a port")
	}
	if err := unix.Listen(fd, 8); err != nil {
		t.Fatal(err)
	}
	if err := unix.Bind(fd, &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); !errors.Is(err, unix.EPERM) {
		t.Fatalf("port-zero grant admitted fixed rebind: %v", err)
	}
	// The failed attempt must not overwrite the admitted listener's rule.
	deny := net.Dialer{Timeout: 150 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.2")}}
	if conn, err := deny.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		conn.Close()
		t.Fatal("unlisted source completed a handshake")
	}
	allow := net.Dialer{Timeout: time.Second, LocalAddr: &net.TCPAddr{IP: net.ParseIP("127.0.0.1")}}
	client, err := allow.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("declared source handshake: %v", err)
	}
	defer client.Close()
	accepted, _, err := unix.Accept4(fd, unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if accepted >= 0 {
			unix.Close(accepted)
		}
	}()
	stats := controlStats(t, h)
	if stats.Connections != 1 || stats.Pending != 0 || stats.DeniedIngress == 0 {
		t.Fatalf("SYN-to-accepted conservation: %+v", stats)
	}
	if _, err := unix.Write(accepted, []byte("reply")); err != nil {
		t.Fatal(err)
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	reply := make([]byte, 5)
	if n, err := client.Read(reply); err != nil || n != 5 || string(reply) != "reply" {
		t.Fatalf("declared listener reply: %q %v", reply[:n], err)
	}
	second := net.Dialer{Timeout: 150 * time.Millisecond}
	if conn, err := second.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
		conn.Close()
		t.Fatal("accepted connection ceiling not enforced")
	}
	if err := unix.SetsockoptLinger(accepted, unix.SOL_SOCKET, unix.SO_LINGER, &unix.Linger{Onoff: 1, Linger: 0}); err != nil {
		t.Fatal(err)
	}
	unix.Close(accepted)
	accepted = -1
	client.Close()
	deadline := time.Now().Add(time.Second)
	for controlStats(t, h).Connections != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if stats := controlStats(t, h); stats.Connections != 0 || stats.Pending != 0 || stats.DeniedConnections == 0 {
		t.Fatalf("actual TCP_CLOSE did not release once: %+v", stats)
	}
	third, err := allow.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("capacity not reusable after actual close: %v", err)
	}
	third.Close()
}

func TestNetworkListenAutobindOnRealKernel(t *testing.T) {
	for _, tc := range []struct {
		name    string
		listen  []string
		allowed bool
	}{
		{"empty", []string{}, false},
		{"fixed", []string{"tcp://0.0.0.0:49152"}, false},
		{"ephemeral", []string{"tcp://0.0.0.0:0"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			contract := &agent.Contract{Net: &agent.NetSection{Listen: tc.listen}}
			listen, _, _, err := agent.CompileListenerControl(contract, nil)
			if err != nil {
				t.Fatal(err)
			}
			rt := &agent.RuleTable{Contract: contract, Listen: listen, Tier: backend.TierCgroup, Record: agent.RecordFull}
			h, dir, _ := realControlRun(t, "listen-"+tc.name, rt)
			if !h.NetworkGuarantees().ListenerBind {
				t.Fatal("actual pre-listen kernel admission absent")
			}
			fd := controlSocket(t, dir, "tcp4")
			err = unix.Listen(fd, 8)
			if tc.allowed {
				if err != nil {
					t.Fatalf("declared autobind: %v", err)
				}
				name, err := unix.Getsockname(fd)
				if err != nil || name.(*unix.SockaddrInet4).Port == 0 {
					t.Fatalf("not actually bound: %v %v", name, err)
				}
			} else if !errors.Is(err, unix.EACCES) {
				t.Fatalf("implicit bind bypass: %v", err)
			}
		})
	}
}

// An inherited socket has an outside creator cgroup. Its original governed
// task must still apply its own listener policy at the actual listen hook.
func TestNetworkImportedListenOnRealKernel(t *testing.T) {
	for _, allow := range []bool{false, true} {
		t.Run(map[bool]string{false: "empty-policy", true: "declared-name"}[allow], func(t *testing.T) {
			name := fmt.Sprintf("tego-import-listen-%d-%v", os.Getpid(), allow)
			fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			outside := os.NewFile(uintptr(fd), "outside-created-bound-socket")
			defer outside.Close()
			if err := unix.Bind(fd, &unix.SockaddrUnix{Name: "@" + name}); err != nil {
				t.Fatal(err)
			}
			contract := &agent.Contract{Net: &agent.NetSection{Listen: []string{}}}
			if allow {
				contract.Net.Listen = []string{"unix:@" + name}
			}
			listen, _, _, err := agent.CompileListenerControl(contract, nil)
			if err != nil {
				t.Fatal(err)
			}
			rt := &agent.RuleTable{Contract: contract, Listen: listen, Tier: backend.TierCgroup, Record: agent.RecordFull}
			h, dir, _ := realControlRun(t, "import-listen", rt)
			if !h.NetworkGuarantees().ListenerBind || !h.ListenOutcomes() {
				t.Fatal("actual listener plane/outcome proof missing")
			}
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNetworkImportedListenHelper$")
			cmd.Env = append(os.Environ(), "TEGO_IMPORTED_LISTEN_HELPER=1")
			cmd.ExtraFiles = []*os.File{outside}
			cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("child actual listen: %v %s", err, out)
			}
			got, err := strconv.Atoi(strings.TrimSpace(string(out)))
			want := int(unix.EACCES)
			if allow {
				want = 0
			}
			if err != nil || got != want {
				t.Fatalf("imported listener got %q, want errno %d", out, want)
			}
		})
	}
}

func TestNetworkImportedListenHelper(t *testing.T) {
	if os.Getenv("TEGO_IMPORTED_LISTEN_HELPER") != "1" {
		return
	}
	errno := 0
	if err := unix.Listen(3, 8); err != nil {
		var value unix.Errno
		if !errors.As(err, &value) {
			os.Exit(2)
		}
		errno = int(value)
	}
	fmt.Println(errno)
	os.Exit(0)
}

// This fixture requests the actual pre-listen plane, rather than relying on
// cgroup bind hooks that do not run for TCP listen's implicit autobind.
func realControlRun(t *testing.T, name string, rt *agent.RuleTable) (*Handle, *os.File, uint64) {
	t.Helper()
	requireBPFCaps(t)
	mode, build := hostPlane(t)
	rows, err := decide.CompilePlane(rt)
	if err != nil {
		t.Fatal(err)
	}
	rel := fmt.Sprintf("/tego-it-%s-%d", name, os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0755); err != nil {
		t.Fatalf("create private cgroup: %v", err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatal(err)
	}
	ll := landlock.New(landlock.Options{})
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}, Plane: PlaneSetup{Mode: mode, Build: build},
		Inherit: func(ctx context.Context, rt *agent.RuleTable, _ Run) (Inherited, error) {
			return ll.Prepare(ctx, rt, landlock.Run{Plane: rows, PlaneMaps: true})
		}})
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-" + name, Agent: "a", CgroupID: id, CgroupPath: rel, PlaneRows: rows})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("close: %v", err)
		}
	})
	if err := h.Attach(id); err != nil {
		t.Fatal(err)
	}
	if err := h.Arm(); err != nil {
		t.Fatal(err)
	}
	dir, err := os.Open(full)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { dir.Close() })
	return h, dir, id
}

func TestNetworkExpiryOnRealKernel(t *testing.T) {
	port := listenLoopback(t, "tcp4", "127.0.0.1")
	ip := netip.MustParseAddr("127.0.0.1")
	end := time.Now().Add(500 * time.Millisecond)
	rule := agent.NetRule{Raw: fmt.Sprintf("host.invalid:%d", port), Host: "host.invalid", Proto: agent.ProtoTCP, Port: port, Verdict: agent.VerdictAllow, IPs: []netip.Addr{ip}, ExpiresAt: end}
	rt := &agent.RuleTable{Net: []agent.NetRule{rule}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, id := realRun(t, "network-expiry", rt)
	// Cold object preparation must not consume the test's live interval.
	end = time.Now().Add(500 * time.Millisecond)
	rule.ExpiresAt = end
	refreshed := *rt
	refreshed.Net = []agent.NetRule{rule}
	if err := h.RefreshNet(&refreshed); err != nil {
		t.Fatal(err)
	}
	dst := netip.AddrPortFrom(ip, uint16(port))
	if err := relayConnect(t, dir, "tcp4", dst); err != nil {
		t.Fatalf("live hostname: %v", err)
	}
	if pause := time.Until(end); pause > 0 {
		time.Sleep(pause + time.Millisecond)
	}
	if err := relayConnect(t, dir, "tcp4", dst); !errors.Is(err, unix.EPERM) {
		t.Fatalf("expired hostname without refresh: %v", err)
	}
	// An independent literal grant must remain available immediately when the
	// earlier hostname expires, including the correct declaration attribution.
	rule.ExpiresAt = time.Now().Add(500 * time.Millisecond)
	literal := rule
	literal.Raw = dst.String()
	literal.Host = ""
	literal.Static = true
	literal.ExpiresAt = time.Time{}
	rt2 := &agent.RuleTable{Net: []agent.NetRule{rule, literal}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h2, dir2, id2 := realRun(t, "network-expiry-fallback", rt2)
	if pause := time.Until(rule.ExpiresAt); pause > 0 {
		time.Sleep(pause + time.Millisecond)
	}
	if err := relayConnect(t, dir2, "tcp4", dst); err != nil {
		t.Fatalf("independent literal shadowed after expiry: %v", err)
	}
	var br bpf.Breadcrumb
	if err := h2.kern.(*bpfKernel).maps[bpf.MapReason].Lookup(&id2, &br); err != nil || h2.Rules().RuleName(br.RuleIdx) != literal.RuleName() {
		t.Fatalf("fallback attribution %+v %v", br, err)
	}
	_ = h
	_ = id
}

func TestConnectApprovalOnRealKernel(t *testing.T) {
	ip := netip.MustParseAddr("127.0.0.1")
	askPort := listenLoopback(t, "tcp4", "127.0.0.1")
	allowPort := listenLoopback(t, "tcp4", "127.0.0.1")
	rt := &agent.RuleTable{Net: []agent.NetRule{
		{Raw: fmt.Sprintf("ask:%d", askPort), Proto: agent.ProtoTCP, Port: askPort, Verdict: agent.VerdictAsk, IPs: []netip.Addr{ip}},
		{Raw: fmt.Sprintf("allow:%d", allowPort), Proto: agent.ProtoTCP, Port: allowPort, Verdict: agent.VerdictAllow, IPs: []netip.Addr{ip}},
	}, Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, _ := realRun(t, "connect-approval", rt)
	// The real launcher arms its membership before any agent socket operation.
	// Ordinary destination tables alone do not require that recorder row, but
	// one-shot approvals bind the credit to this live run's slot generation.
	if err := h.Arm(); err != nil {
		t.Fatal(err)
	}
	ask := netip.AddrPortFrom(ip, uint16(askPort))
	allowed := netip.AddrPortFrom(ip, uint16(allowPort))
	fd := controlSocket(t, dir, "tcp4")
	if err := unix.Connect(fd, controlSockaddr(ask)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("ask connected before approval: %v", err)
	}
	revoke, err := h.GrantConnect(nil, fd, ask, agent.ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer revoke()
	// A second refused destination does not consume or inherit this credit.
	wrong := netip.AddrPortFrom(ip, 1)
	if err := unix.Connect(fd, controlSockaddr(wrong)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("approval widened destination: %v", err)
	}
	if err := unix.Connect(fd, controlSockaddr(ask)); err != nil {
		t.Fatalf("exact approved connect: %v", err)
	}
	cookie, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	key, err := connectApprovalKey(h.slot, h.gen, cookie, ask, agent.ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	var credit bpf.ConnectCredit
	m := h.kern.(*bpfKernel).maps[bpf.MapConnectApprovals]
	if err := m.Lookup(&key, &credit); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("consumed credit remains: %+v %v", credit, err)
	}
	other := controlSocket(t, dir, "tcp4")
	if err := unix.Connect(other, controlSockaddr(ask)); !errors.Is(err, unix.EPERM) {
		t.Fatalf("different socket inherited approval: %v", err)
	}
	if untaken, err := revoke(); err != nil || untaken {
		t.Fatalf("revoking the consumed credit: untaken=%v %v; want taken", untaken, err)
	}
	// An ordinary-policy allow does not spend an unrelated approval; caller
	// cleanup revokes it, including when a relay returns a normal kernel error.
	ordinary := controlSocket(t, dir, "tcp4")
	revokeAllowed, err := h.GrantConnect(nil, ordinary, allowed, agent.ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	defer revokeAllowed()
	if err := unix.Connect(ordinary, controlSockaddr(allowed)); err != nil {
		t.Fatal(err)
	}
	cookie, err = socketCookie(ordinary)
	if err != nil {
		t.Fatal(err)
	}
	key, err = connectApprovalKey(h.slot, h.gen, cookie, allowed, agent.ProtoTCP)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Lookup(&key, &credit); err != nil || credit.Credit != 1 {
		t.Fatalf("ordinary allow consumed credit: %+v %v", credit, err)
	}
	if untaken, err := revokeAllowed(); err != nil || !untaken {
		t.Fatalf("revoking the credit an ordinary allow left: untaken=%v %v; want untaken", untaken, err)
	}
	if err := m.Lookup(&key, &credit); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("revoked credit remains: %v", err)
	}
	// A grant names its socket's own transport: a UDP socket takes no TCP grant and a TCP socket no UDP one
	// (TestDatagramApprovalOnRealKernel has the UDP grants).
	udp := controlSocket(t, dir, "udp4")
	if revoke, err := h.GrantConnect(nil, udp, ask, agent.ProtoTCP); err == nil {
		revoke()
		t.Fatal("UDP socket admitted a TCP approval")
	}
	tcp := controlSocket(t, dir, "tcp4")
	if revoke, err := h.GrantConnect(nil, tcp, ask, agent.ProtoUDP); err == nil {
		revoke()
		t.Fatal("TCP socket admitted a UDP approval")
	}
	// GrantDatagram takes the socket's identity (ADR 0023 F8): the supervisor checks the socket is UDP, and the
	// handle refuses a domain that is not IP.
	if revoke, err := h.GrantDatagram(nil, 1, unix.AF_UNIX, ask); err == nil {
		revoke()
		t.Fatal("a unix socket's domain admitted a datagram approval")
	}
}

// grantDatagramFD grants as the supervisor's askDatagram does: by the cookie and domain of the socket fd, which it
// reads from its duplicate of the agent's socket (GrantDatagram takes no descriptor number, ADR 0023 F8).
func grantDatagramFD(t *testing.T, h *Handle, fd int, dst netip.AddrPort) (Revoke, error) {
	t.Helper()
	cookie, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN)
	if err != nil {
		t.Fatal(err)
	}
	return h.GrantDatagram(nil, cookie, domain, dst)
}

// TestDatagramApprovalOnRealKernel: an approved UDP destination (supervisor R13d) is admitted by the run's sendmsg4/6
// once, on the granted socket alone and to that destination alone, for an AF_INET socket, an AF_INET6 one and an
// IPv4 destination of an AF_INET6 socket in its mapped spelling, which sendmsg4 decides (udpv6_sendmsg); a UDP
// connect's grant is taken by connect4/6. A credit the kernel took is gone; one it did not is gone once revoked.
func TestDatagramApprovalOnRealKernel(t *testing.T) {
	for _, tc := range []struct{ name, family, host, spelled string }{
		{"udp4", "udp4", "127.0.0.1", ""},
		{"udp6", "udp6", "::1", ""},
		{"udp6-mapped", "udp6", "127.0.0.1", "::ffff:127.0.0.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			listen := "udp4"
			if tc.host == "::1" {
				listen = "udp6"
			}
			receiver, err := net.ListenUDP(listen, &net.UDPAddr{IP: net.ParseIP(tc.host)})
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			ap := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
			ask := netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			rt := &agent.RuleTable{Net: []agent.NetRule{
				{Raw: "udp://" + ask.String(), Proto: agent.ProtoUDP, Port: int(ask.Port()), Verdict: agent.VerdictAsk, IPs: []netip.Addr{ask.Addr()}},
			}, Tier: backend.TierCgroup, Record: agent.RecordFull}
			h, dir, _ := realRun(t, "datagram-approval-"+tc.name, rt)
			if err := h.Arm(); err != nil {
				t.Fatal(err)
			}
			sendTo := ask
			if tc.spelled != "" {
				sendTo = netip.AddrPortFrom(netip.MustParseAddr(tc.spelled), ask.Port())
			}
			fd := controlSocket(t, dir, tc.family)
			send := func(fd int, to netip.AddrPort) error { return unix.Sendto(fd, []byte("q"), 0, controlSockaddr(to)) }
			if err := send(fd, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("datagram sent before approval: %v", err)
			}
			revoke, err := grantDatagramFD(t, h, fd, sendTo)
			if err != nil {
				t.Fatal(err)
			}
			defer revoke()
			wrong := netip.AddrPortFrom(sendTo.Addr(), 1)
			if err := send(fd, wrong); !errors.Is(err, unix.EPERM) {
				t.Fatalf("approval widened destination: %v", err)
			}
			other := controlSocket(t, dir, tc.family)
			if err := send(other, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("different socket inherited approval: %v", err)
			}
			if err := send(fd, sendTo); err != nil {
				t.Fatalf("exact approved datagram: %v", err)
			}
			if err := send(fd, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("one datagram approval admitted a second: %v", err)
			}
			if untaken, err := revoke(); err != nil || untaken {
				t.Fatalf("revoking the credit sendmsg took: untaken=%v %v; want taken", untaken, err)
			}
			// An unused credit is gone once revoked, and its revoke says the hook never took it: what tells the
			// supervisor an approved datagram did not pass sendmsg4/6 as its own (R13d).
			unused, err := grantDatagramFD(t, h, other, sendTo)
			if err != nil {
				t.Fatal(err)
			}
			if untaken, err := unused(); err != nil || !untaken {
				t.Fatalf("revoking an unused credit: untaken=%v %v; want untaken", untaken, err)
			}
			if err := send(other, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("revoked datagram approval admitted a send: %v", err)
			}
			// A UDP connect takes its grant at connect4/6; the connected socket's sends name no address.
			conn := controlSocket(t, dir, tc.family)
			if err := unix.Connect(conn, controlSockaddr(sendTo)); !errors.Is(err, unix.EPERM) {
				t.Fatalf("UDP connect before approval: %v", err)
			}
			revokeConn, err := h.GrantConnect(nil, conn, sendTo, agent.ProtoUDP)
			if err != nil {
				t.Fatal(err)
			}
			defer revokeConn()
			if err := unix.Connect(conn, controlSockaddr(sendTo)); err != nil {
				t.Fatalf("approved UDP connect: %v", err)
			}
			_, err = unix.Write(conn, []byte("q"))
			if tc.spelled == "" && err != nil {
				t.Fatalf("send on the approved connected socket: %v", err)
			}
			// An AF_INET6 socket connected to an IPv4 peer sends through udp_sendmsg with the peer as its address
			// (udpv6_sendmsg), so sendmsg4 decides each send after the connect and refuses it: the supervisor refuses
			// such a connect ask-unavailable at these tiers (TestAskUDPConnectOfAnIPv6SocketToIPv4IsUnavailableAtRootTiers).
			if tc.spelled != "" && !errors.Is(err, unix.EPERM) {
				t.Fatalf("send on a v6 socket connected to a v4-mapped peer: %v; want sendmsg4's EPERM", err)
			}
			// A grant lives connectApprovalLifetime: one the relay never used admits nothing after it.
			late := controlSocket(t, dir, tc.family)
			if _, err := grantDatagramFD(t, h, late, sendTo); err != nil {
				t.Fatal(err)
			}
			time.Sleep(connectApprovalLifetime + 100*time.Millisecond)
			if err := send(late, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("an expired datagram grant admitted a send: %v", err)
			}
			// The slot-reuse stale row: a grant of another gen of this slot, as a run that died before its revoke
			// and before the reaper leaves it, is absent to this run.
			stale := controlSocket(t, dir, tc.family)
			staleCookie, err := socketCookie(stale)
			if err != nil {
				t.Fatal(err)
			}
			sk, err := connectApprovalKey(h.slot, h.gen+1, staleCookie, ask, agent.ProtoUDP)
			if err != nil {
				t.Fatal(err)
			}
			var ts unix.Timespec
			if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
				t.Fatal(err)
			}
			m := h.kern.(*bpfKernel).maps[bpf.MapConnectApprovals]
			sv := bpf.ConnectCredit{Credit: 1, DeadlineNS: uint64(ts.Nano()) + uint64(time.Minute)}
			if err := m.Update(&sk, &sv, ebpf.UpdateNoExist); err != nil {
				t.Fatal(err)
			}
			if err := send(stale, sendTo); !errors.Is(err, unix.EPERM) {
				t.Fatalf("a datagram grant of another gen of the slot admitted a send: %v", err)
			}
			// Detach removes every grant of the slot, of every gen, UDP ones among them.
			if _, err := grantDatagramFD(t, h, controlSocket(t, dir, tc.family), sendTo); err != nil {
				t.Fatal(err)
			}
			slot := h.slot
			if err := h.Detach(); err != nil {
				t.Fatalf("Detach: %v", err)
			}
			var k bpf.ConnectApprovalKey
			var credit bpf.ConnectCredit
			for it := m.Iterate(); it.Next(&k, &credit); {
				if k.RunIdx == slot {
					t.Fatalf("an approval of slot %d survived Detach: %+v", slot, k)
				}
			}
		})
	}
}

func TestNetworkDatagramAndByteLimitsOnRealKernel(t *testing.T) {
	for _, family := range []string{"udp4", "udp6"} {
		t.Run(family, func(t *testing.T) {
			t.Run("reply-window", func(t *testing.T) { checkUDPReplyWindow(t, family) })
			for _, mode := range []string{"zero-bytes", "one-per-second", "zero-connections"} {
				t.Run(mode, func(t *testing.T) {
					host := "127.0.0.1"
					if family == "udp6" {
						host = "::1"
					}
					receiver, err := net.ListenUDP(family, &net.UDPAddr{IP: net.ParseIP(host)})
					if err != nil {
						t.Fatal(err)
					}
					defer receiver.Close()
					dst := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
					dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
					zero, one := uint64(0), uint64(1)
					bytes := agent.ByteSize(0)
					limits := agent.NetworkLimits{}
					switch mode {
					case "zero-bytes":
						limits.Bytes = &bytes
					case "one-per-second":
						limits.DatagramsPerSecond = &one
					case "zero-connections":
						limits.Connections = &zero
					}
					rt := &agent.RuleTable{Net: []agent.NetRule{{Raw: dst.String(), Proto: agent.ProtoUDP, Port: int(dst.Port()), Verdict: agent.VerdictAllow, IPs: []netip.Addr{dst.Addr()}, Static: true}}, NetLimits: limits, Tier: backend.TierCgroup, Record: agent.RecordFull}
					h, dir, _ := realRun(t, "datagram-"+family+mode, rt)
					fd := controlSocket(t, dir, family)
					send := func() { _ = unix.Sendto(fd, []byte("x"), 0, controlSockaddr(dst)) }
					read := func(expect bool) {
						t.Helper()
						receiver.SetReadDeadline(time.Now().Add(150 * time.Millisecond))
						var data [16]byte
						n, _, err := receiver.ReadFromUDP(data[:])
						if expect {
							if err != nil || n != 1 || data[0] != 'x' {
								t.Fatalf("expected datagram: n=%d err=%v", n, err)
							}
						} else if err == nil {
							t.Fatal("refused datagram delivered")
						}
					}
					send()
					if mode == "one-per-second" {
						read(true)
						send()
						read(false)
						stats := controlStats(t, h)
						if stats.DatagramsOut != 1 || stats.DeniedDatagrams == 0 {
							t.Fatalf("rate not enforced/accounted: %+v", stats)
						}
						var now unix.Timespec
						if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &now); err != nil {
							t.Fatal(err)
						}
						if wait := time.Duration(stats.WindowNS+uint64(time.Second)) - time.Duration(now.Nano()); wait > 0 {
							time.Sleep(wait + time.Millisecond)
						}
						send()
						read(true)
						stats = controlStats(t, h)
						if stats.DatagramsOut != 2 || stats.Datagrams != 1 {
							t.Fatalf("window reset corrupted monotonic total: %+v", stats)
						}
					} else {
						read(false)
						stats := controlStats(t, h)
						if stats.Bytes != 0 || stats.DatagramsOut != 0 || mode == "zero-bytes" && stats.DeniedBytes == 0 || mode == "zero-connections" && stats.DeniedConnections == 0 {
							t.Fatalf("explicit zero not enforced/accounted: %+v", stats)
						}
					}
					counters, err := h.NetworkCountersSnapshot()
					if err != nil {
						t.Fatal(err)
					}
					if counters.BytesOut == nil || counters.DatagramsOut == nil || !counters.Available["bytes_out"] {
						t.Fatalf("actual egress accounting absent: %+v", counters)
					}
				})
			}
		})
	}
}

// A listener reply refreshes this exact socket's admitted inbound tuple. It
// must retain the UDP lifetime, rather than acquiring TCP's 30-minute window.
func checkUDPReplyWindow(t *testing.T, family string) {
	t.Helper()
	host := "127.0.0.1"
	if family == "udp6" {
		host = "::1"
	}
	peer, err := net.ListenUDP(family, &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	remote := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())
	raw := "udp://" + net.JoinHostPort(host, "0")
	c := &agent.Contract{Net: &agent.NetSection{Listen: []string{raw}, Ingress: []agent.IngressRule{{From: host, To: raw}}}}
	listeners, ingress, limits, err := agent.CompileListenerControl(c, nil)
	if err != nil {
		t.Fatal(err)
	}
	rt := &agent.RuleTable{Contract: c, Listen: listeners, Ingress: ingress, NetLimits: limits,
		Net:  []agent.NetRule{{Raw: remote.String(), Proto: agent.ProtoUDP, Port: int(remote.Port()), IPs: []netip.Addr{remote.Addr()}, Verdict: agent.VerdictAllow, Static: true}},
		Tier: backend.TierCgroup, Record: agent.RecordFull}
	h, dir, _ := realControlRun(t, "udp-reply-window-"+family, rt)
	if !h.NetworkGuarantees().IngressSources {
		t.Fatal("actual ingress/reply hooks unavailable")
	}
	fd := controlSocket(t, dir, family)
	ip := netip.MustParseAddr(host)
	if err := unix.Bind(fd, controlSockaddr(netip.AddrPortFrom(ip, 0))); err != nil {
		t.Fatalf("declared UDP bind: %v", err)
	}
	bound, err := unix.Getsockname(fd)
	if err != nil {
		t.Fatal(err)
	}
	var port int
	switch sa := bound.(type) {
	case *unix.SockaddrInet4:
		port = sa.Port
	case *unix.SockaddrInet6:
		port = sa.Port
	default:
		t.Fatalf("unexpected listener address %T", bound)
	}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &unix.Timeval{Sec: 1}); err != nil {
		t.Fatal(err)
	}
	if _, err := peer.WriteToUDP([]byte("request"), &net.UDPAddr{IP: net.ParseIP(host), Port: port}); err != nil {
		t.Fatal(err)
	}
	var data [16]byte
	n, from, err := unix.Recvfrom(fd, data[:], 0)
	if err != nil || string(data[:n]) != "request" {
		t.Fatalf("declared UDP request: n=%d err=%v", n, err)
	}
	var before, after unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &before); err != nil {
		t.Fatal(err)
	}
	if err := unix.Sendto(fd, []byte("reply"), 0, from); err != nil {
		t.Fatalf("owned UDP reply send: %v", err)
	}
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if n, _, err := peer.ReadFromUDP(data[:]); err != nil || string(data[:n]) != "reply" {
		t.Fatalf("owned UDP reply: n=%d err=%v", n, err)
	}
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &after); err != nil {
		t.Fatal(err)
	}
	local, addrFamily, err := bpf.Addr16(ip)
	if err != nil {
		t.Fatal(err)
	}
	remoteAddr, _, err := bpf.Addr16(remote.Addr().Unmap())
	if err != nil {
		t.Fatal(err)
	}
	key := bpf.NetFlowKey{RunIdx: h.slot, Gen: h.gen, Family: addrFamily, Proto: bpf.ProtoUDP,
		LocalPort: uint16(port), RemotePort: remote.Port(), Local: local, Remote: remoteAddr}
	var flow bpf.NetFlow
	if err := h.kern.(*bpfKernel).maps[bpf.MapNetFlows].Lookup(&key, &flow); err != nil {
		t.Fatalf("exact admitted UDP tuple missing: %v", err)
	}
	cookie, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	if flow.Inbound != 1 || flow.Cookie != cookie ||
		flow.ExpiresNS < uint64(before.Nano())+uint64(29*time.Second) ||
		flow.ExpiresNS > uint64(after.Nano())+uint64(30*time.Second) {
		t.Fatalf("UDP reply changed exact flow identity/lifetime: %+v cookie=%d before=%d after=%d", flow, cookie, before.Nano(), after.Nano())
	}
}

func controlSocket(t *testing.T, dir *os.File, family string) int {
	t.Helper()
	pid, fd, done := holdSocket(t, dir, family)
	t.Cleanup(done)
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pidfd)
	dup, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unix.Close(dup) })
	return dup
}

func controlSockaddr(dst netip.AddrPort) unix.Sockaddr {
	if dst.Addr().Is4() {
		return &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()}
	}
	return &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()}
}

func controlStats(t *testing.T, h *Handle) bpf.NetStats {
	t.Helper()
	var stats bpf.NetStats
	if err := h.kern.(*bpfKernel).maps[bpf.MapNetStats].LookupWithFlags(&h.slot, &stats, ebpf.LookupLock); err != nil {
		t.Fatal(err)
	}
	return stats
}

// TestNetworkReservationRowsAreBoundedOnRealKernel is bpf-1: tego_net_pending and tego_net_sockets are
// non-evicting maps every run of a build shares, so a run may hold rows only for the reservations it admitted, and
// an admitted inbound SYN whose handshake never completes must not hold its row and its charge until teardown. A
// peer sends 64 SYNs from distinct ports and never completes a handshake (its own stack resets each SYN-ACK, which
// no sockops callback reports): two are admitted, the 62 refused keep no row, and the two admitted expire after
// bpf.NetSYNReservation, freeing the cap. An agent with connections: 2 that opens eight UDP sockets to an allowed
// destination keeps rows for its two admitted sockets only. It belongs only in the disposable privileged guest.
func TestNetworkReservationRowsAreBoundedOnRealKernel(t *testing.T) {
	t.Run("inbound-syn", func(t *testing.T) {
		two := uint64(2)
		c := &agent.Contract{Net: &agent.NetSection{Listen: []string{"tcp://127.0.0.1:0"},
			Limits: &agent.NetworkLimits{Connections: &two, PendingConnects: &two}}}
		listen, ingress, limits, err := agent.CompileListenerControl(c, nil)
		if err != nil {
			t.Fatal(err)
		}
		rt := &agent.RuleTable{Contract: c, Listen: listen, Ingress: ingress, NetLimits: limits, Tier: backend.TierCgroup, Record: agent.RecordFull}
		h, dir, _ := realControlRun(t, "reservation-syn", rt)
		fd := controlSocket(t, dir, "tcp4")
		if err := unix.Bind(fd, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatalf("declared ephemeral bind: %v", err)
		}
		bound, err := unix.Getsockname(fd)
		if err != nil {
			t.Fatal(err)
		}
		port := bound.(*unix.SockaddrInet4).Port
		if err := unix.Listen(fd, 128); err != nil {
			t.Fatal(err)
		}
		sendRawSYNs(t, port, 64)
		deadline := time.Now().Add(2 * time.Second)
		for s := controlStats(t, h); s.DeniedConnections+s.DeniedPending < 62 && time.Now().Before(deadline); s = controlStats(t, h) {
			time.Sleep(10 * time.Millisecond)
		}
		pending := h.kern.(*bpfKernel).maps[bpf.MapNetPending]
		rows := func() int {
			keys, err := mapKeys[bpf.NetFlowKey](pending)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, k := range keys {
				if k.RunIdx == h.slot {
					n++
				}
			}
			return n
		}
		stats := controlStats(t, h)
		if n := rows(); n != 2 || stats.Pending != 2 || stats.Connections != 2 || stats.DeniedConnections+stats.DeniedPending < 62 {
			t.Fatalf("64 uncompleted SYNs under caps of 2 left %d pending rows, stats %+v; want the 2 admitted", n, stats)
		}
		deadline = time.Now().Add(bpf.NetSYNReservation + 15*time.Second)
		for controlStats(t, h).Pending != 0 && time.Now().Before(deadline) {
			time.Sleep(500 * time.Millisecond)
		}
		if n, stats := rows(), controlStats(t, h); n != 0 || stats.Pending != 0 || stats.Connections != 0 {
			t.Fatalf("uncompleted SYN reservations did not expire after %v: %d rows, stats %+v", bpf.NetSYNReservation, n, stats)
		}
		dial := net.Dialer{Timeout: time.Second}
		conn, err := dial.Dial("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("capacity not reusable after the reservations expired: %v", err)
		}
		conn.Close()
	})
	t.Run("refused-sockets", func(t *testing.T) {
		receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
		if err != nil {
			t.Fatal(err)
		}
		defer receiver.Close()
		dst := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
		dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
		two := uint64(2)
		rt := &agent.RuleTable{Net: []agent.NetRule{{Raw: dst.String(), Proto: agent.ProtoUDP, Port: int(dst.Port()), Verdict: agent.VerdictAllow,
			IPs: []netip.Addr{dst.Addr()}, Static: true}}, NetLimits: agent.NetworkLimits{Connections: &two}, Tier: backend.TierCgroup, Record: agent.RecordFull}
		h, dir, _ := realRun(t, "reservation-sockets", rt)
		refused := 0
		for i := 0; i < 8; i++ {
			fd := controlSocket(t, dir, "udp4")
			if err := unix.Sendto(fd, []byte("x"), 0, controlSockaddr(dst)); err != nil {
				refused++
			}
		}
		keys, err := mapKeys[bpf.NetSocketKey](h.kern.(*bpfKernel).maps[bpf.MapNetSockets])
		if err != nil {
			t.Fatal(err)
		}
		rows := 0
		for _, k := range keys {
			if k.RunIdx == h.slot {
				rows++
			}
		}
		if stats := controlStats(t, h); refused != 6 || rows != 2 || stats.Connections != 2 || stats.DeniedConnections < 6 {
			t.Fatalf("8 sockets under connections: 2: %d refused, %d socket rows, stats %+v; want 6 refused and the 2 admitted rows", refused, rows, stats)
		}
	})
}

// sendRawSYNs sends n TCP SYNs to 127.0.0.1:port from source ports 40000 upward on a raw socket, as a peer that
// never completes a handshake: the local stack resets each SYN-ACK, since no socket of its own made the SYN.
func sendRawSYNs(t *testing.T, port, n int) {
	t.Helper()
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatalf("raw socket: %v", err)
	}
	defer unix.Close(fd)
	for i := 0; i < n; i++ {
		seg := make([]byte, 20)
		binary.BigEndian.PutUint16(seg[0:], uint16(40000+i))
		binary.BigEndian.PutUint16(seg[2:], uint16(port))
		binary.BigEndian.PutUint32(seg[4:], uint32(1000+i))
		seg[12] = 5 << 4 // data offset: 20 bytes
		seg[13] = 0x02   // SYN
		binary.BigEndian.PutUint16(seg[14:], 65535)
		var sum uint32
		for _, b := range [][]byte{{127, 0, 0, 1, 127, 0, 0, 1, 0, unix.IPPROTO_TCP, 0, 20}, seg} {
			for j := 0; j+1 < len(b); j += 2 {
				sum += uint32(b[j])<<8 | uint32(b[j+1])
			}
		}
		for sum>>16 != 0 {
			sum = sum&0xffff + sum>>16
		}
		binary.BigEndian.PutUint16(seg[16:], ^uint16(sum))
		if err := unix.Sendto(fd, seg, 0, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			t.Fatalf("raw SYN %d: %v", i, err)
		}
	}
}
