// SPDX-License-Identifier: Apache-2.0

//go:build integration

package cgroup

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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

	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// netHelperEnv selects the child half of TestNetVerdictOnRealKernel.
const netHelperEnv = "TEGO_NET_HELPER"

// TestNetVerdictOnRealKernel runs the tier-2 network decision in the running kernel, from both of the places
// a connect of the agent's can come from: the agent's own process, and the seccomp supervisor, which relays
// every allowed connect from its own process on a pidfd_getfd duplicate of the agent's socket
// (docs/p0/supervisor.md R9, I2). The second is the one that never reached a decision: the kernel runs the
// run's connect4/6 because the socket belongs to the run's cgroup, but the program keyed its lookup on the
// caller's cgroup, the supervisor's, missed the run set and allowed, and wrote no breadcrumb (§5 R1, R5). The
// test relays exactly that way and requires the refusal, and requires the breadcrumb to agree with what the
// syscall returned (enforce-cgroup-observe.md §8 I4).
func TestNetVerdictOnRealKernel(t *testing.T) {
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)

	// A cgroup of the test's own at the top of the hierarchy, where no controller constraint applies and
	// nothing else lives, so the run is exactly the helper processes placed in it.
	rel := fmt.Sprintf("/tego-it-net-%d", os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}

	allowedPort, refusedPort := listenLoopback(t, "tcp4", "127.0.0.1"), listenLoopback(t, "tcp4", "127.0.0.1")
	udpAllowed, udpRefused := freeUDPPort(t), freeUDPPort(t)
	rules := []agent.NetRule{
		{Raw: "127.0.0.1:" + strconv.Itoa(allowedPort), Port: allowedPort, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true},
		{Raw: "127.0.0.1:" + strconv.Itoa(udpAllowed), Port: udpAllowed, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("127.0.0.1")}, Static: true},
	}
	v6 := loopbackV6()
	var allowed6, refused6 int
	if v6 {
		allowed6, refused6 = listenLoopback(t, "tcp6", "::1"), listenLoopback(t, "tcp6", "::1")
		rules = append(rules, agent.NetRule{Raw: "[::1]:" + strconv.Itoa(allowed6), Port: allowed6,
			Proto: agent.ProtoInet, Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr("::1")},
			Static: true})
	}

	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	rt := &agent.RuleTable{Net: rules, Tier: backend.TierCgroup, Record: agent.RecordFull}
	// The resolver is systemd-resolved's stub address. A connected UDP socket needs nothing listening, so
	// the query socket's connect is decided whatever runs on the host; a TCP one meets whatever does.
	resolver := netip.MustParseAddrPort("127.0.0.53:53")
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-net", Agent: "a", CgroupID: id, CgroupPath: rel,
		Resolvers: []netip.AddrPort{resolver}})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	reasons := h.kern.(*bpfKernel).maps[ebpfbindings.MapReason]
	if reasons == nil {
		t.Fatal("the reason map is not loaded")
	}
	breadcrumb := func(t *testing.T) ebpfbindings.Breadcrumb {
		t.Helper()
		var br ebpfbindings.Breadcrumb
		if err := reasons.Lookup(&id, &br); err != nil {
			t.Fatalf("no breadcrumb under the run's cgroup %d: %v", id, err)
		}
		return br
	}
	wantBreadcrumb := func(t *testing.T, port int, verdict ebpfbindings.Verdict) {
		t.Helper()
		br := breadcrumb(t)
		if int(br.Port) != port || ebpfbindings.Verdict(br.Verdict) != verdict || br.RunIdx != h.Slot() {
			t.Fatalf("breadcrumb = port %d verdict %d run_idx %d; want port %d verdict %d run_idx %d: the "+
				"record must say what the syscall did (§8 I4)", br.Port, br.Verdict, br.RunIdx, port, verdict, h.Slot())
		}
		if verdict == ebpfbindings.VerdictRefused && ebpfbindings.ReasonCode(br.Reason) != ebpfbindings.ReasonNetNotAllowed {
			t.Fatalf("breadcrumb reason = %d, want net-not-allowed", br.Reason)
		}
	}

	dir, err := os.Open(full)
	if err != nil {
		t.Fatalf("open %s: %v", full, err)
	}
	defer dir.Close()

	t.Run("the agent's own connect", func(t *testing.T) {
		targets := []string{"tcp4 127.0.0.1:" + strconv.Itoa(allowedPort), "tcp4 127.0.0.1:" + strconv.Itoa(refusedPort),
			"udp4 127.0.0.1:" + strconv.Itoa(udpAllowed), "udp4 127.0.0.1:" + strconv.Itoa(udpRefused)}
		want := []error{nil, unix.EPERM, nil, unix.EPERM}
		if v6 {
			targets = append(targets, "tcp6 [::1]:"+strconv.Itoa(allowed6), "tcp6 [::1]:"+strconv.Itoa(refused6))
			want = append(want, nil, unix.EPERM)
		}
		got := runNetHelper(t, dir, "connect", targets)
		for i, target := range targets {
			if !errors.Is(got[i], want[i]) {
				t.Errorf("%s from inside the run: %v, want %v", target, got[i], want[i])
				continue
			}
			t.Logf("%s from inside the run: %v", target, got[i])
		}
	})

	relay := func(t *testing.T, family string, port int, want error) {
		t.Helper()
		pid, fd, done := holdSocket(t, dir, family)
		defer done()
		pidfd, err := unix.PidfdOpen(pid, 0)
		if err != nil {
			t.Fatalf("pidfd_open(%d): %v", pid, err)
		}
		defer unix.Close(pidfd)
		dup, err := unix.PidfdGetfd(pidfd, fd, 0)
		if err != nil {
			t.Fatalf("pidfd_getfd(%d, %d): %v", pid, fd, err)
		}
		defer unix.Close(dup)
		var sa unix.Sockaddr = &unix.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}
		if family == "tcp6" {
			sa = &unix.SockaddrInet6{Port: port, Addr: netip.MustParseAddr("::1").As16()}
		}
		err = unix.Connect(dup, sa)
		if want == nil && err != nil {
			t.Fatalf("relayed %s connect to an allowed port %d: %v", family, port, err)
		}
		if want != nil && !errors.Is(err, want) {
			t.Fatalf("relayed %s connect to port %d the contract does not name = %v, want %v: the run's program "+
				"must decide a connect made on the agent's socket by another process (supervisor.md R9)",
				family, port, err, want)
		}
		t.Logf("relayed %s connect to port %d on descriptor %d of pid %d: %v", family, port, fd, pid, err)
	}

	// §5 R5's reading half, as the supervisor asks it after a relayed connect fails EPERM: the refusal and its
	// reason come back for the connect just made, and nothing comes back for another destination or for a
	// notification that arrived more than 50 ms after the decision (E5).
	wantKernelNet := func(t *testing.T, notified time.Time, ap netip.AddrPort, want record.Verdict, wantReason record.Reason) {
		t.Helper()
		v, rule, reason := h.KernelNet(ap, "tcp", notified)
		if v != want || reason != wantReason || (want == record.VerdictRefused && rule != agent.UnmatchedRule) {
			t.Fatalf("KernelNet(%v) = %q %q %q, want %q %q %q", ap, v, rule, reason, want, agent.UnmatchedRule, wantReason)
		}
	}
	t.Run("a connect relayed from outside the run on the agent's socket", func(t *testing.T) {
		notified := time.Now()
		relay(t, "tcp4", refusedPort, unix.EPERM)
		wantBreadcrumb(t, refusedPort, ebpfbindings.VerdictRefused)
		refusedAP := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(refusedPort))
		wantKernelNet(t, notified, refusedAP, record.VerdictRefused, record.ReasonNetNotAllowed)
		wantKernelNet(t, notified, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(allowedPort)), "", "")
		wantKernelNet(t, time.Now().Add(BreadcrumbStale+time.Second), refusedAP, "", "")
		notified = time.Now()
		relay(t, "tcp4", allowedPort, nil)
		wantBreadcrumb(t, allowedPort, ebpfbindings.VerdictAllow)
		wantKernelNet(t, notified, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(allowedPort)), record.VerdictAllow, "")
		if v6 {
			relay(t, "tcp6", refused6, unix.EPERM)
			wantBreadcrumb(t, refused6, ebpfbindings.VerdictRefused)
			relay(t, "tcp6", allowed6, nil)
			wantBreadcrumb(t, allowed6, ebpfbindings.VerdictAllow)
		}
	})

	t.Run("a resolver query relayed on the agent's socket", func(t *testing.T) {
		// Supervisor R14 admits the machine's resolvers on port 53 whatever the contract names, and relays
		// the query socket's connect like any other (glibc and Go connect their UDP DNS sockets). The
		// contract here names no port 53 at all; the rows the run's resolver list adds are what let it pass.
		if err := relayConnect(t, dir, "udp4", resolver); err != nil {
			t.Fatalf("relayed UDP connect to the resolver %s: %v; the kernel must admit what supervisor R14 "+
				"admits", resolver, err)
		}
		br := breadcrumb(t)
		if ebpfbindings.Verdict(br.Verdict) != ebpfbindings.VerdictAllow || br.Port != 53 ||
			h.Rules().RuleName(br.RuleIdx) != agent.ResolverRule {
			t.Fatalf("breadcrumb = verdict %d port %d rule %q; want allow on 53 under %s", br.Verdict, br.Port,
				h.Rules().RuleName(br.RuleIdx), agent.ResolverRule)
		}
		// TCP, which glibc falls back to on a truncated answer: whatever is listening decides the outcome,
		// but the run's program must not be what refuses it.
		if err := relayConnect(t, dir, "tcp4", resolver); errors.Is(err, unix.EPERM) {
			t.Fatalf("relayed TCP connect to the resolver %s refused in the kernel: %v", resolver, err)
		}
		// Port 53 on an address that is not a resolver is an ordinary destination the contract does not name.
		other := netip.MustParseAddrPort("127.0.0.54:53")
		if err := relayConnect(t, dir, "udp4", other); !errors.Is(err, unix.EPERM) {
			t.Fatalf("relayed UDP connect to %s, no resolver and not in the contract = %v, want EPERM", other, err)
		}
	})

	t.Run("E11 a descendant cgroup is decided by the run's attachment, run set or not", func(t *testing.T) {
		// cgroup_track puts a new descendant into the run set, and the run set is what the tracing programs
		// filter by; the network programs no longer read it. A program attached to the run's cgroup runs for
		// every socket beneath it with the run's own storage, so taking the descendant's row away, which is
		// what a full run set does to a new descendant (§6 E11), changes nothing here.
		child := filepath.Join(full, "child")
		if err := os.Mkdir(child, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", child, err)
		}
		defer os.Remove(child)
		childID, err := cgroupIDOfPath("/sys/fs/cgroup", filepath.Join(rel, "child"))
		if err != nil {
			t.Fatalf("child cgroup id: %v", err)
		}
		if err := h.kern.removeRun(childID); err != nil {
			t.Fatalf("remove the descendant's run-set row: %v", err)
		}
		cdir, err := os.Open(child)
		if err != nil {
			t.Fatalf("open %s: %v", child, err)
		}
		defer cdir.Close()
		targets := []string{"tcp4 127.0.0.1:" + strconv.Itoa(refusedPort), "tcp4 127.0.0.1:" + strconv.Itoa(allowedPort)}
		got := runNetHelper(t, cdir, "connect", targets)
		if !errors.Is(got[0], unix.EPERM) || got[1] != nil {
			t.Fatalf("from a descendant with no run-set row: %s = %v, %s = %v; want EPERM and success",
				targets[0], got[0], targets[1], got[1])
		}
		wantBreadcrumb(t, allowedPort, ebpfbindings.VerdictAllow)
	})

	t.Run("the caller's cgroup is not what decides", func(t *testing.T) {
		// This process is outside the run. A socket it created itself is not the run's, so the run's
		// programs never run for it and a destination the contract does not name connects normally.
		c, err := net.DialTimeout("tcp4", "127.0.0.1:"+strconv.Itoa(refusedPort), 5*time.Second)
		if err != nil {
			t.Fatalf("a connect on a socket outside the run was refused: %v", err)
		}
		c.Close()
	})
}

// TestNetHelper is the child half of TestNetVerdictOnRealKernel. It does nothing in a normal run.
func TestNetHelper(t *testing.T) {
	mode := os.Getenv(netHelperEnv)
	if mode == "" {
		t.Skip("helper process only")
	}
	out := os.NewFile(3, "report")
	switch mode {
	case "connect", "connect-mapped":
		for _, target := range strings.Split(os.Getenv("TEGO_NET_TARGETS"), ",") {
			network, addr, _ := strings.Cut(target, " ")
			var err error
			if mode == "connect-mapped" {
				err = connectMapped(network, addr)
			} else if strings.HasPrefix(network, "udp") {
				err = sendDatagram(network, addr)
			} else {
				var c net.Conn
				if c, err = net.DialTimeout(network, addr, 5*time.Second); err == nil {
					c.Close()
				}
			}
			errno := 0
			var en syscall.Errno
			if errors.As(err, &en) {
				errno = int(en)
			} else if err != nil {
				errno = -1
			}
			fmt.Fprintf(out, "%d\n", errno)
		}
	case "socket":
		// Each target is "family/type/protocol": one socket(2) with no seccomp filter in front of it, which stands
		// for any path the filter misses (cgroup/sock_create, §5 R4). The answer is its errno, 0 when it was made.
		for _, target := range strings.Split(os.Getenv("TEGO_NET_TARGETS"), ",") {
			c, err := parseSockTriple(target)
			if err != nil {
				fmt.Fprintf(out, "-1\n")
				continue
			}
			fmt.Fprintf(out, "%d\n", errnoOf(c.create()))
		}
	case "ulp":
		// Each target is a TCP ULP name: setsockopt(SOL_TCP, TCP_ULP) on a fresh unconnected TCP socket, with no seccomp
		// filter in front of it, which stands for io_uring's SOCKET_URING_OP_SETSOCKOPT (cgroup/setsockopt, ADR 0018
		// (7)). The answer is its errno, 0 when the ULP was set, or -1 when the socket ended as another family.
		for _, name := range strings.Split(os.Getenv("TEGO_NET_TARGETS"), ",") {
			fmt.Fprintf(out, "%d\n", setULP(name))
		}
	case "tcp4", "tcp6", "udp4", "udp6", "unix-stream":
		domain, typ := unix.AF_INET, unix.SOCK_STREAM
		if mode == "tcp6" || mode == "udp6" {
			domain = unix.AF_INET6
		}
		if mode == "unix-stream" {
			domain = unix.AF_UNIX
		}
		if mode == "udp4" || mode == "udp6" {
			typ = unix.SOCK_DGRAM
		}
		fd, err := unix.Socket(domain, typ|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			fmt.Fprintf(out, "ERR %v\n", err)
			return
		}
		fmt.Fprintf(out, "FD %d\n", fd)
		_ = out.Close()
		// Keep the socket until the parent is done with its duplicate.
		_, _ = io.Copy(io.Discard, os.Stdin)
	default:
		fmt.Fprintf(out, "ERR unsupported socket helper mode %q\n", mode)
	}
}

// connectMapped deliberately uses an AF_INET6 dual-stack socket. Go's generic
// net clients may unmap the address and create AF_INET sockets instead, which
// would leave the mapped-address connect6/sendmsg6 paths untested.
func connectMapped(network, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return err
	}
	if !ap.Addr().Is4In6() {
		return fmt.Errorf("mapped helper requires an IPv4-mapped address: %s", addr)
	}
	typ := unix.SOCK_DGRAM
	if network == "tcp6" {
		typ = unix.SOCK_STREAM
	} else if network != "udp6" && network != "udp6-connected" {
		return fmt.Errorf("unsupported mapped helper network %q", network)
	}
	fd, err := unix.Socket(unix.AF_INET6, typ|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY, 0); err != nil {
		return err
	}
	if err = unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_SNDTIMEO, &unix.Timeval{Sec: 5}); err != nil {
		return err
	}
	sa := &unix.SockaddrInet6{Port: int(ap.Port()), Addr: ap.Addr().As16()}
	if network == "udp6" {
		return unix.Sendto(fd, []byte("x"), 0, sa)
	}
	if err = unix.Connect(fd, sa); err != nil || network == "tcp6" {
		return err
	}
	_, err = unix.Write(fd, []byte("x"))
	return err
}

// sendDatagram sends one unconnected UDP datagram, which is what sendmsg4/6 decide (§5 R4).
func sendDatagram(network, addr string) error {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return err
	}
	c, err := net.ListenUDP(network, nil)
	if err != nil {
		return err
	}
	defer c.Close()
	_, err = c.WriteToUDPAddrPort([]byte("x"), ap)
	return err
}

// relayConnect does what the supervisor does with a connect it allows (supervisor R9): a helper inside the run's
// cgroup creates a socket of the given mode, and this process, outside the run, connects a pidfd_getfd
// duplicate of it to dst. It returns the connect's own error.
func relayConnect(t *testing.T, dir *os.File, mode string, dst netip.AddrPort) error {
	t.Helper()
	pid, fd, done := holdSocket(t, dir, mode)
	defer done()
	pidfd, err := unix.PidfdOpen(pid, 0)
	if err != nil {
		t.Fatalf("pidfd_open(%d): %v", pid, err)
	}
	defer unix.Close(pidfd)
	dup, err := unix.PidfdGetfd(pidfd, fd, 0)
	if err != nil {
		t.Fatalf("pidfd_getfd(%d, %d): %v", pid, fd, err)
	}
	defer unix.Close(dup)
	var sa unix.Sockaddr = &unix.SockaddrInet4{Port: int(dst.Port()), Addr: dst.Addr().As4()}
	if dst.Addr().Is6() {
		sa = &unix.SockaddrInet6{Port: int(dst.Port()), Addr: dst.Addr().As16()}
	}
	err = unix.Connect(dup, sa)
	t.Logf("relayed %s connect to %s on descriptor %d of pid %d: %v", mode, dst, fd, pid, err)
	return err
}

// realRun prepares and attaches a tier-2 run for rt on a fresh cgroup of the test's own, and returns the
// handle, the cgroup's directory (for placing helpers into it) and its id. Everything goes at cleanup.
func realRun(t *testing.T, name string, rt *agent.RuleTable) (*Handle, *os.File, uint64) {
	t.Helper()
	if !ebpfbindings.Available() {
		t.Skip("built without the compiled objects; add -tags tegobpf")
	}
	if err := checkBPFFS(DefaultBPFFS); err != nil {
		t.Skipf("%v", err)
	}
	requireBPFCaps(t)
	rel := fmt.Sprintf("/tego-it-%s-%d", name, os.Getpid())
	full := filepath.Join("/sys/fs/cgroup", rel)
	if err := os.Mkdir(full, 0o755); err != nil {
		t.Skipf("cannot create a cgroup for the run at %s: %v", full, err)
	}
	t.Cleanup(func() { _ = os.Remove(full) })
	id, err := cgroupIDOfPath("/sys/fs/cgroup", rel)
	if err != nil {
		t.Fatalf("cgroup id: %v", err)
	}
	b := New(Options{Machine: machineLinger(0), StateDir: pinState(t), Events: &sink{}})
	h, err := b.Prepare(context.Background(), rt, Run{ID: "it-" + name, Agent: "a", CgroupID: id, CgroupPath: rel})
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	t.Cleanup(func() {
		if err := h.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	if err := h.Attach(id); err != nil {
		t.Fatalf("Attach: %v", err)
	}
	dir, err := os.Open(full)
	if err != nil {
		t.Fatalf("open %s: %v", full, err)
	}
	t.Cleanup(func() { dir.Close() })
	return h, dir, id
}

// TestNetUnrestrictedOnRealKernel is SEMANTICS §1 in the running kernel: under a contract with no net:
// section the supervisor admits every destination (agent.RuleTable.NetUnrestricted) and relays the connect,
// and the kernel must not refuse it. The run's rows are none, so attached deciding programs refused every such connect.
func TestNetUnrestrictedOnRealKernel(t *testing.T) {
	port := listenLoopback(t, "tcp4", "127.0.0.1")
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Contract: &agent.Contract{}}
	h, dir, id := realRun(t, "open", rt)
	dst := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port))
	if err := relayConnect(t, dir, "tcp4", dst); err != nil {
		t.Fatalf("relayed connect to %s under a contract with no net: section: %v, want success", dst, err)
	}
	target := "tcp4 " + dst.String()
	if got := runNetHelper(t, dir, "connect", []string{target, "udp4 127.0.0.1:" + strconv.Itoa(freeUDPPort(t))}); got[0] != nil || got[1] != nil {
		t.Fatalf("the run's own connect and datagram under no net: section = %v, %v; want both allowed", got[0], got[1])
	}
	var br ebpfbindings.Breadcrumb
	reasons := h.kern.(*bpfKernel).maps[ebpfbindings.MapReason]
	if err := reasons.Lookup(&id, &br); err == nil {
		t.Fatalf("a breadcrumb %+v was written for a run with no network program attached", br)
	}
}

// TestNetRefreshOnRealKernel is §6 E7 as amended, in the running kernel: a host entry whose address rotated is
// refused until RefreshNet moves the run's rows, and then decided by the new address alone, which is what the
// supervisor's refreshed set admits (supervisor R8).
func TestNetRefreshOnRealKernel(t *testing.T) {
	port := listenLoopback(t, "tcp4", "127.0.0.1")
	entry := func(ip string) *agent.RuleTable {
		return &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull, Net: []agent.NetRule{{
			Raw: "api.example:" + strconv.Itoa(port), Host: "api.example", Port: port, Proto: agent.ProtoInet,
			Verdict: agent.VerdictAllow, IPs: []netip.Addr{netip.MustParseAddr(ip)},
		}}}
	}
	h, dir, _ := realRun(t, "refresh", entry("127.0.0.2"))
	now, before := "tcp4 127.0.0.1:"+strconv.Itoa(port), "tcp4 127.0.0.2:"+strconv.Itoa(port)
	if got := runNetHelper(t, dir, "connect", []string{now}); !errors.Is(got[0], unix.EPERM) {
		t.Fatalf("%s before the refresh = %v, want EPERM: the prepared rows name 127.0.0.2", now, got[0])
	}
	if err := h.RefreshNet(entry("127.0.0.1")); err != nil {
		t.Fatalf("RefreshNet: %v", err)
	}
	got := runNetHelper(t, dir, "connect", []string{now, before})
	if got[0] != nil {
		t.Fatalf("%s after the refresh = %v, want success", now, got[0])
	}
	if !errors.Is(got[1], unix.EPERM) {
		t.Fatalf("%s after the refresh = %v, want EPERM: the rotated-away address must lose its row", before, got[1])
	}
}

// runNetHelper runs the helper inside the run's cgroup and returns one result per target.
func runNetHelper(t *testing.T, dir *os.File, mode string, targets []string) []error {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := helperCommand(dir, mode)
	cmd.Env = append(cmd.Env, "TEGO_NET_TARGETS="+strings.Join(targets, ","))
	cmd.ExtraFiles = []*os.File{w}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper in the run's cgroup: %v", err)
	}
	w.Close()
	var out []error
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		n, err := strconv.Atoi(strings.TrimSpace(sc.Text()))
		switch {
		case err != nil || n < 0:
			out = append(out, fmt.Errorf("helper: %q", sc.Text()))
		case n == 0:
			out = append(out, nil)
		default:
			out = append(out, syscall.Errno(n))
		}
	}
	r.Close()
	if err := cmd.Wait(); err != nil {
		t.Fatalf("helper: %v", err)
	}
	if len(out) != len(targets) {
		t.Fatalf("helper reported %d results for %d targets", len(out), len(targets))
	}
	return out
}

// setULP sets the TCP upper-layer protocol name on a fresh unconnected AF_INET TCP socket and returns the errno, 0
// when it was set and the socket is still AF_INET, or -1 when it was set and the socket is now another family (the smc
// module's "smc" makes it AF_SMC).
func setULP(name string) int {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return errnoOf(err)
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptString(fd, unix.SOL_TCP, unix.TCP_ULP, name); err != nil {
		return errnoOf(err)
	}
	if domain, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_DOMAIN); err != nil || domain != unix.AF_INET {
		return -1
	}
	return 0
}

// holdSocket starts a helper inside the run's cgroup that creates one socket and keeps it open, and returns
// its pid and the socket's descriptor number there.
func holdSocket(t *testing.T, dir *os.File, family string) (int, int, func()) {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	cmd := helperCommand(dir, family)
	cmd.ExtraFiles = []*os.File{w}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("stdin: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	w.Close()
	line, err := bufio.NewReader(r).ReadString('\n')
	r.Close()
	var fd int
	if _, perr := fmt.Sscanf(line, "FD %d", &fd); err != nil || perr != nil {
		_ = cmd.Process.Kill()
		t.Fatalf("helper did not report its socket: %q, %v", line, err)
	}
	return cmd.Process.Pid, fd, func() {
		stdin.Close()
		_ = cmd.Wait()
	}
}

// helperCommand re-executes this test binary as TestNetHelper, placed into the run's cgroup at clone time
// (CLONE_INTO_CGROUP), the way the launcher places the agent.
func helperCommand(dir *os.File, mode string) *exec.Cmd {
	cmd := exec.Command(os.Args[0], "-test.run=^TestNetHelper$")
	cmd.Env = append(os.Environ(), netHelperEnv+"="+mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{UseCgroupFD: true, CgroupFD: int(dir.Fd())}
	cmd.Stderr = os.Stderr
	return cmd
}

// listenLoopback starts a listener that accepts and closes every connection, and returns its port.
func listenLoopback(t *testing.T, network, host string) int {
	t.Helper()
	l, err := net.Listen(network, net.JoinHostPort(host, "0"))
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, host, err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			c.Close()
		}
	}()
	return l.Addr().(*net.TCPAddr).Port
}

// freeUDPPort returns a loopback UDP port with a socket bound to it for the test's lifetime, so a datagram
// the kernel lets through has somewhere to land.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c.LocalAddr().(*net.UDPAddr).Port
}

// loopbackV6 reports whether ::1 can be listened on here.
func loopbackV6() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}
