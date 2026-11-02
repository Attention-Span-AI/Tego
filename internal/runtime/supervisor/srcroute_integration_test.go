// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeSourceRoute runs sourceRouteChecks under the filter of a run with a net: section, its source-route arm included
// (landlock.BuildFilterSourceRoute), over the declared-net harness's contract.
const modeSourceRoute = "source-route"

// sourceRouteChecks are a net: run's source routes, each made from the target under the real filter and loop (GAPS
// C34): the setsockopt that puts one on a socket, which the filter's arm refuses; a datagram whose control message
// carries one, addressed to the declared port or sent on a socket connected to it, which the loop refuses; and,
// beside them, a plain datagram, one with a benign control message and a TCP connect to the declared port, which go
// through. Every route's hops are loopback addresses, so a send that did leave stayed on this machine.
func sourceRouteChecks() []checkResult {
	ports := splitPorts(os.Getenv(helperPorts))
	declared := &unix.SockaddrInet4{Port: ports[0], Addr: [4]byte{127, 0, 0, 1}}
	var out []checkResult
	add := func(name string, err error, n int) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n})
	}
	// IPOPT_NOOP, then IPOPT_LSRR of length 7, pointer 4, one hop: 127.0.0.2.
	lsrr := []byte{1, 0x83, 7, 4, 127, 0, 0, 2}
	// A type 2 routing header via ::1: next header, length 2, type 2, segments left 1, reserved, the address.
	rthdr := make([]byte, 24)
	rthdr[1], rthdr[2], rthdr[3], rthdr[23] = 2, 2, 1, 1
	setsockopt := func(name string, domain, level, opt int, val []byte) {
		fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			add(name, err, 0)
			return
		}
		defer unix.Close(fd) //nolint:errcheck // the target's own socket
		_, _, e := unix.Syscall6(unix.SYS_SETSOCKOPT, uintptr(fd), uintptr(level), uintptr(opt),
			uintptr(unsafe.Pointer(&val[0])), uintptr(len(val)), 0)
		add(name, sysErr(e), 0)
	}
	setsockopt("setsockopt_ip_options", unix.AF_INET, unix.SOL_IP, unix.IP_OPTIONS, lsrr)
	setsockopt("setsockopt_ipv6_rthdr", unix.AF_INET6, unix.SOL_IPV6, unix.IPV6_RTHDR, rthdr)

	send := func(name string, domain int, to unix.Sockaddr, connect bool, oob []byte) {
		fd, err := unix.Socket(domain, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			add(name, err, 0)
			return
		}
		defer unix.Close(fd) //nolint:errcheck // the target's own socket
		if connect {
			if err := unix.Connect(fd, to); err != nil {
				add(name, err, 0)
				return
			}
			to = nil
		}
		n, err := unix.SendmsgN(fd, []byte("x"), oob, to, 0)
		add(name, err, n)
	}
	send("sendmsg_ip_retopts", unix.AF_INET, declared, false, cmsgOf(unix.SOL_IP, unix.IP_RETOPTS, lsrr))
	send("sendmsg_connected_ip_retopts", unix.AF_INET, declared, true, cmsgOf(unix.SOL_IP, unix.IP_RETOPTS, lsrr))
	send("sendmsg_ipv6_rthdr", unix.AF_INET6, &unix.SockaddrInet6{Port: ports[0], Addr: [16]byte{15: 1}}, false,
		cmsgOf(unix.SOL_IPV6, unix.IPV6_RTHDR, rthdr))
	send("sendmsg_plain", unix.AF_INET, declared, false, nil)
	send("sendmsg_tos", unix.AF_INET, declared, false, cmsgOf(unix.SOL_IP, unix.IP_TOS, []byte{0x10, 0, 0, 0}))

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.Connect(fd, declared)
		_ = unix.Close(fd)
	}
	add("connect_tcp", err, 0)
	return out
}

// sysErr is a raw syscall's errno as an error, nil for none.
func sysErr(e unix.Errno) error {
	if e == 0 {
		return nil
	}
	return e
}

// TestIntegrationSourceRoute is GAPS C34 end to end at tier landlock, on the real kernel, filter and loop: under a
// net: section with no gate an agent could put an LSRR route or an IPv6 routing header on its socket, or carry one in a
// datagram's control message, and the kernel sent the admitted datagram, or the relayed connect, to the route's first
// hop, an address no entry admits. Now the setsockopt is refused EPERM by the filter's arm, and a datagram whose
// control message routes it is refused with R10's errno and one refused line, rule relay-source-routed, whether it
// names the declared destination or goes to a connected socket's peer. A plain datagram, one carrying a benign
// IP_TOS, and a TCP connect to the declared port still go through. A host without IPv6 skips its two IPv6 cells.
func TestIntegrationSourceRoute(t *testing.T) {
	h := startHarnessMode(t, 0, modeSourceRoute, nil)
	h.stop(t)
	noIPv6 := func(c checkResult) bool { return isErrno(c.Err, unix.EAFNOSUPPORT) }
	for _, name := range []string{"setsockopt_ip_options", "setsockopt_ipv6_rthdr"} {
		if c := h.check(t, name); !isErrno(c.Err, unix.EPERM) && !noIPv6(c) {
			t.Errorf("%s = %q, want EPERM from the filter's source-route arm", name, c.Err)
		}
	}
	routed := 0
	for _, name := range []string{"sendmsg_ip_retopts", "sendmsg_connected_ip_retopts", "sendmsg_ipv6_rthdr"} {
		c := h.check(t, name)
		if noIPv6(c) {
			continue
		}
		routed++
		if !isErrno(c.Err, refusalErrno) || c.N > 0 {
			t.Errorf("%s = %q (%d sent), want R10's errno and nothing sent", name, c.Err, c.N)
		}
	}
	for _, name := range []string{"sendmsg_plain", "sendmsg_tos", "connect_tcp"} {
		if c := h.check(t, name); c.Err != "" {
			t.Errorf("%s = %q, want it to go through", name, c.Err)
		}
	}
	lines := 0
	for _, ev := range h.sink.all() {
		if ev.Rule != ruleSourceRouted {
			continue
		}
		lines++
		if ev.Kind != record.KindNet || ev.Verdict != record.VerdictRefused {
			t.Errorf("line %+v; want a refused net line", ev)
		}
	}
	if lines != routed {
		t.Errorf("%d %s lines for %d routed datagrams, want one each", lines, ruleSourceRouted, routed)
	}
}
