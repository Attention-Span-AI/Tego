// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"strconv"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// modeGuard runs the target under a contract with no net: section and capture: forwarder whose models[]
// endpoint is 127.0.0.1 on the harness's allowed port, where an echo server stands in for the model.
const modeGuard = "guard"

// guardChecks are the target's ways to the model stand-in: the endpoint as declared, the unspecified
// addresses the kernel sends to loopback, another loopback address, and a datagram; then another port
// through the unspecified address, which the guard admits. Each connect that succeeds says ping and reads
// the answer, so a success is proof the bytes reached a server.
func guardChecks() []checkResult {
	ports := splitPorts(os.Getenv(helperPorts))
	model, other := ports[0], ports[1]
	var out []checkResult
	add := func(name string, err error, n int, s string) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n, Out: s})
	}
	stream := func(name string, domain int, sa unix.Sockaddr) {
		fd, err := unix.Socket(domain, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			add(name, err, 0, "")
			return
		}
		defer unix.Close(fd) //nolint:errcheck // the target's own socket
		n := 0
		buf := make([]byte, 8)
		if err = unix.Connect(fd, sa); err == nil {
			if _, err = unix.Write(fd, []byte("ping")); err == nil {
				n, err = unix.Read(fd, buf)
			}
		}
		add(name, err, n, string(buf[:max(n, 0)]))
	}
	stream("guard_model", unix.AF_INET, &unix.SockaddrInet4{Port: model, Addr: [4]byte{127, 0, 0, 1}})
	stream("guard_unspec", unix.AF_INET, &unix.SockaddrInet4{Port: model})
	stream("guard_unspec_mapped", unix.AF_INET6, &unix.SockaddrInet6{Port: model, Addr: [16]byte{10: 0xff, 11: 0xff}})
	stream("guard_loopback2", unix.AF_INET, &unix.SockaddrInet4{Port: model, Addr: [4]byte{127, 0, 0, 2}})
	stream("guard_other_unspec", unix.AF_INET, &unix.SockaddrInet4{Port: other})
	for _, tc := range []struct {
		name string
		sa   unix.Sockaddr
	}{
		{"guard_udp", &unix.SockaddrInet4{Port: model, Addr: [4]byte{127, 0, 0, 1}}},
		{"guard_udp_unspec", &unix.SockaddrInet4{Port: model}},
	} {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if err == nil {
			err = unix.Sendto(fd, []byte("ping"), 0, tc.sa)
			_ = unix.Close(fd)
		}
		add(tc.name, err, 0, "")
	}
	return append(out, guardUnaddressedChecks()...)
}

// guardUnaddressedChecks are sends whose msghdr names no destination on guarded IP sockets (sendUnaddressed,
// unaddressedFastOpen): a datagram on a UDP socket connected to a receiver the target binds, which the relay
// must deliver, one on an unconnected socket, and Fast-Open sends with no address, by sendmsg and by
// sendmmsg. Beside them, datagrams to the same receiver with MSG_ZEROCOPY on a socket that set SO_ZEROCOPY,
// unaddressed and addressed, which a relay refuses (zeroCopy), and whether any of them arrived.
func guardUnaddressedChecks() []checkResult {
	var out []checkResult
	add := func(name string, err error, n int, s string) {
		out = append(out, checkResult{Name: name, Err: errText(err), N: n, Out: s})
	}
	rx, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		defer unix.Close(rx) //nolint:errcheck // the target's own socket
		err = unix.Bind(rx, &unix.SockaddrInet4{Addr: [4]byte{127, 0, 0, 1}})
	}
	var to unix.Sockaddr
	if err == nil {
		to, err = unix.Getsockname(rx)
	}
	tx := -1
	if err == nil {
		tx, err = unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	}
	n := 0
	got := ""
	if err == nil {
		defer unix.Close(tx) //nolint:errcheck // the target's own socket
		if err = unix.Connect(tx, to); err == nil {
			if n, err = unix.SendmsgN(tx, []byte("ping"), nil, nil, 0); err == nil {
				buf := make([]byte, 8)
				var m int
				m, _, err = unix.Recvfrom(rx, buf, unix.MSG_DONTWAIT)
				got = string(buf[:max(m, 0)])
			}
		}
	}
	add("guard_udp_unaddressed_connected", err, n, got)

	if tx >= 0 && to != nil {
		// SO_ZEROCOPY is what makes the kernel pin the sender's pages; its answer does not matter, since the
		// relay refuses the flag whether or not it is set.
		_ = unix.SetsockoptInt(tx, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)
		_, err = unix.SendmsgN(tx, []byte("zc-1"), nil, nil, unix.MSG_ZEROCOPY)
		add("guard_udp_zerocopy_unaddressed", err, 0, "")
		zfd, zerr := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
		if zerr == nil {
			_ = unix.SetsockoptInt(zfd, unix.SOL_SOCKET, unix.SO_ZEROCOPY, 1)
			zerr = unix.Sendto(zfd, []byte("zc-2"), unix.MSG_ZEROCOPY, to)
			_ = unix.Close(zfd)
		}
		add("guard_udp_zerocopy_addressed", zerr, 0, "")
		buf := make([]byte, 8)
		m, _, rerr := unix.Recvfrom(rx, buf, unix.MSG_DONTWAIT)
		add("guard_udp_zerocopy_received", rerr, m, string(buf[:max(m, 0)]))
	}

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_, err = unix.SendmsgN(fd, []byte("ping"), nil, nil, 0)
		_ = unix.Close(fd)
	}
	add("guard_udp_unaddressed_unconnected", err, 0, "")

	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		_, err = unix.SendmsgN(fd, []byte("ping"), nil, nil, unix.MSG_FASTOPEN)
		_ = unix.Close(fd)
	}
	add("guard_tfo_unaddressed", err, 0, "")

	fd, err = unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		payload := []byte("ping")
		iov := unix.Iovec{Base: &payload[0]}
		iov.SetLen(len(payload))
		msgs := make([]mmsghdr, 2)
		for i := range msgs {
			msgs[i].hdr.Iov = &iov
			msgs[i].hdr.SetIovlen(1)
		}
		_, _, errno := unix.Syscall6(unix.SYS_SENDMMSG, uintptr(fd), uintptr(unsafe.Pointer(&msgs[0])), uintptr(len(msgs)),
			unix.MSG_FASTOPEN, 0, 0)
		if errno != 0 {
			err = errno
		}
		_ = unix.Close(fd)
	}
	add("guard_tfo_unaddressed_batch", err, 0, "")
	return out
}

// TestIntegrationModelGuard is the models[] guard on a real kernel (R7, SEMANTICS §1): the connect the kernel
// would route to the model stand-in on 127.0.0.1 is refused under every spelling that reaches it —
// 0.0.0.0 and its v4-mapped form, which ip_route_connect sends to loopback, and 127.0.0.2, which a server
// bound to all interfaces answers — and so is a datagram to it. Before the loopback aliasing, 0.0.0.0 was
// relayed and reached the stand-in, recorded allow/unmatched with dst 0.0.0.0, which is how a copy of kt2 whose
// agent connected to 0.0.0.0:$port went around the forwarder (the shipped kt2 connects to 127.0.0.1:$port;
// supervisor.md's corrections name the copy). Another port through 0.0.0.0 is admitted and relayed, and
// reaches its server.
func TestIntegrationModelGuard(t *testing.T) {
	h := startHarnessMode(t, 0, modeGuard, nil)
	h.stop(t)
	model := strconv.Itoa(h.allowedPort)
	for _, name := range []string{"guard_model", "guard_unspec", "guard_unspec_mapped", "guard_loopback2", "guard_udp", "guard_udp_unspec"} {
		if c := h.check(t, name); !isErrno(c.Err, refusalErrno) || c.Out != "" {
			t.Errorf("%s = %+v, want R10's errno and nothing read back", name, c)
		}
	}
	if c := h.check(t, "guard_other_unspec"); c.Err != "" || c.Out != "pong" {
		t.Errorf("another port through 0.0.0.0 = %+v, want the relayed connect carrying pong", c)
	}
	for _, want := range []struct{ dst, proto string }{
		{"127.0.0.1:" + model, protoTCP},
		{"0.0.0.0:" + model, protoTCP},
		{"127.0.0.2:" + model, protoTCP},
		{"127.0.0.1:" + model, protoUDP},
		{"0.0.0.0:" + model, protoUDP},
	} {
		found := false
		for _, ev := range h.netEvents(t, want.dst) {
			p := netLine(t, ev)
			if p.Proto != want.proto {
				continue
			}
			found = true
			if ev.Verdict != record.VerdictRefused || ev.Rule != "models[127.0.0.1:"+model+"]" || p.BestEffort {
				t.Errorf("%s %s: event %s/%s best_effort=%v, want refused/models[127.0.0.1:%s], enforced",
					want.proto, want.dst, ev.Verdict, ev.Rule, p.BestEffort, model)
			}
		}
		if !found {
			t.Errorf("%s %s: no net event", want.proto, want.dst)
		}
	}
	// An unaddressed datagram on a connected socket is relayed to the peer and arrives; on an unconnected
	// one the relay returns the kernel's own EDESTADDRREQ. A Fast-Open sendmsg with no address gets the
	// kernel's answer to it as read, EINVAL on a peerless socket (EOPNOTSUPP where the client side of Fast
	// Open is switched off), and the batch form R10's errno.
	if c := h.check(t, "guard_udp_unaddressed_connected"); c.Err != "" || c.N != 4 || c.Out != "ping" {
		t.Errorf("guard_udp_unaddressed_connected = %+v, want the datagram relayed to the peer and received", c)
	}
	if c := h.check(t, "guard_udp_unaddressed_unconnected"); !isErrno(c.Err, unix.EDESTADDRREQ) {
		t.Errorf("guard_udp_unaddressed_unconnected = %+v, want the kernel's own EDESTADDRREQ", c)
	}
	if c := h.check(t, "guard_tfo_unaddressed"); !isErrno(c.Err, unix.EINVAL) && !isErrno(c.Err, unix.EOPNOTSUPP) {
		t.Errorf("guard_tfo_unaddressed = %+v, want the kernel's own EINVAL", c)
	}
	if c := h.check(t, "guard_tfo_unaddressed_batch"); !isErrno(c.Err, refusalErrno) {
		t.Errorf("guard_tfo_unaddressed_batch = %+v, want R10's errno", c)
	}
	// A relayed datagram carrying MSG_ZEROCOPY is refused, addressed or not, and nothing of it arrives: the
	// kernel would have transmitted from this process's heap.
	for _, name := range []string{"guard_udp_zerocopy_unaddressed", "guard_udp_zerocopy_addressed"} {
		if c := h.check(t, name); !isErrno(c.Err, refusalErrno) {
			t.Errorf("%s = %+v, want R10's errno", name, c)
		}
	}
	if c := h.check(t, "guard_udp_zerocopy_received"); !isErrno(c.Err, unix.EAGAIN) {
		t.Errorf("guard_udp_zerocopy_received = %+v, want nothing to have arrived (EAGAIN)", c)
	}
	other := "0.0.0.0:" + strconv.Itoa(h.deniedPort)
	if evs := h.netEvents(t, other); len(evs) != 1 || evs[0].Verdict != record.VerdictAllow || netLine(t, evs[0]).BestEffort {
		t.Errorf("%s: %d events, want one allow line for a relayed connect", other, len(evs))
	}
}
