// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/attention-span-ai/tego/internal/platform/sys"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// sockaddrNL is a struct sockaddr_nl.
func sockaddrNL(pid, groups uint32) []byte {
	b := make([]byte, sizeofSockaddrNL)
	binary.NativeEndian.PutUint16(b, unix.AF_NETLINK)
	binary.NativeEndian.PutUint32(b[4:], pid)
	binary.NativeEndian.PutUint32(b[8:], groups)
	return b
}

// rtRequest is one netlink message of size bytes in all, as a program sends it: NLM_F_REQUEST and a dump.
func rtRequest(typ uint16, size int) []byte {
	b := make([]byte, size)
	binary.NativeEndian.PutUint32(b, uint32(size))
	binary.NativeEndian.PutUint16(b[4:], typ)
	binary.NativeEndian.PutUint16(b[6:], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	return b
}

// TestRouteReadOnly is the walk's table: every GET of rtnetlink's and nothing else, however the datagram is laid out.
func TestRouteReadOnly(t *testing.T) {
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	getLink, newRoute := rtRequest(unix.RTM_GETLINK, 20), rtRequest(unix.RTM_NEWROUTE, 28)
	hugeLen := rtRequest(unix.RTM_GETLINK, 20)
	binary.NativeEndian.PutUint32(hugeLen, 1<<31)
	shortLen := rtRequest(unix.RTM_GETLINK, 20)
	binary.NativeEndian.PutUint32(shortLen, 15)
	for _, tc := range []struct {
		name string
		p    []byte
		want bool
	}{
		{"glibc's dump: a header, a family and padding", rtRequest(unix.RTM_GETADDR, 20), true},
		{"Go's dump: a header and a family, no padding", rtRequest(unix.RTM_GETLINK, 17), true},
		{"a route lookup", rtRequest(unix.RTM_GETROUTE, 60), true},
		{"a neighbour dump", rtRequest(unix.RTM_GETNEIGH, 28), true},
		{"the last GET the table names", rtRequest(unix.RTM_BASE+((unix.RTM_MAX-unix.RTM_BASE)&^3)+2, 20), true},
		{"two GETs in one datagram", join(rtRequest(unix.RTM_GETLINK, 20), rtRequest(unix.RTM_GETADDR, 20)), true},
		{"an unaligned GET before another", join(rtRequest(unix.RTM_GETLINK, 17), make([]byte, 3), rtRequest(unix.RTM_GETADDR, 17)), true},

		{"nothing", nil, false},
		{"less than a header", getLink[:15], false},
		{"a new link", rtRequest(unix.RTM_NEWLINK, 32), false},
		{"a deleted link", rtRequest(unix.RTM_DELLINK, 32), false},
		{"a link set", rtRequest(unix.RTM_SETLINK, 32), false},
		{"a new address", rtRequest(unix.RTM_NEWADDR, 40), false},
		{"a new route", newRoute, false},
		{"a deleted route", rtRequest(unix.RTM_DELROUTE, 28), false},
		{"a new routing rule", rtRequest(unix.RTM_NEWRULE, 28), false},
		{"a new qdisc", rtRequest(unix.RTM_NEWQDISC, 36), false},
		{"a new neighbour", rtRequest(unix.RTM_NEWNEIGH, 28), false},
		{"a new network namespace id", rtRequest(unix.RTM_NEWNSID, 28), false},
		{"a change behind a GET", join(getLink, newRoute), false},
		{"a change behind an unaligned GET", join(rtRequest(unix.RTM_GETLINK, 17), make([]byte, 3), newRoute), false},
		{"a change behind two GETs", join(getLink, getLink, newRoute), false},
		{"a GET behind a change", join(newRoute, getLink), false},
		{"a control message", rtRequest(unix.NLMSG_NOOP, 16), false},
		{"an error message", rtRequest(unix.NLMSG_ERROR, 36), false},
		{"below rtnetlink's types", rtRequest(unix.RTM_BASE-1, 20), false},
		{"past RTM_MAX, though its low bits say GET", rtRequest(unix.RTM_BASE+((unix.RTM_MAX-unix.RTM_BASE)&^3)+6, 20), false},
		{"a length past the datagram", hugeLen, false},
		{"a length short of the header", shortLen, false},
		{"bytes behind a GET too short to be a header", join(getLink, []byte{1, 2, 3, 4}), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := routeReadOnly(tc.p); got != tc.want {
				t.Errorf("routeReadOnly = %v, want %v", got, tc.want)
			}
		})
	}
}

// FuzzRouteReadOnly holds the walk to netlink_rcv_skb, written out here on its own: of a datagram it calls read-only,
// everything the kernel would hand rtnetlink_rcv_msg is a GET.
func FuzzRouteReadOnly(f *testing.F) {
	f.Add(rtRequest(unix.RTM_GETLINK, 20))
	f.Add(rtRequest(unix.RTM_NEWROUTE, 28))
	f.Add(append(rtRequest(unix.RTM_GETLINK, 17), rtRequest(unix.RTM_NEWROUTE, 28)...))
	f.Fuzz(func(t *testing.T, p []byte) {
		if !routeReadOnly(p) {
			return
		}
		for len(p) >= unix.NLMSG_HDRLEN {
			size := binary.NativeEndian.Uint32(p)
			typ := binary.NativeEndian.Uint16(p[4:])
			if size < unix.NLMSG_HDRLEN || uint64(len(p)) < uint64(size) {
				return // netlink_rcv_skb stops here
			}
			if typ < unix.RTM_BASE || (typ-unix.RTM_BASE)%4 != 2 {
				t.Fatalf("read-only, but the kernel would take a message of type %d", typ)
			}
			msg := (uint64(size) + 3) &^ 3
			if msg > uint64(len(p)) {
				msg = uint64(len(p))
			}
			p = p[msg:]
		}
	})
}

// TestRouteQueriesUnderANetSection is ADR 0128 at the supervisor. Under a net: section an addressed send to the kernel
// on a NETLINK_ROUTE socket that holds only GET requests is relayed on the duplicate as the task, from the copies read,
// and recorded allow, rule route-query: refused, Node's os.networkInterfaces, Python's if_nameindex and glibc's
// AI_ADDRCONFIG failed under every contract with a net: section. A request that changes the network is refused and
// never sent, whoever asks, a task holding CAP_NET_ADMIN included; every other netlink destination, protocol or shape
// keeps its refusal.
func TestRouteQueriesUnderANetSection(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	const capNetAdmin = uint64(1) << unix.CAP_NET_ADMIN
	getLink, newRoute := rtRequest(unix.RTM_GETLINK, 20), rtRequest(unix.RTM_NEWROUTE, 28)
	cases := []struct {
		name     string
		domain   int
		proto    int
		protoErr error
		sa       []byte
		payload  []byte
		control  bool
		capEff   uint64
		sendmsg  bool
		rule     string // the refusal's; empty: relayed
	}{
		{name: "a link dump by sendto", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: getLink},
		{name: "an address dump by sendmsg", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: rtRequest(unix.RTM_GETADDR, 20), sendmsg: true},
		{name: "Go's unpadded dump", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: rtRequest(unix.RTM_GETLINK, 17)},
		{name: "two GETs in one datagram", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: append(bytes.Clone(getLink), getLink...)},
		{name: "a dump from a task holding CAP_NET_ADMIN", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: getLink, capEff: capNetAdmin},

		{name: "a new route", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: newRoute, rule: ruleRouteChange},
		{name: "a new route by sendmsg", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: newRoute, sendmsg: true, rule: ruleRouteChange},
		{name: "a link set", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: rtRequest(unix.RTM_SETLINK, 32), rule: ruleRouteChange},
		{name: "a deleted address", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: rtRequest(unix.RTM_DELADDR, 40), rule: ruleRouteChange},
		{name: "a new route from a task holding CAP_NET_ADMIN", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: newRoute, capEff: capNetAdmin, rule: ruleRouteChange},
		{name: "a new route behind a GET", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: append(bytes.Clone(getLink), newRoute...), rule: ruleRouteChange},
		{name: "a query past what is copied", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: rtRequest(unix.RTM_GETLINK, sendBytes+1), rule: ruleDatagramSize},

		{name: "another process's port", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(4243, 0), payload: getLink, rule: ruleUnmatched},
		{name: "a multicast group", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 1), payload: getLink, rule: ruleUnmatched},
		{name: "a short netlink address", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0)[:8], payload: getLink, rule: ruleUnmatched},
		{name: "ancillary data", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), payload: getLink, control: true, sendmsg: true, rule: ruleUnmatched},
		{name: "audit, on a socket the run was handed", proto: unix.NETLINK_AUDIT, sa: sockaddrNL(0, 0), payload: getLink, rule: ruleUnmatched},
		{name: "generic netlink, on a socket the run was handed", proto: unix.NETLINK_GENERIC, sa: sockaddrNL(0, 0), payload: getLink, rule: ruleUnmatched},
		{name: "a protocol that cannot be read is no route socket", protoErr: errors.New("gone"), sa: sockaddrNL(0, 0), payload: getLink, rule: ruleUnmatched},
		{name: "a netlink address on an IP socket", domain: unix.AF_INET, sa: sockaddrNL(0, 0), payload: getLink, rule: ruleUnmatched},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.sockProto, f.sockProtoErr = unix.SOCK_RAW, unix.AF_NETLINK, tc.proto, tc.protoErr
			if tc.domain != 0 {
				f.sockType, f.sockDomain = unix.SOCK_DGRAM, tc.domain
			}
			f.taskCreds = sys.TaskCreds{EUID: 1000, EGID: 1000, FSUID: 1000, FSGID: 1000, CapEff: tc.capEff}
			f.put(addr, tc.sa)
			f.put(bufAddr, tc.payload)
			l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil, nil))
			if tc.sendmsg {
				const hdrAt, iovAt = 0x42000, 0x43000
				hdr := namedMsgHdr(addr, uint32(len(tc.sa)))
				putU64(hdr[msgIovOff:], iovAt)
				putU64(hdr[msgIovLenOff:], 1)
				if tc.control {
					putU64(hdr[msgControlLenOff:], 32) // SCM_CREDENTIALS
				}
				iov := make([]byte, iovecSize)
				putU64(iov, bufAddr)
				putU64(iov[8:], uint64(len(tc.payload)))
				f.put(iovAt, iov)
				f.put(hdrAt, hdr)
				l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAt, 0))
			} else {
				l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(tc.payload)), 0, addr, uint64(len(tc.sa))))
			}
			got, _ := f.lastResp()
			ev := sink.one(t)
			if tc.rule != "" {
				if len(f.sends) != 0 || got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule {
					t.Fatalf("sends = %d, response = %+v, event = %s/%s; want nothing sent, R10's errno, refused/%s",
						len(f.sends), got, ev.Verdict, ev.Rule, tc.rule)
				}
			} else {
				if len(f.sendsAs) != 1 || len(f.sends) != 1 || !bytes.Equal(f.sends[0].addr, tc.sa) ||
					!bytes.Equal(f.sends[0].payload, tc.payload) {
					t.Fatalf("sends = %+v (as the task: %v), want one relayed send of the copies", f.sends, f.sendsAs)
				}
				if !f.sendsAs[0].Equal(f.taskCreds) {
					t.Errorf("relayed with %+v, want the task's credentials %+v", f.sendsAs[0], f.taskCreds)
				}
				if got.Error != 0 || got.Val != int64(len(tc.payload)) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
					t.Errorf("response = %+v, want the relayed result, never a CONTINUE", got)
				}
				var p netPayload
				if ev.DecodePayload(&p) != nil || ev.Verdict != record.VerdictAllow || ev.Rule != ruleRouteQuery || p.BestEffort ||
					p.Dst != "family(16)" || p.Proto != protoRaw {
					t.Errorf("event = %s/%s %+v, want allow/%s, enforced, dst family(16), proto raw", ev.Verdict, ev.Rule, p, ruleRouteQuery)
				}
			}
			if n := f.fdBalance(); n != 0 {
				t.Errorf("%d descriptors left open, want the duplicate and the task view closed", n)
			}
		})
	}
}

// TestRouteConnectStaysRefused: a connect names a peer for every later send, and no program this package knows of makes
// one on a route socket, so ADR 0128 admits none: under a net: section it is refused unmatched and connects nothing.
func TestRouteConnectStaysRefused(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrNL(0, 0)
	f := newFake()
	f.sockType, f.sockDomain, f.sockProto = unix.SOCK_RAW, unix.AF_NETLINK, unix.NETLINK_ROUTE
	f.put(addr, sa)
	l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	got, _ := f.lastResp()
	if ev := sink.one(t); got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
		t.Fatalf("response = %+v, event = %s/%s; want R10's errno, refused/%s", got, ev.Verdict, ev.Rule, ruleUnmatched)
	}
}

// TestRouteChangeInTheUnixOnlyState: ADR 0070's relay runs as the task, and the kernel lets a task holding
// CAP_NET_ADMIN through, so a NEWROUTE it relayed changed the host's routes under a contract that names no network. A
// route query is what the state admits, so a change is refused route-change there too and never sent.
func TestRouteChangeInTheUnixOnlyState(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x9000
	sa, payload := sockaddrNL(0, 0), rtRequest(unix.RTM_NEWROUTE, 28)
	f := newFake()
	f.sockType, f.sockDomain, f.sockProto = unix.SOCK_RAW, unix.AF_NETLINK, unix.NETLINK_ROUTE
	f.taskCreds = sys.TaskCreds{CapEff: 1 << unix.CAP_NET_ADMIN}
	f.put(addr, sa)
	f.put(bufAddr, payload)
	l, sink := newTestLoop(t, f, contractPolicy(&agent.Contract{}, nil, nil))
	l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), 0, addr, uint64(len(sa))))
	got, _ := f.lastResp()
	if ev := sink.one(t); len(f.sends) != 0 || got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused ||
		ev.Rule != ruleRouteChange {
		t.Fatalf("sends = %d, response = %+v, event = %s/%s; want nothing sent, R10's errno, refused/%s", len(f.sends), got,
			ev.Verdict, ev.Rule, ruleRouteChange)
	}
}

// TestBindOfARouteSocketUnderAListenerPolicy: with a net.listen key every bind is notified, and a netlink address, which
// no listener rule can name, was refused args-unreadable, so glibc's getifaddrs and getaddrinfo failed before they sent
// anything. A bind of a NETLINK_ROUTE socket with no multicast group is made on the duplicate from the copy, never
// continued, and recorded allow; every other netlink bind keeps its refusal.
func TestBindOfARouteSocketUnderAListenerPolicy(t *testing.T) {
	const addr = 0x40000
	for _, tc := range []struct {
		name     string
		domain   int
		proto    int
		protoErr error
		sa       []byte
		addrlen  uint64
		bindErr  error
		wantBind bool
		wantErr  error
		refused  bool
	}{
		{name: "glibc's bind, port id 0", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0), wantBind: true},
		{name: "libnl's bind, a port id of its own", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(7777, 0), wantBind: true},
		{name: "the kernel's own refusal of the bind", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(7777, 0), bindErr: unix.EADDRINUSE,
			wantBind: true, wantErr: unix.EADDRINUSE},
		{name: "a short name is the kernel's EINVAL", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 0)[:8], wantErr: unix.EINVAL},
		{name: "a multicast group", proto: unix.NETLINK_ROUTE, sa: sockaddrNL(0, 1), refused: true},
		{name: "another protocol", proto: unix.NETLINK_GENERIC, sa: sockaddrNL(0, 0), refused: true},
		{name: "a protocol that cannot be read", protoErr: errors.New("gone"), sa: sockaddrNL(0, 0), refused: true},
		{name: "a netlink address on an IP socket", domain: unix.AF_INET, sa: sockaddrNL(0, 0), refused: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.sockProto, f.sockProtoErr = unix.SOCK_RAW, unix.AF_NETLINK, tc.proto, tc.protoErr
			if tc.domain != 0 {
				f.sockType, f.sockDomain = unix.SOCK_STREAM, tc.domain
			}
			f.put(addr, tc.sa)
			policy := testPolicy(nil, nil, nil)
			policy.Rules.Listen = []agent.ListenRule{}
			l, sink := newTestLoop(t, f, policy)
			binder := &bindFake{fakeKernel: f, err: tc.bindErr}
			l.k = binder
			handleBind(l, notifFor(connectNR(), 4242, 5, addr, uint64(len(tc.sa))))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("bind not answered")
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatal("continued: the kernel would read the descriptor and the address again")
			}
			ev := sink.one(t)
			if tc.refused {
				if len(binder.calls) != 0 || got.Error != -int32(refusalErrno) || ev.Verdict != record.VerdictRefused {
					t.Fatalf("binds = %d, response = %+v, event = %s/%s; want no bind, R10's errno, refused", len(binder.calls), got,
						ev.Verdict, ev.Rule)
				}
			} else {
				if tc.wantBind != (len(binder.calls) == 1) {
					t.Fatalf("binds = %d, want a bind: %v", len(binder.calls), tc.wantBind)
				}
				if tc.wantBind && !bytes.Equal(binder.calls[0], tc.sa) {
					t.Errorf("bound %x, want the copy read, %x", binder.calls[0], tc.sa)
				}
				var want int32
				if tc.wantErr != nil {
					var errno unix.Errno
					if !errors.As(tc.wantErr, &errno) {
						t.Fatalf("%v is no errno", tc.wantErr)
					}
					want = -int32(errno)
				}
				if got.Error != want || ev.Verdict != record.VerdictAllow || ev.Rule != ruleRouteQuery {
					t.Errorf("response = %+v, event = %s/%s; want errno %d, allow/%s", got, ev.Verdict, ev.Rule, want, ruleRouteQuery)
				}
			}
			if n := f.fdBalance(); n != 0 {
				t.Errorf("%d descriptors left open, want the duplicate closed", n)
			}
		})
	}
}
