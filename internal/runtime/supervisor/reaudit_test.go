// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// unspecSockaddr is a 16-byte sockaddr whose family word is AF_UNSPEC and whose remaining bytes are a real
// sockaddr_in for ip:port. udp_sendmsg and raw_sendmsg read exactly this and send to that address — "if
// (usin->sin_family != AF_INET) { if (usin->sin_family != AF_UNSPEC) return -EAFNOSUPPORT; }" — which is
// why the family word alone does not make it a destination-free call.
func unspecSockaddr(ip string, port uint16) []byte {
	b := sockaddrIn4(ip, port)
	b[0], b[1] = unix.AF_UNSPEC, 0
	return b
}

// namedMsgHdr is a struct msghdr whose msg_name points at nameAddr and carries nothing else.
func namedMsgHdr(nameAddr uint64, namelen uint32) []byte {
	hdr := make([]byte, msgHdrSize)
	putU64(hdr[msgNameOff:], nameAddr)
	putU32(hdr[msgNameLenOff:], namelen)
	return hdr
}

// TestUnspecIsOnlyADisassociationInConnect keeps R4's carve-out inside the syscall it is written for.
//
// R4 excludes AF_UNSPEC from "unrecognized family" because in connect(2) it is the defined request to
// dissolve a socket's association, which the kernel routes straight to the protocol's disconnect: it
// "names no destination, sends nothing and can only narrow what the socket may reach". None of that is
// true of a send. udp_sendmsg and raw_sendmsg accept sin_family AF_UNSPEC as a spelling of AF_INET and
// send the datagram to the address that follows it, and rawv6_sendmsg reads a sockaddr_in6 there. Only
// TCP turns it away itself: tcp_sendmsg_fastopen answers an AF_UNSPEC address with EOPNOTSUPP before any
// connect (measured on 6.17), and without MSG_FASTOPEN a TCP send ignores the address.
//
// The first scoping of the carve-out recorded these as `refused / unmatched` and still answered a
// datagram CONTINUE, as R13b does for a destination it has matched — so the datagram left for
// 203.0.113.9:8080 under a line whose dst said only "unspec", a declared host behind the family word was
// recorded as refused while the kernel delivered to it, and the same bytes in family 17 were answered
// EACCES. Outside connect(2) AF_UNSPEC is now what R4 calls every family this tier does not parse:
// refused with R10's errno on every send form and every socket type, connected stream sockets included.
// That includes the row whose embedded address is declared: which address the bytes name depends on a
// socket domain this tier never reads, so it is not matched, and the agent loses nothing it could not
// spell as AF_INET (or as a NULL address on a connected socket). The socket is still read, only so the
// line names its protocol: before that, every one of these lines said proto=tcp, including the datagram
// and raw sends that are the only ones the kernel would have delivered.
//
// Every row runs twice: under a net: section, and under a contract with none. With no net: section this
// loop decides nothing and continues an unrecognised family (R7), and it continued AF_UNSPEC too: the
// datagram reached 203.0.113.9:8080 under a line that said verdict observed, dst "unspec" — bytes on the
// wire recorded as going nowhere, which drift and measure then never counted. It is refused there too.
func TestUnspecIsOnlyADisassociationInConnect(t *testing.T) {
	for _, withNet := range []bool{true, false} {
		t.Run(map[bool]string{true: "net section", false: "no net section"}[withNet], func(t *testing.T) {
			unspecIsOnlyADisassociationInConnect(t, withNet)
		})
	}
}

func unspecIsOnlyADisassociationInConnect(t *testing.T, withNet bool) {
	const saAddr, bufAddr, hdrAddr, arrayAddr = 0x40000, 0x50000, 0x60000, 0x90000
	sendto := func(flags uint64) func(*Loop) {
		return func(l *Loop) { l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, 4, flags, saAddr, 16)) }
	}
	sendmsg := func(l *Loop) { l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0)) }
	sendmmsg := func(l *Loop) { l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0)) }
	undeclared := unspecSockaddr("203.0.113.9", 8080)
	declared := unspecSockaddr("10.0.0.5", 8080) // the host:port the policy below allows
	tests := []struct {
		name      string
		sockType  int
		sa        []byte
		drive     func(l *Loop)
		connected bool
		proto     string
	}{
		{"sendto on a datagram socket", unix.SOCK_DGRAM, undeclared, sendto(0), false, protoUDP},
		{"sendto on a datagram socket, declared address behind the family", unix.SOCK_DGRAM, declared, sendto(0), false, protoUDP},
		{"sendto on a raw socket", unix.SOCK_RAW, undeclared, sendto(0), false, protoRaw},
		{"sendto with MSG_FASTOPEN on an unconnected stream socket", unix.SOCK_STREAM, declared, sendto(unix.MSG_FASTOPEN), false, protoTCP},
		// A deliberate cost of refusing before anything else: the kernel ignores this address on a
		// connected TCP socket and would have sent to the peer.
		{"sendto on a connected stream socket", unix.SOCK_STREAM, undeclared, sendto(0), true, protoTCP},
		{"sendmsg on a datagram socket", unix.SOCK_DGRAM, undeclared, sendmsg, false, protoUDP},
		{"sendmsg on a datagram socket, declared address behind the family", unix.SOCK_DGRAM, declared, sendmsg, false, protoUDP},
		{"sendmsg on a raw socket", unix.SOCK_RAW, undeclared, sendmsg, false, protoRaw},
		{"sendmmsg on a datagram socket", unix.SOCK_DGRAM, undeclared, sendmmsg, false, protoUDP},
		{"sendmmsg on a datagram socket, declared address behind the family", unix.SOCK_DGRAM, declared, sendmmsg, false, protoUDP},
		// The batch twin of the connected sendto row: the same cost, so vlen=1 answers what sendmsg does.
		{"sendmmsg on a connected stream socket", unix.SOCK_STREAM, undeclared, sendmmsg, true, protoTCP},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			f.connected = tc.connected
			f.put(saAddr, tc.sa)
			f.put(bufAddr, []byte("leak"))
			f.put(hdrAddr, namedMsgHdr(saAddr, 16))
			f.put(arrayAddr, mmsgBatch(saAddr, 16))
			pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
			if !withNet {
				pol = contractPolicy(&agent.Contract{}, nil, nil)
			}
			l, sink := newTestLoop(t, f, pol)

			tc.drive(l)

			got, ok := f.lastResp()
			if !ok || f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one", f.respCount())
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want R10's errno: outside connect(2) AF_UNSPEC is an address this tier cannot decide (R4, E4)", got)
			}
			if got.Error != -int32(refusalErrno) || got.Val != -1 {
				t.Errorf("response = {error=%d val=%d}, want R10's errno", got.Error, got.Val)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed {
				t.Errorf("event = {verdict=%s reason=%s}, want refused/net-not-allowed", ev.Verdict, ev.Reason)
			}
			if ev.Rule != ruleUnmatched {
				t.Errorf("rule = %q, want %q: the disassociation carve-out is connect(2)'s alone", ev.Rule, ruleUnmatched)
			}
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if p.BestEffort {
				t.Error("best_effort marks a verdict this tier recorded without enforcing; this refusal was enforced")
			}
			if p.Dst != "unspec" {
				t.Errorf("dst = %q, want the family the agent passed", p.Dst)
			}
			if p.Proto != tc.proto {
				t.Errorf("proto = %q, want %q: the refusal names the socket it was made on", p.Proto, tc.proto)
			}
			if len(f.sends) != 0 || len(f.connects) != 0 {
				t.Errorf("relayed %d sends and %d connects for an address nothing decided", len(f.sends), len(f.connects))
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open", f.fdBalance())
			}
		})
	}
}

// TestSendMMsgUndecidableAddressRefusesTheBatch is the batch form of the refusal above.
//
// sendto and sendmsg refuse an address this tier cannot parse whatever the socket is (R4, E4), but
// handleSendMMsg answered a datagram batch CONTINUE whatever it held, as R13b does for destinations it has
// matched. The identical msghdr passed through sendmmsg with vlen=1 therefore left the kernel after its
// sendmsg twin was refused — the evasion R12 already closes for the stream shape — and an AF_UNSPEC
// message in a batch went to the sockaddr_in behind its family word. A batch that carries one such
// message is refused whole; a declared destination beside it is recorded under batch-send, because the
// batch, not the host, is what refused it. TestSendMMsgReadsTheBatchAsFarAsTheKernelSends carries the
// same refusal past the 64th message.
func TestSendMMsgUndecidableAddressRefusesTheBatch(t *testing.T) {
	const arrayAddr, hdrAddr, sa0, sa1 = 0x90000, 0x60000, 0x40000, 0x41000
	vsock := make([]byte, 16) // struct sockaddr_vm: a family this tier does not parse
	vsock[0] = unix.AF_VSOCK
	pol := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	}
	refusedOnce := func(t *testing.T, f *fakeKernel) {
		t.Helper()
		got, ok := f.lastResp()
		if !ok || f.respCount() != 1 {
			t.Fatalf("responses = %d, want exactly one", f.respCount())
		}
		if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
			t.Fatalf("response = %+v, want R10's errno for a batch holding an address nothing decided", got)
		}
		if len(f.sends) != 0 || f.fdBalance() != 0 {
			t.Errorf("sends = %d, open descriptors = %d, want none", len(f.sends), f.fdBalance())
		}
	}

	t.Run("AF_UNSPEC beside a declared destination", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_DGRAM
		arr := make([]byte, 2*mmsgHdrSize)
		putU64(arr[msgNameOff:], sa0)
		putU32(arr[msgNameLenOff:], 16)
		putU64(arr[mmsgHdrSize+msgNameOff:], sa1)
		putU32(arr[mmsgHdrSize+msgNameLenOff:], 16)
		f.put(arrayAddr, arr)
		f.put(sa0, sockaddrIn4("10.0.0.5", 8080))
		f.put(sa1, unspecSockaddr("203.0.113.9", 8080))
		l, sink := newTestLoop(t, f, pol())

		l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 2, 0))

		refusedOnce(t, f)
		evs := sink.all()
		if len(evs) != 2 {
			t.Fatalf("events = %d, want one per addressed message (R13b)", len(evs))
		}
		for i, want := range []struct{ rule, dst string }{{ruleBatchSend, "10.0.0.5:8080"}, {ruleUnmatched, "unspec"}} {
			var p netPayload
			if err := evs[i].DecodePayload(&p); err != nil {
				t.Fatalf("payload %d: %v", i, err)
			}
			if evs[i].Verdict != record.VerdictRefused || evs[i].Rule != want.rule || p.Dst != want.dst {
				t.Errorf("event %d = {%s %s %s}, want {refused %s %s}", i, evs[i].Verdict, evs[i].Rule, p.Dst, want.rule, want.dst)
			}
			if p.BestEffort {
				t.Errorf("event %d carries best_effort for a refusal that was enforced", i)
			}
		}
	})

	// The same msghdr through both entry points must get the same answer, and the same line: sendmsg used
	// to refuse before reading the socket and so recorded proto=tcp where sendmmsg recorded udp.
	for _, form := range []struct {
		name  string
		drive func(l *Loop)
	}{
		{"sendmsg", func(l *Loop) { l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, 0)) }},
		{"sendmmsg with vlen=1", func(l *Loop) { l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0)) }},
	} {
		t.Run("an unrecognised family through "+form.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			f.put(sa0, vsock)
			f.put(hdrAddr, namedMsgHdr(sa0, 16))
			f.put(arrayAddr, mmsgBatch(sa0, 16))
			l, sink := newTestLoop(t, f, pol())

			form.drive(l)

			refusedOnce(t, f)
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if ev.Rule != ruleUnmatched || p.Dst != "family(40)" || p.Proto != protoUDP {
				t.Errorf("event = {rule=%s dst=%s proto=%s}, want {%s family(40) udp}", ev.Rule, p.Dst, p.Proto, ruleUnmatched)
			}
		})
	}
}

// TestConnectUnspecIsStillTheCarveOut is the other half: scoping it to connect(2) must not take it away
// from connect(2), where one UDP socket reused across peers depends on it.
func TestConnectUnspecIsStillTheCarveOut(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	f.put(addr, make([]byte, 16))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))

	ev := sink.one(t)
	if ev.Verdict != record.VerdictObserved || ev.Rule != ruleUnspec {
		t.Errorf("event = {verdict=%s rule=%s}, want observed/%s", ev.Verdict, ev.Rule, ruleUnspec)
	}
	if len(f.connects) != 1 {
		t.Errorf("connects = %d, want the disassociation relayed on the duplicate (I3)", len(f.connects))
	}
}

// TestRelayWhoseAnswerNeverLandsIsMarkedOrphaned is E35 on the path it actually happens on.
//
// The ID_VALID watch only ever sees a relay that outlives relayGrace. A connect to a local or already
// established endpoint, and a Fast-Open send that completes, return in microseconds — so the commonest
// E35 case never reaches the watch at all: the relay returns relayDone, respond() takes ENOENT from
// NOTIF_SEND, isGone() swallows it as an ordinary target death (E2), and the ledger gets an `allow` line
// indistinguishable from one the agent received. The kernel then restarts the abandoned syscall
// (seccomp_unotify(2), "Interaction with SA_RESTART signal handlers") and a second line follows it for
// one call the agent made once, which is what `drift` and `measure` count. The condition is the same one
// the watch reports — the notification was withdrawn after this loop had already performed the syscall —
// so it carries the same marker and the same counter.
func TestRelayWhoseAnswerNeverLandsIsMarkedOrphaned(t *testing.T) {
	const saAddr, bufAddr = 0x40000, 0x50000
	for _, tc := range []struct {
		name         string
		n            *notif
		wantConnects int
		wantSends    int
	}{
		{name: "connect", n: notifFor(connectNR(), 4242, 5, saAddr, 16), wantConnects: 1},
		{
			name:      "Fast-Open sendto on an unconnected stream socket",
			n:         notifFor(sendToNR(), 4242, 5, bufAddr, 4, unix.MSG_FASTOPEN, saAddr, 16),
			wantSends: 1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.put(saAddr, sockaddrIn4("10.0.0.5", 8080))
			f.put(bufAddr, []byte("ping"))
			// NOTIF_SEND returns ENOENT while ID_VALID still answers live: the id was withdrawn inside the
			// window between the last bracket and the answer, which is the window the relayed syscall sits in.
			f.sendErrno = unix.ENOENT
			pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
			l, sink := newTestLoop(t, f, pol)

			l.handle(tc.n)

			if len(f.connects) != tc.wantConnects || len(f.sends) != tc.wantSends {
				t.Fatalf("connects/sends = %d/%d, want %d/%d: the syscall this loop performed before the answer was lost",
					len(f.connects), len(f.sends), tc.wantConnects, tc.wantSends)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if !p.ResultUnknown {
				t.Error("result_unknown is unset: the line reads as a syscall whose result the agent received, and the kernel's restart will add a second one (E35)")
			}
			if got := l.metrics.orphaned.Load(); got != 1 {
				t.Errorf("orphaned = %d, want 1", got)
			}
		})
	}
}

// TestRelayDoneThatWasAnsweredCarriesNoMarker guards the ordinary path against the marker.
func TestRelayDoneThatWasAnsweredCarriesNoMarker(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	f.put(addr, sockaddrIn4("10.0.0.5", 8080))
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	l, sink := newTestLoop(t, f, pol)

	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))

	var p netPayload
	if err := sink.one(t).DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.ResultUnknown {
		t.Error("an answered relay was marked result_unknown")
	}
	if got := l.metrics.orphaned.Load(); got != 0 {
		t.Errorf("orphaned = %d, want 0", got)
	}
}

// panickingKernel panics inside the relayed connect, standing in for a bug in the syscall seam.
type panickingKernel struct{ *fakeKernel }

func (p *panickingKernel) ConnectRaw(int, []byte) error { panic("relay boom") }

// TestRelayPanicIsContainedPerNotification is R25 for the one call that stopped running on the worker's
// stack.
//
// R25 puts every dispatch call inside a per-notification recover() in the worker loop, and I12 and E34
// say a panicking handler never crashes another in-flight notification's worker. The relay moved the
// connect and the Fast-Open send onto a bare goroutine, where a panic is nobody's to recover: it takes
// the whole process with it — every other in-flight notification, the ledger writer, the run — and the
// duplicate that goroutine owned is never closed (E28). The panic travels back to the worker instead, so
// R25's wrapper answers it fail-closed and records the gap exactly as it did when the call was inline.
func TestRelayPanicIsContainedPerNotification(t *testing.T) {
	const addr = 0x40000
	f := newFake()
	f.put(addr, sockaddrIn4("10.0.0.5", 8080))
	pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
	sink := &testSink{}
	l, err := New(testListener(), pol, sink, Options{kernel: &panickingKernel{fakeKernel: f}, Workers: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	l.handle(notifFor(connectNR(), 4242, 5, addr, 16))

	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response: a recovered panic still answers a decision kind fail-closed (R25b)")
	}
	if got.Error != -int32(refusalErrno) || got.Val != -1 {
		t.Errorf("response = {error=%d val=%d}, want the fail-closed refusal R25 gives a decision kind", got.Error, got.Val)
	}
	var gaps int
	for _, ev := range sink.all() {
		if ev.Kind == record.KindGap {
			gaps++
		}
	}
	if gaps != 1 {
		t.Errorf("gap events = %d, want the one R25 records for a recovered panic", gaps)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open: the relay owns the duplicate and must release it on every path (E28)", f.fdBalance())
	}
}

// TestFastOpenOnAConnectedStreamIsDecided closes a check-then-continue gap in R13a.
//
// A send on a stream socket that has a peer was answered CONTINUE whatever address it carried, because
// the kernel ignores that address — while the socket keeps its peer. The peer is only what this loop saw
// through getpeername; CONTINUE hands the syscall back, and a sibling thread's connect(fd, {AF_UNSPEC}),
// which R4 allows, can dissolve the association before the kernel runs it. With MSG_FASTOPEN
// tcp_sendmsg_fastopen then connects the now peerless socket to the send's own address, a host nothing
// decided (measured on 6.17: connect, connect AF_UNSPEC, sendto(MSG_FASTOPEN) to a second listener
// delivers there). With MSG_FASTOPEN the send is now decided as R12 even on a connected socket. Nothing
// legitimate is lost: on a socket that keeps its peer the kernel answers such a send with EISCONN, which
// the relay passes through for a declared destination, and a refusal replaces it with R10's errno.
func TestFastOpenOnAConnectedStreamIsDecided(t *testing.T) {
	const saAddr, bufAddr, hdrAddr, arrayAddr = 0x40000, 0x50000, 0x60000, 0x90000
	sendto := func(flags uint64) func(*Loop) {
		return func(l *Loop) { l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, 4, flags, saAddr, 16)) }
	}
	sendmsg := func(flags uint64) func(*Loop) {
		return func(l *Loop) { l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)) }
	}
	sendmmsg := func(flags uint64) func(*Loop) {
		return func(l *Loop) { l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, flags)) }
	}
	for _, tc := range []struct {
		name     string
		ip       string
		drive    func(*Loop)
		wantCont bool
		wantErr  int32 // the response's error when not continued
		wantRule string
		relayed  int
	}{
		{
			name: "sendto, undeclared", ip: "203.0.113.9", drive: sendto(unix.MSG_FASTOPEN),
			wantErr: -int32(refusalErrno), wantRule: ruleUnmatched,
		},
		{
			name: "sendto, declared: the relay carries the kernel's own EISCONN", ip: "10.0.0.5", drive: sendto(unix.MSG_FASTOPEN),
			wantErr: -int32(unix.EISCONN), wantRule: "net[10.0.0.5:8080]", relayed: 1,
		},
		{
			name: "sendmsg, undeclared", ip: "203.0.113.9", drive: sendmsg(unix.MSG_FASTOPEN),
			wantErr: -int32(refusalErrno), wantRule: ruleUnmatched,
		},
		{
			name: "sendmmsg, declared: the batch form is never relayed (R13c)", ip: "10.0.0.5", drive: sendmmsg(unix.MSG_FASTOPEN),
			wantErr: -int32(refusalErrno), wantRule: ruleBatchSend,
		},
		// Without MSG_FASTOPEN the kernel cannot connect anywhere from inside the send, so R13a stands.
		{name: "sendto without MSG_FASTOPEN", ip: "203.0.113.9", drive: sendto(0), wantCont: true},
		{name: "sendmsg without MSG_FASTOPEN", ip: "203.0.113.9", drive: sendmsg(0), wantCont: true},
		{name: "sendmmsg without MSG_FASTOPEN", ip: "203.0.113.9", drive: sendmmsg(0), wantCont: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.connected = true
			f.sendErr = unix.EISCONN
			f.put(saAddr, sockaddrIn4(tc.ip, 8080))
			f.put(bufAddr, []byte("evil"))
			f.put(hdrAddr, namedMsgHdr(saAddr, 16))
			f.put(arrayAddr, mmsgBatch(saAddr, 16))
			pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
			l, sink := newTestLoop(t, f, pol)

			tc.drive(l)

			got, ok := f.lastResp()
			if !ok || f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one", f.respCount())
			}
			cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0
			if cont != tc.wantCont {
				t.Fatalf("response = %+v, want CONTINUE=%v: a peer seen by this loop is not one the kernel is bound to see", got, tc.wantCont)
			}
			if len(f.sends) != tc.relayed {
				t.Errorf("relayed sends = %d, want %d", len(f.sends), tc.relayed)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open", f.fdBalance())
			}
			if tc.wantCont {
				if evs := sink.all(); len(evs) != 0 {
					t.Errorf("events = %d, want none for an address the kernel ignores (R13a)", len(evs))
				}
				return
			}
			if got.Error != tc.wantErr || got.Val != -1 {
				t.Errorf("response = {error=%d val=%d}, want {error=%d val=-1}", got.Error, got.Val, tc.wantErr)
			}
			if ev := sink.one(t); ev.Rule != tc.wantRule {
				t.Errorf("rule = %q, want %q", ev.Rule, tc.wantRule)
			}
		})
	}
}
