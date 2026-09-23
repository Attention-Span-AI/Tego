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

// mmsgBatch lays out a one-message mmsghdr array whose msg_name points at nameAddr.
func mmsgBatch(nameAddr uint64, namelen uint32) []byte {
	arr := make([]byte, mmsgHdrSize)
	putU64(arr[msgNameOff:], nameAddr)
	putU32(arr[msgNameLenOff:], namelen)
	return arr
}

// fastOpenPolicy declares one host:port, the shape an agent's contract has when it is allowed to reach an
// API endpoint and nothing else.
func fastOpenPolicy() *Policy {
	return testPolicy([]agent.NetRule{
		netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34"),
	}, nil, []netip.AddrPort{})
}

// TestSendMMsgStreamIsDecidedNotContinued is R12 reached through sendmmsg instead of sendmsg.
//
// The handler used to answer CONTINUE for every sendmmsg whatever the socket type and whatever the
// verdict, recording the unmatched destination as `refused best_effort=true` while the kernel then ran the
// real syscall: on a SOCK_STREAM socket with MSG_FASTOPEN that is tcp_sendmsg_fastopen opening the
// connection and the payload leaving for an undeclared host. The comment justifying it named Landlock's
// per-port rule as the backstop, which cannot see the host at all (enforce-landlock R6) — and the same
// call made through sendmsg was refused with EACCES, so the rule was evadable by picking the other entry
// point for the identical operation. R12 and I2 apply to the batch form too.
func TestSendMMsgStreamIsDecidedNotContinued(t *testing.T) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	f := newFake()
	f.sockType = unix.SOCK_STREAM // an unconnected stream socket: the Fast-Open shape
	f.put(arrayAddr, mmsgBatch(saAddr, 16))
	f.put(saAddr, sockaddrIn4("203.0.113.9", 443)) // a host the contract never declared
	l, sink := newTestLoop(t, f, fastOpenPolicy())

	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0))

	got, ok := f.lastResp()
	if !ok {
		t.Fatal("no response at all for a decision kind")
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Fatalf("response = %+v: CONTINUE lets the kernel run the real sendmmsg, so the bytes reach an undeclared host (I2, R12)", got)
	}
	if got.Error != -int32(refusalErrno) || got.Val != -1 {
		t.Errorf("response = {error=%d val=%d}, want {error=%d val=-1}", got.Error, got.Val, -int32(refusalErrno))
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed {
		t.Errorf("event = {verdict=%s reason=%s}, want a refusal with net-not-allowed", ev.Verdict, ev.Reason)
	}
	if ev.Rule != ruleUnmatched {
		t.Errorf("rule = %q, want %q", ev.Rule, ruleUnmatched)
	}
	var p netPayload
	if err := ev.DecodePayload(&p); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if p.BestEffort {
		t.Error("best_effort marks a verdict this tier recorded but did not enforce; this one was enforced")
	}
	if p.Proto != protoTCP || p.Dst != "203.0.113.9:443" {
		t.Errorf("payload = {%s %s}, want tcp 203.0.113.9:443", p.Proto, p.Dst)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open", f.fdBalance())
	}
}

// TestSendMMsgStreamRefusesEvenADeclaredDestination pins the reason the batch form is refused outright:
// sendmmsg reports each message's byte count by writing msg_len back into the caller's own array, and
// this loop reads the target's memory but never writes it, so R12's relay cannot be reproduced and any
// answer it gave would be the fabricated result I3 forbids. The destination's own rule is still recorded,
// under the marker that names why the send did not happen.
func TestSendMMsgStreamRefusesEvenADeclaredDestination(t *testing.T) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.put(arrayAddr, mmsgBatch(saAddr, 16))
	f.put(saAddr, sockaddrIn4("93.184.216.34", 443)) // exactly what the contract declares
	l, sink := newTestLoop(t, f, fastOpenPolicy())

	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0))

	got, _ := f.lastResp()
	if got.Error != -int32(refusalErrno) {
		t.Fatalf("response = %+v, want refusalErrno", got)
	}
	if len(f.sends) != 0 {
		t.Errorf("relayed %d sends; the batch form is never relayed", len(f.sends))
	}
	ev := sink.one(t)
	if ev.Rule != ruleBatchSend || ev.Verdict != record.VerdictRefused {
		t.Errorf("event = {rule=%s verdict=%s}, want {%s refused}", ev.Rule, ev.Verdict, ruleBatchSend)
	}
}

// TestSendMMsgConnectedStreamContinues: once the socket has a peer the kernel ignores every msg_name in
// the batch, so there is no new decision here and recording the ignored addresses would invent refusals
// for destinations nothing was sent to (R13a).
func TestSendMMsgConnectedStreamContinues(t *testing.T) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	f := newFake()
	f.sockType = unix.SOCK_STREAM
	f.connected = true
	f.put(arrayAddr, mmsgBatch(saAddr, 16))
	f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
	l, sink := newTestLoop(t, f, fastOpenPolicy())

	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, 0))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Fatalf("response = %+v, want CONTINUE for a send the connect already decided", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("events = %d, want none for addresses the kernel ignores", len(evs))
	}
}

// TestSendMMsgFailsClosedWithoutTheSocket is §7's "pidfd_getfd fails" row applied to the batch form. The
// socket type is what says whether this batch is R12's decision or R13b's best-effort record; without it
// there is nothing to decide against, so it takes the same answer a failed duplicate takes on a connect.
// Before the fix the type was simply assumed to be udp and the syscall continued. A batch whose only
// address lies past the 64th message needs the socket just the same, and its refusal names that address.
func TestSendMMsgFailsClosedWithoutTheSocket(t *testing.T) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	for _, layout := range []struct {
		name string
		vlen int
		arr  []byte
	}{
		{"one addressed message", 1, mmsgBatch(saAddr, 16)},
		{"the only address past the 64th message", mmsgMessages + 1, mmsgArray(mmsgMessages+1, func(i int) uint64 {
			if i == mmsgMessages {
				return saAddr
			}
			return 0
		})},
	} {
		for _, tc := range []struct {
			name    string
			breakIt func(*fakeKernel)
		}{
			{"pidfd_getfd fails", func(f *fakeKernel) { f.dupErr = unix.EBADF }},
			{"SO_TYPE fails", func(f *fakeKernel) { f.sockTypErr = unix.ENOTSOCK }},
		} {
			t.Run(layout.name+", "+tc.name, func(t *testing.T) {
				f := newFake()
				tc.breakIt(f)
				f.put(arrayAddr, layout.arr)
				f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
				l, sink := newTestLoop(t, f, fastOpenPolicy())

				l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(layout.vlen), 0))

				got, _ := f.lastResp()
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
					t.Fatalf("response = %+v, want a refusal when the socket could not be read", got)
				}
				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if ev.Rule != ruleFDRaced || p.Dst != "203.0.113.9:443" {
					t.Errorf("event = {rule=%s dst=%s}, want {%s 203.0.113.9:443}", ev.Rule, p.Dst, ruleFDRaced)
				}
				if f.fdBalance() != 0 {
					t.Errorf("%d descriptors left open", f.fdBalance())
				}
			})
		}
	}
}

// TestSendMMsgUnreadableHeaderFailsClosed is R5 for the batch form: the kernel is about to read the same
// mmsghdr, so a header this loop cannot read is not "no destination" but not knowing whether there was
// one — on a syscall that may be the Fast-Open shape. An unreadable sendmsg header already failed closed;
// sendmmsg's dropped out of the loop with an empty destination list and answered CONTINUE.
func TestSendMMsgUnreadableHeaderFailsClosed(t *testing.T) {
	f := newFake() // nothing mapped at the array address: process_vm_readv returns EFAULT
	l, sink := newTestLoop(t, f, fastOpenPolicy())

	l.handle(notifFor(sendMMsgNR(), 4242, 5, 0x90000, 1, 0))

	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
		t.Fatalf("response = %+v, want a refusal for an unreadable header (R5)", got)
	}
	if ev := sink.one(t); ev.Rule != ruleArgsUnreadable {
		t.Errorf("rule = %q, want %q", ev.Rule, ruleArgsUnreadable)
	}
}

// mmsgArray lays out a vlen-message mmsghdr array; name says where message i's msg_name points, 0 for a
// message that carries none.
func mmsgArray(vlen int, name func(i int) uint64) []byte {
	arr := make([]byte, vlen*mmsgHdrSize)
	for i := 0; i < vlen; i++ {
		if a := name(i); a != 0 {
			putU64(arr[i*mmsgHdrSize+msgNameOff:], a)
			putU32(arr[i*mmsgHdrSize+msgNameLenOff:], 16)
		}
	}
	return arr
}

// TestSendMMsgReadsTheBatchAsFarAsTheKernelSends is R13b at the length the kernel honours.
//
// The refusal of a datagram batch holding an address this tier cannot decide ran only over the messages
// the handler read, and it read mmsgMessages (64) of them. __sys_sendmmsg clamps vlen to UIO_MAXIOV (1024)
// instead and sends every message up to that, so vlen=65 with an AF_UNSPEC message at index 64 was
// answered CONTINUE with 64 events and none for the 65th, which udp_sendmsg delivered to the sockaddr_in
// behind its family word — the vlen=1 route around sendmsg's refusal, moved to vlen=65. The same held
// with the first 64 messages carrying no address at all, where the handler never took the socket.
//
// The next fix read the tail to the kernel's clamp but only checked each address there for
// decidability, never against the policy, and recorded none it could decide. A datagram past the 64th
// addressed to a host the contract never declared therefore left with no line at all: 64 NULL messages
// and one addressed one on a connected UDP socket was CONTINUE with zero events, and 64 declared messages
// followed by 960 to an undeclared host was 64 allow lines while the undeclared host received 960
// datagrams. At this tier UDP is record-only, so the ledger is the only control. The first destination
// past the 64th that the policy does not admit now has its own line, which keeps the ledger at 65 lines.
func TestSendMMsgReadsTheBatchAsFarAsTheKernelSends(t *testing.T) {
	const arrayAddr, declaredAddr, oddAddr = 0x100000, 0x40000, 0x41000
	vsock := make([]byte, 16) // struct sockaddr_vm: a family this tier does not parse
	vsock[0] = unix.AF_VSOCK
	unspec := unspecSockaddr("203.0.113.9", 8080)
	undeclared := sockaddrIn4("203.0.113.9", 4444) // a host the contract never declared
	// Where message i's msg_name points: the declared destination, the row's odd address, or nowhere.
	declaredHead := func(i int) uint64 {
		if i < mmsgMessages {
			return declaredAddr
		}
		return 0
	}
	oddAt := func(at int, rest func(int) uint64) func(int) uint64 {
		return func(i int) uint64 {
			if i == at {
				return oddAddr
			}
			return rest(i)
		}
	}
	none := func(int) uint64 { return 0 }
	type want struct {
		refused   bool
		batchSend int    // lines for the declared destination, refused by the batch
		declared  int    // lines for the declared destination, recorded best-effort
		odd       string // dst of the one refused/unmatched line, "" for none
		dup       bool   // whether the socket was taken at all
	}
	for _, tc := range []struct {
		name      string
		vlen      int
		connected bool
		odd       []byte // what oddAddr holds
		msg       func(i int) uint64
		want      want
	}{
		{
			name: "AF_UNSPEC at index 64 behind 64 declared messages", vlen: mmsgMessages + 1,
			odd: unspec, msg: oddAt(mmsgMessages, declaredHead),
			want: want{refused: true, batchSend: mmsgMessages, odd: "unspec", dup: true},
		},
		{
			// The refusal is decided from every message read, not from where the read stopped: an
			// AF_UNSPEC at 64 followed by a declared message at 65 is refused as surely as one that ends
			// the batch.
			name: "AF_UNSPEC at index 64 with a declared message after it", vlen: mmsgMessages + 2,
			odd: unspec, msg: func(i int) uint64 {
				if i == mmsgMessages {
					return oddAddr
				}
				return declaredAddr
			},
			want: want{refused: true, batchSend: mmsgMessages, odd: "unspec", dup: true},
		},
		{
			// R13b's Lines: the message that refused the batch is the one the tail line names, even when
			// a declared message precedes it past the 64th.
			name: "a declared message at 64 and AF_UNSPEC at 65", vlen: mmsgMessages + 2,
			odd: unspec, msg: func(i int) uint64 {
				if i == mmsgMessages+1 {
					return oddAddr
				}
				return declaredAddr
			},
			want: want{refused: true, batchSend: mmsgMessages, odd: "unspec", dup: true},
		},
		{
			name: "AF_UNSPEC at index 64 behind 64 messages with no address", vlen: mmsgMessages + 1,
			odd: unspec, msg: oddAt(mmsgMessages, none),
			want: want{refused: true, odd: "unspec", dup: true},
		},
		{
			name: "an unrecognised family at index 64", vlen: mmsgMessages + 1,
			odd: vsock, msg: oddAt(mmsgMessages, declaredHead),
			want: want{refused: true, batchSend: mmsgMessages, odd: "family(40)", dup: true},
		},
		{
			name: "AF_UNSPEC at the last message the kernel sends", vlen: mmsgKernelMax,
			odd: unspec, msg: oddAt(mmsgKernelMax-1, none),
			want: want{refused: true, odd: "unspec", dup: true},
		},
		{
			// __sys_sendmmsg never reaches index 1024, so what it holds is not this loop's to decide.
			name: "AF_UNSPEC past the kernel's clamp", vlen: mmsgKernelMax + 1,
			odd: unspec, msg: oddAt(mmsgKernelMax, none),
		},
		{
			// A long batch whose every destination the policy admits is R13b's record-and-continue, with
			// the 64 lines the recording cap allows and none past them: R13b's residual.
			name: "65 declared messages", vlen: mmsgMessages + 1, msg: func(int) uint64 { return declaredAddr },
			want: want{declared: mmsgMessages, dup: true},
		},
		{
			// Measured on 6.17: a connected UDP socket sends the NULL-name messages to its peer and the
			// addressed one to its own msg_name, and sendmmsg returns 65. That one is a destination the policy
			// refuses, so the batch is refused whole (R13b as amended 2026-10-16).
			name: "a connected datagram socket, 64 messages with no address and an undeclared one", vlen: mmsgMessages + 1,
			connected: true, odd: undeclared, msg: oddAt(mmsgMessages, none),
			want: want{refused: true, odd: "203.0.113.9:4444", dup: true},
		},
		{
			name: "64 declared messages and an undeclared one", vlen: mmsgMessages + 1,
			odd: undeclared, msg: oddAt(mmsgMessages, declaredHead),
			want: want{refused: true, batchSend: mmsgMessages, odd: "203.0.113.9:4444", dup: true},
		},
		{
			// 960 datagrams to one undeclared host: the batch is refused, one line names the host, and the
			// ledger stays at 65.
			name: "64 declared messages and 960 undeclared ones", vlen: mmsgKernelMax, odd: undeclared,
			msg: func(i int) uint64 {
				if i < mmsgMessages {
					return declaredAddr
				}
				return oddAddr
			},
			want: want{refused: true, batchSend: mmsgMessages, odd: "203.0.113.9:4444", dup: true},
		},
		{
			// An undeclared destination past the 64th refuses the batch, however many admitted ones run before
			// and between, and the one tail line names it.
			name: "a tail alternating declared and undeclared messages", vlen: 2 * mmsgMessages, odd: undeclared,
			msg: func(i int) uint64 {
				switch {
				case i < mmsgMessages:
					return 0
				case i%2 == 0:
					return declaredAddr
				}
				return oddAddr
			},
			want: want{refused: true, odd: "203.0.113.9:4444", dup: true},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			f.connected = tc.connected
			f.put(arrayAddr, mmsgArray(tc.vlen, tc.msg))
			f.put(declaredAddr, sockaddrIn4("10.0.0.5", 8080))
			if tc.odd != nil {
				f.put(oddAddr, tc.odd)
			}
			pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
			l, sink := newTestLoop(t, f, pol)

			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, uint64(tc.vlen), 0))

			got, ok := f.lastResp()
			if !ok || f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one", f.respCount())
			}
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont == tc.want.refused {
				t.Fatalf("response = %+v, want refused=%v: the kernel sends every message up to UIO_MAXIOV", got, tc.want.refused)
			}
			if tc.want.refused && (got.Error != -int32(refusalErrno) || got.Val != -1) {
				t.Errorf("response = {error=%d val=%d}, want R10's errno", got.Error, got.Val)
			}
			var batchSend, declared int
			odd := ""
			evs := sink.all()
			for _, ev := range evs {
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatalf("payload: %v", err)
				}
				if p.Proto != protoUDP {
					t.Errorf("proto = %q, want the socket's own udp", p.Proto)
				}
				if p.BestEffort == tc.want.refused {
					t.Errorf("event %s best_effort = %v, want %v", p.Dst, p.BestEffort, !tc.want.refused)
				}
				switch {
				case p.Dst == "10.0.0.5:8080" && ev.Rule == ruleBatchSend && ev.Verdict == record.VerdictRefused:
					batchSend++
				case p.Dst == "10.0.0.5:8080" && ev.Rule != ruleBatchSend && ev.Verdict == record.VerdictAllow:
					declared++
				case ev.Rule == ruleUnmatched && ev.Verdict == record.VerdictRefused && ev.Reason == record.ReasonNetNotAllowed && odd == "":
					odd = p.Dst
				default:
					t.Errorf("unexpected event {%s %s %s}", ev.Verdict, ev.Rule, p.Dst)
				}
			}
			if batchSend != tc.want.batchSend || declared != tc.want.declared || odd != tc.want.odd {
				t.Errorf("events = {batch-send %d, recorded %d, refused/unmatched %q}, want {%d, %d, %q}: the first %d messages are recorded, and past them one line for the first destination the batch did not admit",
					batchSend, declared, odd, tc.want.batchSend, tc.want.declared, tc.want.odd, mmsgMessages)
			}
			if len(evs) > mmsgMessages+1 {
				t.Errorf("events = %d, want at most %d for one call", len(evs), mmsgMessages+1)
			}
			if took := f.openFDs != 0; took != tc.want.dup {
				t.Errorf("took the socket = %v, want %v", took, tc.want.dup)
			}
			if f.fdBalance() != 0 {
				t.Errorf("%d descriptors left open", f.fdBalance())
			}
		})
	}
}

// TestSendMMsgStreamTailIsDecidedWithTheBatch is R13c for an address past the 64th message. A batch whose
// first 64 messages carried no address was continued before the socket was even taken, whatever decidable
// address came after them; on a stream socket the address past them is now decided with the batch like
// one before them. Without a peer, or with MSG_FASTOPEN, that is R13c's refusal and a line naming the address; on a
// connected socket without MSG_FASTOPEN it is R13a's CONTINUE, undecided and unrecorded.
func TestSendMMsgStreamTailIsDecidedWithTheBatch(t *testing.T) {
	const arrayAddr, saAddr = 0x100000, 0x40000
	for _, tc := range []struct {
		name      string
		ip        string
		connected bool
		flags     uint64
		wantCont  bool
		wantRule  string
	}{
		{name: "declared, on a socket without a peer", ip: "10.0.0.5", wantRule: ruleBatchSend},
		{name: "undeclared, on a socket without a peer", ip: "203.0.113.9", wantRule: ruleUnmatched},
		{name: "undeclared, MSG_FASTOPEN on a connected socket", ip: "203.0.113.9", connected: true, flags: unix.MSG_FASTOPEN, wantRule: ruleUnmatched},
		{name: "undeclared, a connected socket without MSG_FASTOPEN", ip: "203.0.113.9", connected: true, wantCont: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.connected = tc.connected
			f.put(arrayAddr, mmsgArray(mmsgMessages+1, func(i int) uint64 {
				if i == mmsgMessages {
					return saAddr
				}
				return 0
			}))
			f.put(saAddr, sockaddrIn4(tc.ip, 8080))
			pol := testPolicy([]agent.NetRule{netRule("10.0.0.5:8080", "", 8080, "10.0.0.5")}, nil, []netip.AddrPort{})
			l, sink := newTestLoop(t, f, pol)

			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgMessages+1, tc.flags))

			got, ok := f.lastResp()
			if !ok || f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one", f.respCount())
			}
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.wantCont {
				t.Fatalf("response = %+v, want CONTINUE=%v", got, tc.wantCont)
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
			if got.Error != -int32(refusalErrno) || got.Val != -1 {
				t.Errorf("response = {error=%d val=%d}, want R10's errno", got.Error, got.Val)
			}
			ev := sink.one(t)
			var p netPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatalf("payload: %v", err)
			}
			if ev.Verdict != record.VerdictRefused || ev.Rule != tc.wantRule || p.Dst != tc.ip+":8080" || p.Proto != protoTCP || p.BestEffort {
				t.Errorf("event = {%s %s %s %s best_effort=%v}, want an enforced tcp refusal {%s %s:8080}",
					ev.Verdict, ev.Rule, p.Dst, p.Proto, p.BestEffort, tc.wantRule, tc.ip)
			}
		})
	}
}

// TestSendMMsgUnreadableTailFailsClosed: a header the read did not reach is one the kernel is about to
// read, past index 64 as before it, so it is R5's "not knowing whether there was an address", not "no
// address". It used to be outside what the handler read at all.
func TestSendMMsgUnreadableTailFailsClosed(t *testing.T) {
	const arrayAddr, saAddr = 0x100000, 0x40000
	f := newFake()
	f.sockType = unix.SOCK_DGRAM
	f.put(arrayAddr, mmsgArray(mmsgMessages, func(int) uint64 { return saAddr })) // header 64 is not mapped
	f.put(saAddr, sockaddrIn4("10.0.0.5", 8080))
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))

	l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, mmsgMessages+1, 0))

	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
		t.Fatalf("response = %+v, want R10's errno for a header this loop could not read (R5)", got)
	}
	if ev := sink.one(t); ev.Rule != ruleArgsUnreadable {
		t.Errorf("rule = %q, want %q", ev.Rule, ruleArgsUnreadable)
	}
}
