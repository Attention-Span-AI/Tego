// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"errors"
	"fmt"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// frameSock is one kind of socket a send can name, as SO_TYPE, SO_PROTOCOL and SO_DOMAIN read it, and whether a UDP
// pending frame can form on it (R13's pending frames): an IP datagram socket of UDP or UDP-Lite, a raw IP socket, and
// one whose domain cannot be read, which counts as one.
type frameSock struct {
	name               string
	typ, proto, domain int
	domainErr          error
	frames             bool
}

var frameSocks = []frameSock{
	{name: "UDP over IPv4", typ: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, domain: unix.AF_INET, frames: true},
	{name: "UDP over IPv6", typ: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDP, domain: unix.AF_INET6, frames: true},
	{name: "UDP-Lite", typ: unix.SOCK_DGRAM, proto: unix.IPPROTO_UDPLITE, domain: unix.AF_INET, frames: true},
	{name: "raw IP", typ: unix.SOCK_RAW, proto: unix.IPPROTO_RAW, domain: unix.AF_INET, frames: true},
	{name: "a datagram socket whose domain cannot be read", typ: unix.SOCK_DGRAM, domainErr: errors.New("EBADF"), frames: true},
	{name: "a ping socket", typ: unix.SOCK_DGRAM, proto: unix.IPPROTO_ICMP, domain: unix.AF_INET},
	{name: "TCP", typ: unix.SOCK_STREAM, proto: unix.IPPROTO_TCP, domain: unix.AF_INET},
	{name: "a unix datagram socket", typ: unix.SOCK_DGRAM, domain: unix.AF_UNIX},
}

// frameSend is one shape of a notified send: the syscall, whether and where it carries an address, and how many
// messages a batch holds. The address is the first message's (what the batch path used to name the batch's proto by),
// so a unix one on an IP socket is the shape this checks.
type frameSend struct {
	name string
	call func(f *fakeKernel, flags uint64) *notif
}

// TestAPendingFrameIsDecidedFromTheSocketAlone is R13's pending frames as one rule: under a contract that decides
// datagrams (agent.RuleTable.DecidesDatagrams: a net:
// section, a guarded models[] endpoint, a net gate), every send carrying MSG_MORE on a socket that can hold a UDP
// pending frame is refused datagram-corked before anything about its destination is decided, and no send on any other
// socket, and no send without the flag, is. What the socket is comes from the socket alone, never from an address the
// call carries: a batch whose first addressed message names a unix destination on a UDP socket was continued, its
// frame left pending to the socket's peer, and the next approved datagram joined it under a line naming another
// destination. Every send shape the filter notifies, on every kind of socket, is asked here.
func TestAPendingFrameIsDecidedFromTheSocketAlone(t *testing.T) {
	const saAddr, unAddr, bufAddr, hdrAddr, iovAddr, arrAddr = 0x40000, 0x48000, 0x50000, 0x60000, 0x80000, 0x90000
	payload := []byte("dgrm")
	sa := sockaddrIn4("203.0.113.9", 443)
	sun := sockaddrUn("@bus")
	header := func(f *fakeKernel, name uint64, namelen int) []byte {
		hdr := make([]byte, msgHdrSize)
		if name != 0 {
			hdr = namedMsgHdr(name, uint32(namelen))
		}
		iov := make([]byte, iovecSize)
		putU64(iov[iovecBaseOff:], bufAddr)
		putU64(iov[iovecLenOff:], uint64(len(payload)))
		f.put(iovAddr, iov)
		f.put(bufAddr, payload)
		putU64(hdr[msgIovOff:], iovAddr)
		putU64(hdr[msgIovLenOff:], 1)
		return hdr
	}
	put := func(f *fakeKernel) {
		f.put(saAddr, sa)
		f.put(unAddr, sun)
	}
	batch := func(names ...uint64) func(f *fakeKernel, flags uint64) *notif {
		return func(f *fakeKernel, flags uint64) *notif {
			put(f)
			arr := make([]byte, len(names)*mmsgHdrSize)
			for i, name := range names {
				namelen := 0
				switch name {
				case saAddr:
					namelen = len(sa)
				case unAddr:
					namelen = len(sun)
				}
				copy(arr[i*mmsgHdrSize:], header(f, name, namelen))
			}
			f.put(arrAddr, arr)
			return notifFor(sendMMsgNR(), 4242, 5, arrAddr, uint64(len(names)), flags)
		}
	}
	sends := []frameSend{
		{"an addressed sendto", func(f *fakeKernel, flags uint64) *notif {
			put(f)
			f.put(bufAddr, payload)
			return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), flags, saAddr, uint64(len(sa)))
		}},
		{"a sendto with no address", func(f *fakeKernel, flags uint64) *notif {
			f.put(bufAddr, payload)
			return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), flags, 0, 0)
		}},
		{"a sendto to a unix name", func(f *fakeKernel, flags uint64) *notif {
			put(f)
			f.put(bufAddr, payload)
			return notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), flags, unAddr, uint64(len(sun)))
		}},
		{"an addressed sendmsg", func(f *fakeKernel, flags uint64) *notif {
			put(f)
			f.put(hdrAddr, header(f, saAddr, len(sa)))
			return notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)
		}},
		{"an unaddressed sendmsg", func(f *fakeKernel, flags uint64) *notif {
			f.put(hdrAddr, header(f, 0, 0))
			return notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)
		}},
		{"a sendmsg to a unix name", func(f *fakeKernel, flags uint64) *notif {
			put(f)
			f.put(hdrAddr, header(f, unAddr, len(sun)))
			return notifFor(sendMsgNR(), 4242, 5, hdrAddr, flags)
		}},
		{"an addressed batch", batch(saAddr)},
		{"an unaddressed batch", batch(0)},
		{"a batch whose first address is a unix name, after an unaddressed message", batch(0, unAddr)},
		{"a batch whose first address is a unix name, before an IP one", batch(unAddr, saAddr)},
	}
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	contracts := []struct {
		name    string
		pol     func() *Policy
		decides bool
	}{
		{"a net: section", func() *Policy {
			return testPolicy([]agent.NetRule{
				netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9"),
				unixRuleOf("unix:@bus", "bus", true),
			}, nil, nil)
		}, true},
		{"a models[] guard", func() *Policy { return guardPolicy(backend.TierCgroup, nil, model) }, true},
		{"no net: section", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, false},
	}
	for _, ct := range contracts {
		if got := ct.pol().Rules.DecidesDatagrams(); got != ct.decides {
			t.Fatalf("%s: DecidesDatagrams = %v, want %v", ct.name, got, ct.decides)
		}
		for _, sk := range frameSocks {
			for _, s := range sends {
				for _, flags := range []uint64{0, unix.MSG_MORE, unix.MSG_MORE | unix.MSG_DONTWAIT} {
					name := fmt.Sprintf("%s/%s/%s/flags %#x", ct.name, sk.name, s.name, flags)
					t.Run(name, func(t *testing.T) {
						f := newFake()
						f.sockType, f.sockProto, f.sockDomain, f.sockDomainErr = sk.typ, sk.proto, sk.domain, sk.domainErr
						pol := ct.pol()
						pol.Rules.Record = agent.RecordFull
						l, sink := newTestLoop(t, f, pol)
						l.handle(s.call(f, flags))
						got, _ := f.lastResp()
						if b := f.fdBalance(); b != 0 {
							t.Errorf("fd balance %d; want every duplicate closed", b)
						}
						corked := 0
						for _, ev := range sink.all() {
							if ev.Rule != ruleCorked {
								continue
							}
							corked++
							if ev.Kind != record.KindNet || ev.Verdict != record.VerdictRefused || netLine(t, ev).BestEffort {
								t.Errorf("line %s %s/%s best_effort=%v; want an enforced net refusal", ev.Kind, ev.Verdict, ev.Rule, netLine(t, ev).BestEffort)
							}
							if err := ev.Validate(); err != nil {
								t.Errorf("line does not validate: %v", err)
							}
						}
						want := ct.decides && sk.frames && flags&unix.MSG_MORE != 0
						if !want {
							if corked != 0 {
								t.Fatalf("%d datagram-corked lines, response %+v; want none", corked, got)
							}
							return
						}
						if corked != 1 {
							t.Errorf("%d datagram-corked lines; want 1", corked)
						}
						if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
							t.Errorf("response %+v; want R10's errno", got)
						}
						if len(f.sends) != 0 {
							t.Errorf("%d sends; want nothing relayed", len(f.sends))
						}
					})
				}
			}
		}
	}
}

// TestTheRunCannotCorkASocket is R13's pending frames for UDP_CORK (enforce-landlock R11d): in a run that decides
// datagrams the filter notifies setsockopt(UDP_CORK) at SOL_UDP and SOL_UDPLITE, and the supervisor refuses it with R10's
// errno and a refused line, op setsockopt, rule datagram-corked, whatever the value: the value is in the agent's memory,
// and the scalars decide. A corked socket appends every later datagram to one frame whose destination is the first
// one's. A run that decides no datagrams is continued (its filter never notifies one). An observe run's filter notifies
// it too, and its supervisor continues it (R30) with no refused line, since nothing was refused: the binary's first cork
// is recorded gap what=record why=datagram-corked-setsockopt.
func TestTheRunCannotCorkASocket(t *testing.T) {
	nr := nrFor(t, "setsockopt")
	const optval = 0x7000
	for _, tc := range []struct {
		name    string
		pol     func() *Policy
		level   uint64
		refused bool
		gap     bool // an observe run: continued, a gap line in place of the refusal
	}{
		{"SOL_UDP under a net: section", func() *Policy { return testPolicy(nil, nil, nil) }, unix.SOL_UDP, true, false},
		{"SOL_UDPLITE under a net: section", func() *Policy { return testPolicy(nil, nil, nil) }, unix.IPPROTO_UDPLITE, true, false},
		{"int truncation", func() *Policy { return testPolicy(nil, nil, nil) }, 7<<32 | unix.SOL_UDP, true, false},
		{"no net: section", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, unix.SOL_UDP, false, false},
		{"SOL_UDP in an observe run", observePolicy, unix.SOL_UDP, false, true},
		{"SOL_UDPLITE in an observe run", observePolicy, unix.IPPROTO_UDPLITE, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(optval, []byte{1, 0, 0, 0})
			f.links["/proc/42/exe"] = "/usr/bin/agent"
			l, sink := newTestLoop(t, f, tc.pol())
			l.handle(notifFor(nr, 42, 3, tc.level, unix.UDP_CORK, optval, 4))
			got, _ := f.lastResp()
			if tc.gap {
				wantContinue(t, f)
				// The same binary's second cork adds no line: the gap is once per binary, syscall and rule.
				l.handle(notifFor(nr, 42, 3, tc.level, unix.UDP_CORK, optval, 4))
				wantFrameGap(t, sink.all(), "datagram-corked-setsockopt", "/usr/bin/agent")
				return
			}
			if !tc.refused {
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(sink.all()) != 0 {
					t.Fatalf("response %+v, %d lines; want CONTINUE and none", got, len(sink.all()))
				}
				return
			}
			if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno", got)
			}
			ev := sink.one(t)
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil {
				t.Fatal(err)
			}
			want := record.SocketOption(int32(tc.level), unix.UDP_CORK, nil, false)
			if ev.Kind != record.KindRefused || ev.Reason != record.ReasonNetNotAllowed || ev.Rule != ruleCorked ||
				p.Op != "setsockopt" || p.Target != want || p.Rule != ruleCorked {
				t.Errorf("event %s reason=%s rule=%s payload %+v, want op setsockopt target %q rule %s", ev.Kind, ev.Reason, ev.Rule, p, want, ruleCorked)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("line does not validate: %v", err)
			}
			if f.openFDs != 0 {
				t.Errorf("%d descriptors duplicated; the scalars decide", f.openFDs)
			}
		})
	}
}

// TestASendfileOrSpliceIntoAFrameSocketIsRefused is R13's pending frames for sendfile and splice (enforce-landlock R11d):
// splice_to_socket marks every write but a call's last with MSG_MORE, a splice with SPLICE_F_MORE marks the last one too,
// and so does a sendfile whose file ended before its count, so either can leave a UDP frame pending. In a run that
// decides datagrams one into a socket that can hold a frame is refused with R10's errno, rule datagram-corked; one into
// any other socket, a file or a pipe (ENOTSOCK) is continued, and so is one whose descriptor is not open (the kernel's
// EBADF). One whose descriptor this loop cannot duplicate or read is refused too, since it may be such a socket, but its
// line is a refused line naming the call and the descriptor, not a net line: nothing says the
// bytes were bound for a network, and a net line would have to name a protocol nobody read. The rule says why the
// descriptor was not read: fd-exhausted (no descriptor for the duplicate), fd-unreadable (pidfd_getfd's EPERM, a
// non-dumpable target at tier 1, whose file copies are then all refused) or fd-raced (the duplicate's type unreadable).
func TestASendfileOrSpliceIntoAFrameSocketIsRefused(t *testing.T) {
	sendfile, splice := nrFor(t, "sendfile"), nrFor(t, "splice")
	udp := func(f *fakeKernel) {
		f.sockType, f.sockProto, f.sockDomain = unix.SOCK_DGRAM, unix.IPPROTO_UDP, unix.AF_INET
	}
	for _, tc := range []struct {
		name  string
		pol   func() *Policy
		setup func(f *fakeKernel)
		rule  string // "" continues
	}{
		{"into a UDP socket", func() *Policy { return testPolicy(nil, nil, nil) }, udp, ruleCorked},
		{"into a UDP-Lite socket over IPv6", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) {
			f.sockType, f.sockProto, f.sockDomain = unix.SOCK_DGRAM, unix.IPPROTO_UDPLITE, unix.AF_INET6
		}, ruleCorked},
		{"into a TCP socket", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) {
			f.sockType, f.sockProto, f.sockDomain = unix.SOCK_STREAM, unix.IPPROTO_TCP, unix.AF_INET
		}, ""},
		{"into a unix datagram socket", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) {
			f.sockType, f.sockDomain = unix.SOCK_DGRAM, unix.AF_UNIX
		}, ""},
		{"into a file or a pipe", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) { f.sockTypErr = unix.ENOTSOCK }, ""},
		{"into a descriptor not open", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) { f.dupErr = unix.EBADF }, ""},
		{"with no descriptor to duplicate it", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) { f.dupErr = unix.EMFILE }, ruleFDExhausted},
		{"by a non-dumpable target", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) { f.dupErr = unix.EPERM }, ruleFDUnreadable},
		{"whose duplicate's type cannot be read", func() *Policy { return testPolicy(nil, nil, nil) }, func(f *fakeKernel) { f.sockTypErr = unix.EIO }, ruleFDRaced},
		{"into a UDP socket, no net: section", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, udp, ""},
		{"by a non-dumpable target, no net: section", func() *Policy { return contractPolicy(&agent.Contract{}, nil, nil) }, func(f *fakeKernel) { f.dupErr = unix.EPERM }, ""},
	} {
		for _, call := range []struct {
			name string
			n    func() *notif
		}{
			{"sendfile", func() *notif { return notifFor(sendfile, 42, 5, 6, 0, 1<<20) }},
			{"splice", func() *notif { return notifFor(splice, 42, 6, 0, 5, 0, 1<<20, unix.SPLICE_F_MORE) }},
		} {
			t.Run(call.name+" "+tc.name, func(t *testing.T) {
				f := newFake()
				tc.setup(f)
				l, sink := newTestLoop(t, f, tc.pol())
				l.handle(call.n())
				got, _ := f.lastResp()
				if b := f.fdBalance(); b != 0 {
					t.Errorf("fd balance %d; want every duplicate closed", b)
				}
				if tc.rule == "" {
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(sink.all()) != 0 {
						t.Fatalf("response %+v, %d lines; want CONTINUE and none", got, len(sink.all()))
					}
					return
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("response = %+v, want R10's errno", got)
				}
				ev := sink.one(t)
				if err := ev.Validate(); err != nil {
					t.Errorf("line does not validate: %v", err)
				}
				if tc.rule == ruleCorked {
					if ev.Kind != record.KindNet || ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule {
						t.Errorf("line %s %s/%s; want a refused net line, rule %s", ev.Kind, ev.Verdict, ev.Rule, tc.rule)
					}
					return
				}
				var p record.RefusedPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if ev.Kind != record.KindRefused || ev.Rule != tc.rule || ev.Reason != record.ReasonNetNotAllowed ||
					p.Op != call.name || p.Target != "fd 5" || p.Rule != tc.rule {
					t.Errorf("line %s rule %s reason %s payload %+v; want a refused line, op %s, target fd 5, rule %s",
						ev.Kind, ev.Rule, ev.Reason, p, call.name, tc.rule)
				}
			})
		}
	}
}

// TestAnObserveRunRecordsAPendingFrameRefusalItContinued is TestASendfileOrSpliceIntoAFrameSocketIsRefused for an observe
// run (R30): its filter notifies the same calls (enforce-landlock R11d), and its supervisor
// continues every one. A copy into a socket that can hold a frame keeps its net line, stamped observed under rule
// datagram-corked. One whose output descriptor could not be read gets no refused line, which would put a refusal that
// never happened in last-refusal.json and the agent's reason channel: the binary's first such call of each syscall and
// rule is recorded gap what=record why=<rule>-<syscall>, as an observed keyring syscall is (R32); a non-dumpable
// target's line names no binary, since the fake refuses its exe link as the kernel does.
func TestAnObserveRunRecordsAPendingFrameRefusalItContinued(t *testing.T) {
	sendfile, splice := nrFor(t, "sendfile"), nrFor(t, "splice")
	for _, tc := range []struct {
		name  string
		setup func(f *fakeKernel)
		rule  string
	}{
		{"into a UDP socket", func(f *fakeKernel) {
			f.sockType, f.sockProto, f.sockDomain = unix.SOCK_DGRAM, unix.IPPROTO_UDP, unix.AF_INET
		}, ruleCorked},
		{"with no descriptor to duplicate it", func(f *fakeKernel) { f.dupErr = unix.EMFILE }, ruleFDExhausted},
		{"by a non-dumpable target", func(f *fakeKernel) { f.dupErr = unix.EPERM }, ruleFDUnreadable},
		{"whose duplicate's type cannot be read", func(f *fakeKernel) { f.sockTypErr = unix.EIO }, ruleFDRaced},
	} {
		for _, call := range []struct {
			name string
			n    func() *notif
		}{
			{"sendfile", func() *notif { return notifFor(sendfile, 42, 5, 6, 0, 1<<20) }},
			{"splice", func() *notif { return notifFor(splice, 42, 6, 0, 5, 0, 1<<20, unix.SPLICE_F_MORE) }},
		} {
			t.Run(call.name+" "+tc.name, func(t *testing.T) {
				f := newFake()
				tc.setup(f)
				f.links["/proc/42/exe"] = "/usr/bin/agent"
				l, sink := newTestLoop(t, f, observePolicy())
				l.handle(call.n())
				wantContinue(t, f)
				if b := f.fdBalance(); b != 0 {
					t.Errorf("fd balance %d; want every duplicate closed", b)
				}
				if tc.rule == ruleCorked {
					wantObserved(t, sink.one(t), record.KindNet, ruleCorked)
					return
				}
				l.handle(call.n())
				// A non-dumpable target's binary cannot be read: the ptrace check that refused its descriptor
				// refuses /proc/<pid>/exe too, and the line names none (TestAGapWhoseBinaryCannotBeReadIsOncePerProcess).
				binary := "/usr/bin/agent"
				if f.dupErr == unix.EPERM {
					binary = ""
				}
				wantFrameGap(t, sink.all(), tc.rule+"-"+call.name, binary)
			})
		}
	}
}

// wantFrameGap fails unless lines are exactly one gap what=record with the given why and binary: what an observe run
// records for a pending-frame refusal it continued, once per binary, syscall and rule, never a refused line.
func wantFrameGap(t *testing.T, lines []*record.Event, why, binary string) {
	t.Helper()
	if len(lines) != 1 {
		t.Fatalf("%d lines, want one gap line", len(lines))
	}
	ev := lines[0]
	var p record.GapPayload
	if err := ev.DecodePayload(&p); err != nil || ev.Kind != record.KindGap || p.What != record.GapRecord ||
		p.Why != why || p.Binary != binary || p.Count != 1 {
		t.Errorf("line %s %+v (%v), want gap what=record why=%s binary=%s count=1", ev.Kind, p, err, why, binary)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("line does not validate: %v", err)
	}
}

// TestAMoreSendWhoseSocketCannotBeReadIsRefused is the failure table's fd-exhausted and fd-raced rows for R13's pending
// frames: a send whose flags carry MSG_MORE, in a run that decides datagrams, has its socket read
// to tell whether it can hold a frame, so one this loop cannot duplicate (no descriptor left) or read (the number was
// reused by a non-socket) is refused fd-exhausted, fd-unreadable (a non-dumpable target's pidfd_getfd EPERM) or fd-raced
// whatever socket it is, a TCP one included; the same send
// without the flag is continued with nothing read.
func TestAMoreSendWhoseSocketCannotBeReadIsRefused(t *testing.T) {
	const hdrAddr, iovAddr, bufAddr = 0x60000, 0x80000, 0x50000
	for _, tc := range []struct {
		name  string
		setup func(f *fakeKernel)
		rule  string
	}{
		{"no descriptor to duplicate it", func(f *fakeKernel) { f.dupErr = unix.EMFILE }, ruleFDExhausted},
		{"a non-dumpable target's", func(f *fakeKernel) { f.dupErr = unix.EPERM }, ruleFDUnreadable},
		{"not a socket any more", func(f *fakeKernel) { f.sockTypErr = unix.ENOTSOCK }, ruleFDRaced},
	} {
		for _, flags := range []uint64{0, unix.MSG_MORE} {
			t.Run(fmt.Sprintf("%s/flags %#x", tc.name, flags), func(t *testing.T) {
				f := newFake()
				f.sockType, f.sockProto, f.sockDomain = unix.SOCK_STREAM, unix.IPPROTO_TCP, unix.AF_INET
				tc.setup(f)
				hdr := make([]byte, msgHdrSize)
				iov := make([]byte, iovecSize)
				putU64(iov[iovecBaseOff:], bufAddr)
				putU64(iov[iovecLenOff:], 4)
				putU64(hdr[msgIovOff:], iovAddr)
				putU64(hdr[msgIovLenOff:], 1)
				f.put(hdrAddr, hdr)
				f.put(iovAddr, iov)
				f.put(bufAddr, []byte("data"))
				l, sink := newTestLoop(t, f, testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil))
				l.handle(notifFor(sendMsgNR(), 42, 5, hdrAddr, flags))
				got, _ := f.lastResp()
				if flags == 0 {
					if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(sink.all()) != 0 {
						t.Fatalf("response %+v, %d lines; want CONTINUE and none", got, len(sink.all()))
					}
					return
				}
				if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(refusalErrno) {
					t.Fatalf("response = %+v, want R10's errno", got)
				}
				if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != tc.rule {
					t.Errorf("line %s/%s; want refused/%s", ev.Verdict, ev.Rule, tc.rule)
				}
			})
		}
	}
}

// TestAnEmptyBatchStartsNoFrame: a sendmmsg of no message sends nothing and starts no frame, whatever its flags, so one
// carrying MSG_MORE on a UDP socket is continued as every empty batch is (R13c's "empty batches remain no-ops"), with no
// socket read.
func TestAnEmptyBatchStartsNoFrame(t *testing.T) {
	f := newFake()
	f.sockType, f.sockProto, f.sockDomain = unix.SOCK_DGRAM, unix.IPPROTO_UDP, unix.AF_INET
	l, sink := newTestLoop(t, f, testPolicy([]agent.NetRule{netRule("203.0.113.9:443", "203.0.113.9", 443, "203.0.113.9")}, nil, nil))
	l.handle(notifFor(sendMMsgNR(), 42, 5, 0x90000, 0, unix.MSG_MORE))
	got, _ := f.lastResp()
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(sink.all()) != 0 || f.openFDs != 0 {
		t.Fatalf("response %+v, %d lines, %d duplicates; want CONTINUE, none and none", got, len(sink.all()), f.openFDs)
	}
}
