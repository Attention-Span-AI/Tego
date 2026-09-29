// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestUnresolvedWithNoNetSection is R5 under SEMANTICS §1's "no net: — deny nothing". A task that made
// itself non-dumpable denies the unprivileged tier-1 supervisor both process_vm_readv and pidfd_getfd, so its
// address cannot be read nor its socket duplicated. R5 refused every such connect and send with R10's errno
// under a contract that restricts no network, where decide admits every destination. With no decision to
// hold, it is continued and recorded observed, best-effort, under args-unreadable or fd-unreadable. A net: section,
// the models[] guard, and an AF_UNSPEC send (refused on every socket) keep the refusal.
func TestUnresolvedWithNoNetSection(t *testing.T) {
	const addr, hdrAddr, arrayAddr = 0x40000, 0x30000, 0x100000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	ip := sockaddrIn4("203.0.113.9", 443)
	open := func() *Policy { return contractPolicy(&agent.Contract{HostSockets: true}, nil, nil) }
	for _, tc := range []struct {
		name     string
		pol      func() *Policy
		sockType int
		unread   bool // the address is not in the target's memory
		dupErr   error
		sa       []byte
		nr       int32
		args     []uint64
		cont     bool
		rule     string
	}{
		{"connect: address unreadable", open, unix.SOCK_STREAM, true, nil, ip, connectNR(), []uint64{5, addr, uint64(len(ip))}, true, ruleArgsUnreadable},
		{"connect: socket not duplicable", open, unix.SOCK_STREAM, false, unix.EPERM, ip, connectNR(), []uint64{5, addr, uint64(len(ip))}, true, ruleFDUnreadable},
		{"sendto datagram: socket not duplicable", open, unix.SOCK_DGRAM, false, unix.EPERM, ip, sendToNR(), []uint64{5, 0x9000, 4, 0, addr, uint64(len(ip))}, true, ruleFDUnreadable},
		{"sendto: address unreadable", open, unix.SOCK_DGRAM, true, nil, ip, sendToNR(), []uint64{5, 0x9000, 4, 0, addr, uint64(len(ip))}, true, ruleArgsUnreadable},
		{"sendmsg: header unreadable", open, unix.SOCK_DGRAM, true, nil, nil, sendMsgNR(), []uint64{5, hdrAddr, 0}, true, ruleArgsUnreadable},
		{"sendmmsg: socket not duplicable", open, unix.SOCK_DGRAM, false, unix.EPERM, nil, sendMMsgNR(), []uint64{5, arrayAddr, 1, 0}, true, ruleFDUnreadable},
		{"sendmmsg: headers unreadable", open, unix.SOCK_DGRAM, true, nil, nil, sendMMsgNR(), []uint64{5, arrayAddr, 1, 0}, true, ruleArgsUnreadable},
		{"sendto AF_UNSPEC: still refused", open, unix.SOCK_DGRAM, false, unix.EPERM, unspecSockaddr("203.0.113.9", 53), sendToNR(), []uint64{5, 0x9000, 4, 0, addr, 16}, false, ruleFDUnreadable},
		{"net: {}: still refused", func() *Policy { return contractPolicy(&agent.Contract{Net: &agent.NetSection{}}, nil, nil) },
			unix.SOCK_STREAM, false, unix.EPERM, ip, connectNR(), []uint64{5, addr, uint64(len(ip))}, false, ruleFDUnreadable},
		{"models[] guard: still refused", func() *Policy { return guardPolicy(backend.TierLandlock, nil, model) },
			unix.SOCK_STREAM, true, nil, ip, connectNR(), []uint64{5, addr, uint64(len(ip))}, false, ruleArgsUnreadable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			f.dupErr = tc.dupErr
			if !tc.unread {
				if tc.nr == sendMMsgNR() {
					f.put(arrayAddr, mmsgArray(1, func(int) uint64 { return addr }))
					f.put(addr, ip)
				} else {
					f.put(addr, tc.sa)
				}
			}
			l, sink := newTestLoop(t, f, tc.pol())
			l.handle(notifFor(tc.nr, 4242, tc.args...))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.cont {
				t.Fatalf("response = %+v, want CONTINUE=%v", got, tc.cont)
			}
			if !tc.cont && got.Error != -int32(refusalErrno) {
				t.Fatalf("response = %+v, want R10's errno", got)
			}
			ev := sink.one(t)
			p := netLine(t, ev)
			want, wantBE := record.VerdictRefused, false
			if tc.cont {
				want, wantBE = record.VerdictObserved, true
			}
			if ev.Verdict != want || ev.Rule != tc.rule || p.BestEffort != wantBE {
				t.Errorf("event = %s/%s best_effort=%v, want %s/%s best_effort=%v", ev.Verdict, ev.Rule, p.BestEffort, want, tc.rule, wantBE)
			}
			if len(f.connects) != 0 || f.openFDs != 0 {
				t.Errorf("connects %d, open duplicates %d; want nothing performed and nothing held", len(f.connects), f.openFDs)
			}
		})
	}
}

// TestNoNetRecordOffTakesNoDuplicate: under a contract with no net: section, no models[] guard and record:
// off, an addressed connect or send decides nothing (SEMANTICS §1) and writes no line (emitNet), so the
// socket's duplicate — ID_VALID twice, pidfd_open, pidfd_getfd, SO_TYPE, SO_PROTOCOL and two closes — was
// taken for nothing on every datagram a statsd, QUIC or mDNS client sent. It is answered CONTINUE from the
// address alone. An address that refuses the syscall on every socket (AF_UNSPEC in a send) still refuses.
func TestNoNetRecordOffTakesNoDuplicate(t *testing.T) {
	const addr, hdrAddr = 0x40000, 0x30000
	ip := sockaddrIn4("203.0.113.9", 443)
	for _, tc := range []struct {
		name  string
		sa    []byte
		nr    int32
		args  []uint64
		allow bool
	}{
		{"connect", ip, connectNR(), []uint64{5, addr, uint64(len(ip))}, true},
		{"sendto datagram", ip, sendToNR(), []uint64{5, 0x9000, 4, 0, addr, uint64(len(ip))}, true},
		{"sendmsg datagram", ip, sendMsgNR(), []uint64{5, hdrAddr, 0}, true},
		{"sendmmsg datagram", ip, sendMMsgNR(), []uint64{5, hdrAddr, 1, 0}, true},
		{"sendto AF_UNSPEC: still refused", unspecSockaddr("203.0.113.9", 53), sendToNR(),
			[]uint64{5, 0x9000, 4, 0, addr, 16}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_DGRAM
			f.put(addr, tc.sa)
			f.put(hdrAddr, mmsgArray(1, func(int) uint64 { return addr }))
			f.put(0x9000, []byte("ping"))
			pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
			pol.Record = agent.RecordOff
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(tc.nr, 4242, tc.args...))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.allow {
				t.Fatalf("response = %+v, want CONTINUE=%v", got, tc.allow)
			}
			if !tc.allow {
				if len(sink.all()) != 1 {
					t.Errorf("a refusal under record: off wrote %d lines, want 1", len(sink.all()))
				}
				return
			}
			if len(f.pidfdOpenedFor) != 0 {
				t.Errorf("took %d duplicates for a call that decides and records nothing", len(f.pidfdOpenedFor))
			}
			if len(sink.all()) != 0 {
				t.Errorf("wrote %d lines under record: off for an allowed call", len(sink.all()))
			}
		})
	}
}
