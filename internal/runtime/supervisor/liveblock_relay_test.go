// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveRelayLoop is a loop over a contract that continues its connects, no net: section and host_sockets: true, with
// set as its live blocks and call's socket and the copied address sa in the fake's memory.
func liveRelayLoop(t *testing.T, call gateRelayCall, sa []byte, set *liveblock.Set) (*fakeKernel, *Loop, *testSink) {
	t.Helper()
	f := newFake()
	f.sockType = call.sockType
	f.put(0x40000, sa)
	f.put(0x50000, []byte("x"))
	pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
	pol.Rules.Record = agent.RecordFull
	l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
	return f, l, sink
}

// TestLiveBlockRelaysAnAdmittedIPConnect: a contract with no net: section and host_sockets: true continues its connects
// because any address a sibling swaps in is one it admits. A live net block ends that: the connect the block admitted,
// checked on a benign copy, is performed on the duplicate with that copy, so the kernel never reads the address again
// and a sibling that rewrote it to the blocked destination reaches nothing. Before, one connect in five of a
// two-thread agent reached a server on the exact destination the block named, under a line that read allow to the copy.
// The socket's domain is SO_DOMAIN of the duplicate; one that cannot be read is IP, the side that decides. A unix-spelled
// copy on an IP socket is relayed too, and gets the kernel's own answer. A unix socket cannot reach an IP destination,
// and keeps the agent's own connect, credentials and Landlock scope.
func TestLiveBlockRelaysAnAdmittedIPConnect(t *testing.T) {
	blocks := liveSet(t, "net", "127.0.0.1:39511")
	benign := sockaddrIn4("198.51.100.1", 443)
	unixSpelled := sockaddrUn("blocked.sock")
	for _, call := range gateRelayCalls[:2] { // connect and Fast Open
		for _, tc := range []struct {
			name    string
			domain  int
			domErr  error
			sa      []byte
			relayed bool
		}{
			{"inet socket", unix.AF_INET, nil, benign, true},
			{"inet6 socket", unix.AF_INET6, nil, sockaddrIn6("2001:db8::1", 443), true},
			{"inet socket, unix-spelled copy", unix.AF_INET, nil, unixSpelled, true},
			{"unreadable domain", unix.AF_INET, unix.EBADF, benign, true},
			{"unix socket", unix.AF_UNIX, nil, unixSpelled, false},
		} {
			t.Run(call.name+"/"+tc.name, func(t *testing.T) {
				f, l, sink := liveRelayLoop(t, call, tc.sa, blocks)
				f.sockDomain, f.sockDomainErr = tc.domain, tc.domErr
				call.n(l, tc.sa)
				r, ok := f.lastResp()
				if !ok {
					t.Fatal("unanswered")
				}
				if !tc.relayed {
					if r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
						t.Fatalf("response %+v; a unix socket's connect stays the agent's own", r)
					}
					return
				}
				if r.Flags != 0 || !relayedWith(f, call, tc.sa) {
					t.Fatalf("response %+v connects %q sends %+v unix %q; want the copy performed on the duplicate, no CONTINUE",
						r, f.connects, f.sends, f.unixConnects)
				}
				ev := sink.one(t)
				var p netPayload
				if err := ev.DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if p.BestEffort {
					t.Errorf("a relayed connect's line is best_effort: %+v", p)
				}
			})
		}
	}
}

// TestLiveBlockStillRefusesWhatItNames: the relay carries out only what the block admitted, and refused is still
// refused, on the copy: nothing is performed.
func TestLiveBlockStillRefusesWhatItNames(t *testing.T) {
	blocks := liveSet(t, "net", "127.0.0.1:39511")
	sa := sockaddrIn4("127.0.0.1", 39511)
	for _, call := range gateRelayCalls[:2] {
		t.Run(call.name, func(t *testing.T) {
			f, l, sink := liveRelayLoop(t, call, sa, blocks)
			call.n(l, sa)
			r, _ := f.lastResp()
			if r.Flags != 0 || r.Error != -int32(refusalErrno) || len(f.connects) != 0 || len(f.sends) != 0 {
				t.Fatalf("response %+v connects %d sends %d; want the refusal and nothing performed", r, len(f.connects), len(f.sends))
			}
			if ev := sink.one(t); ev.Rule != "live.block[net:127.0.0.1:39511]" || ev.Verdict != record.VerdictRefused {
				t.Fatalf("line %s %s", ev.Verdict, ev.Rule)
			}
		})
	}
}

// TestLiveBlockRelayNeedsANetBlock: with no net block a contract with host_sockets: true keeps continuing its connects,
// the agent's own with its own credentials: a path or exec block narrows nothing a connect could reach, so it costs no
// connect its directness.
func TestLiveBlockRelayNeedsANetBlock(t *testing.T) {
	benign := sockaddrIn4("198.51.100.1", 443)
	for name, set := range map[string]*liveblock.Set{
		"no blocks":         nil,
		"an exec block":     liveSet(t, "exec", "curl"),
		"a read block":      liveSet(t, "read", "/secrets"),
		"a path block":      liveSet(t, "path", "/secrets"),
		"both, no net kind": liveSet(t, "exec", "curl", "write", "/etc"),
	} {
		for _, call := range gateRelayCalls[:2] {
			t.Run(name+"/"+call.name, func(t *testing.T) {
				f, l, _ := liveRelayLoop(t, call, benign, set)
				f.sockDomain = unix.AF_INET
				call.n(l, benign)
				if r, _ := f.lastResp(); r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.connects) != 0 || len(f.sends) != 0 {
					t.Fatalf("response %+v connects %d sends %d, want CONTINUE", r, len(f.connects), len(f.sends))
				}
			})
		}
	}
}

// TestLiveBlockLeavesADatagramBestEffort: an addressed datagram keeps R13b's tier-1 reading under a block, stated in
// docs/OPERATIONS.md: refused when its copy is blocked, continued best_effort otherwise, since a relay could not
// reproduce QUIC's ancillary data and would refuse it (relayDatagram).
func TestLiveBlockLeavesADatagramBestEffort(t *testing.T) {
	blocks := liveSet(t, "net", "127.0.0.1:39511")
	call := gateRelayCalls[2]
	t.Run("admitted", func(t *testing.T) {
		sa := sockaddrIn4("198.51.100.1", 443)
		f, l, sink := liveRelayLoop(t, call, sa, blocks)
		f.sockDomain = unix.AF_INET
		call.n(l, sa)
		if r, _ := f.lastResp(); r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || len(f.sends) != 0 {
			t.Fatalf("response %+v sends %d, want CONTINUE", r, len(f.sends))
		}
		var p netPayload
		if err := sink.one(t).DecodePayload(&p); err != nil {
			t.Fatal(err)
		}
		if !p.BestEffort {
			t.Errorf("a continued datagram's line is not best_effort: %+v", p)
		}
	})
	t.Run("blocked", func(t *testing.T) {
		sa := sockaddrIn4("127.0.0.1", 39511)
		f, l, sink := liveRelayLoop(t, call, sa, blocks)
		f.sockDomain = unix.AF_INET
		call.n(l, sa)
		if r, _ := f.lastResp(); r.Error != -int32(refusalErrno) || len(f.sends) != 0 {
			t.Fatalf("response %+v sends %d, want the refusal", r, len(f.sends))
		}
		if ev := sink.one(t); ev.Rule != "live.block[net:127.0.0.1:39511]" {
			t.Errorf("rule = %s", ev.Rule)
		}
	})
}

// TestLiveBlockFastOpenWithNoAddressIsNotContinued: a sendmsg with no msg_name and MSG_FASTOPEN names nothing to check,
// and after a CONTINUE the kernel copies the msghdr again, so a sibling that wrote an address in has
// tcp_sendmsg_fastopen connect to it, around a block. While a net block exists it is relayed as it was read, with no
// address (R12), under every contract that would continue it. A unix socket has no Fast Open to redirect.
func TestLiveBlockFastOpenWithNoAddressIsNotContinued(t *testing.T) {
	const hdrAddr, iovAddr, bufAddr = 0x60000, 0x61000, 0x50000
	put := func(f *fakeKernel) {
		hdr := make([]byte, msgHdrSize)
		putU64(hdr[msgIovOff:], iovAddr)
		putU64(hdr[msgIovLenOff:], 1)
		f.put(hdrAddr, hdr)
		iov := make([]byte, iovecSize)
		putU64(iov[iovecBaseOff:], bufAddr)
		putU64(iov[iovecLenOff:], 1)
		f.put(iovAddr, iov)
		f.put(bufAddr, []byte("x"))
	}
	blocks := liveSet(t, "net", "127.0.0.1:39511")
	for _, tc := range []struct {
		name        string
		hostSockets bool
		domain      int
		set         *liveblock.Set
		relayed     bool
	}{
		{"host_sockets: true, a block", true, unix.AF_INET, blocks, true},
		{"the unix-only state, a block", false, unix.AF_INET6, blocks, true},
		{"host_sockets: true, a unix socket", true, unix.AF_UNIX, blocks, false},
		{"host_sockets: true, no block", true, unix.AF_INET, nil, false},
		{"the unix-only state, no block", false, unix.AF_INET, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain = unix.SOCK_STREAM, tc.domain
			put(f)
			set := tc.set
			pol := contractPolicy(&agent.Contract{HostSockets: tc.hostSockets}, nil, nil)
			l, _ := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(notifFor(sendMsgNR(), 4242, 5, hdrAddr, unix.MSG_FASTOPEN))
			r, ok := f.lastResp()
			if !ok {
				t.Fatal("unanswered")
			}
			if continued := r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; continued == tc.relayed {
				t.Fatalf("response %+v, want relayed: %v", r, tc.relayed)
			}
			if tc.relayed && (len(f.sends) != 1 || !bytes.Equal(f.sends[0].addr, nil) || f.sends[0].flags != unix.MSG_FASTOPEN) {
				t.Fatalf("sends %+v, want the one send as read, with no address", f.sends)
			}
		})
	}
}

// TestLiveBlockStreamBatchIsRefused: an unconnected stream batch, or a Fast-Open one, addressed or not, cannot be relayed
// (R13c), so while a net block exists it is refused batch-send, as under a net: section: continued, the kernel reads
// every address again. A datagram batch keeps R13b's reading, and a connected stream's addresses are ignored (R13a).
func TestLiveBlockStreamBatchIsRefused(t *testing.T) {
	const arrayAddr, saAddr = 0x90000, 0x40000
	blocks := liveSet(t, "net", "127.0.0.1:39511")
	for _, tc := range []struct {
		name      string
		sockType  int
		connected bool
		addressed bool
		flags     uint64
		set       *liveblock.Set
		refused   bool
	}{
		{"unconnected stream", unix.SOCK_STREAM, false, true, 0, blocks, true},
		{"Fast Open on a connected stream", unix.SOCK_STREAM, true, true, unix.MSG_FASTOPEN, blocks, true},
		{"Fast Open with no address", unix.SOCK_STREAM, false, false, unix.MSG_FASTOPEN, blocks, true},
		{"a connected stream", unix.SOCK_STREAM, true, true, 0, blocks, false},
		{"a datagram batch", unix.SOCK_DGRAM, false, true, 0, blocks, false},
		{"no block", unix.SOCK_STREAM, false, true, 0, nil, false},
		{"no block, Fast Open with no address", unix.SOCK_STREAM, false, false, unix.MSG_FASTOPEN, nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType, f.sockDomain, f.connected = tc.sockType, unix.AF_INET, tc.connected
			sa := sockaddrIn4("198.51.100.1", 443)
			if tc.addressed {
				f.put(arrayAddr, mmsgBatch(saAddr, uint32(len(sa))))
				f.put(saAddr, sa)
			} else {
				f.put(arrayAddr, mmsgBatch(0, 0))
			}
			set := tc.set
			pol := contractPolicy(&agent.Contract{HostSockets: true}, nil, nil)
			pol.Rules.Record = agent.RecordFull
			l, sink := newTestLoopOpts(t, f, pol, Options{LiveBlocks: func() *liveblock.Set { return set }})
			l.handle(notifFor(sendMMsgNR(), 4242, 5, arrayAddr, 1, tc.flags))
			r, ok := f.lastResp()
			if !ok {
				t.Fatal("unanswered")
			}
			if !tc.refused {
				if r.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("response %+v, want CONTINUE", r)
				}
				return
			}
			if r.Flags != 0 || r.Error != -int32(refusalErrno) {
				t.Fatalf("response %+v, want the refusal", r)
			}
			if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Rule != ruleBatchSend {
				t.Fatalf("line %s %s, want refused %s", ev.Verdict, ev.Rule, ruleBatchSend)
			}
		})
	}
}
