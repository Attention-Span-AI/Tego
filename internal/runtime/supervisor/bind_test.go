// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"bytes"
	"net/netip"
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

type bindFake struct {
	*fakeKernel
	calls [][]byte
	err   error
}

func (f *bindFake) BindRaw(_ int, raw []byte) error {
	f.calls = append(f.calls, bytes.Clone(raw))
	return f.err
}

func TestBindFreezesSocketAddressAndRelaysRealError(t *testing.T) {
	for _, tc := range []struct {
		name, proto, address string
		typ                  int
		port                 uint16
		allow                bool
		err                  error
	}{
		{"TCP ephemeral", agent.ProtoTCP, "127.0.0.1", unix.SOCK_STREAM, 0, true, nil},
		{"zero is not arbitrary port", agent.ProtoTCP, "127.0.0.1", unix.SOCK_STREAM, 8080, false, nil},
		{"UDP selector", agent.ProtoUDP, "127.0.0.1", unix.SOCK_DGRAM, 0, true, nil},
		{"wrong transport", agent.ProtoUDP, "127.0.0.1", unix.SOCK_STREAM, 0, false, nil},
		{"actual bind failure", agent.ProtoTCP, "127.0.0.1", unix.SOCK_STREAM, 0, true, unix.EADDRINUSE},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.typ
			raw := sockaddrIn4(tc.address, tc.port)
			f.put(0x40000, raw)
			policy := testPolicy(nil, nil, nil)
			policy.Rules.Listen = []agent.ListenRule{{Raw: tc.proto + "://127.0.0.1:0", Proto: tc.proto, Address: netip.MustParseAddr(tc.address)}}
			l, sink := newTestLoop(t, f, policy)
			binder := &bindFake{fakeKernel: f, err: tc.err}
			l.k = binder
			n := notifFor(connectNR(), 4242, 5, 0x40000, uint64(len(raw)))
			handleBind(l, n)
			response, ok := f.lastResp()
			if !ok {
				t.Fatal("bind not answered")
			}
			if response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatal("IP bind rereads mutable target address")
			}
			if tc.allow {
				if len(binder.calls) != 1 || !bytes.Equal(binder.calls[0], raw) {
					t.Fatalf("bind used different bytes: %v", binder.calls)
				}
			} else if len(binder.calls) != 0 || response.Error != -int32(refusalErrno) {
				t.Fatalf("refused bind performed: calls=%v response=%+v", binder.calls, response)
			}
			if tc.err != nil && response.Error != -int32(unix.EADDRINUSE) {
				t.Fatalf("real failure not relayed: %+v", response)
			}
			ev := sink.one(t)
			if (ev.Verdict == record.VerdictAllow) != tc.allow {
				t.Fatalf("wrong decision: %+v", ev)
			}
			var payload bindPayload
			if err := ev.DecodePayload(&payload); err != nil || payload.Op != "bind" {
				t.Fatalf("missing operation: %+v %v", payload, err)
			}
			if err := ev.Validate(); err != nil {
				t.Fatal(err)
			}
			if f.fdBalance() != 0 {
				t.Fatalf("duplicate leaked: %d", f.fdBalance())
			}
		})
	}
}

// TestBindAnswersTheKernelsAddressErrors pins that an allowed IP bind is answered what the target's own
// bind would answer for its address (R3, R9, I3): move_addr_to_kernel fails a length past 128 EINVAL and
// faults EFAULT when any of min(addrlen, 128) bytes cannot be copied, and only then does the protocol fail a
// length short of its family's EINVAL. A bind performed with the readable prefix of a short read used to
// succeed where the target's own call faults.
func TestBindAnswersTheKernelsAddressErrors(t *testing.T) {
	raw := sockaddrIn4("127.0.0.1", 0)
	for _, tc := range []struct {
		name    string
		addrlen uint64
		want    unix.Errno
	}{
		{"exact", uint64(len(raw)), 0},
		{"addrlen 128 past a mapped address", sockaddrMax, unix.EFAULT},
		{"addrlen past 128", 4096, unix.EINVAL},
		{"addrlen short of the family's", 8, unix.EINVAL},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = unix.SOCK_STREAM
			f.put(0x40000, raw) // mapped alone: the bytes past it fault
			policy := testPolicy(nil, nil, nil)
			policy.Rules.Listen = []agent.ListenRule{{Raw: "tcp://127.0.0.1:0", Proto: agent.ProtoTCP, Address: netip.MustParseAddr("127.0.0.1")}}
			l, _ := newTestLoop(t, f, policy)
			binder := &bindFake{fakeKernel: f}
			l.k = binder
			handleBind(l, notifFor(connectNR(), 4242, 5, 0x40000, tc.addrlen))
			response, ok := f.lastResp()
			if !ok {
				t.Fatal("bind not answered")
			}
			if tc.want == 0 {
				if len(binder.calls) != 1 || response.Error != 0 {
					t.Fatalf("calls %d response %+v: want the fully read address bound", len(binder.calls), response)
				}
				return
			}
			if len(binder.calls) != 0 || response.Error != -int32(tc.want) || response.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("calls %d response %+v: want the kernel's own %v and nothing bound", len(binder.calls), response, tc.want)
			}
		})
	}
}
