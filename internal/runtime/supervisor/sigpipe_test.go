// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestARelayedSendsEPIPERaisesSIGPIPE: a relayed Fast-Open send runs sendto(2) on the duplicate, on this
// process's thread, so the SIGPIPE the kernel pairs with EPIPE on a connection-oriented socket (a send after
// shutdown(SHUT_WR), without MSG_NOSIGNAL) hit the supervisor, whose Go runtime drops it: the agent read a
// bare EPIPE, and a default-disposition agent lived on where the native call kills it (I3). The signal is
// now raised on the trapping task through a pidfd taken before the answer and sent after it. MSG_NOSIGNAL, a
// datagram socket and any other errno raise nothing.
func TestARelayedSendsEPIPERaisesSIGPIPE(t *testing.T) {
	const saAddr, bufAddr = 0x40000, 0x50000
	model := agent.ModelEndpoint{Provider: "anthropic", Host: "127.0.0.1", Port: 8443}
	payload := []byte("GET / HTTP/1.1\r\n")
	for _, tc := range []struct {
		name     string
		flags    uint64
		sockType int
		err      error
		want     bool
	}{
		{"EPIPE", unix.MSG_FASTOPEN, unix.SOCK_STREAM, unix.EPIPE, true},
		{"EPIPE with MSG_NOSIGNAL", unix.MSG_FASTOPEN | unix.MSG_NOSIGNAL, unix.SOCK_STREAM, unix.EPIPE, false},
		{"ECONNREFUSED", unix.MSG_FASTOPEN, unix.SOCK_STREAM, unix.ECONNREFUSED, false},
		{"datagram EPIPE", 0, unix.SOCK_DGRAM, unix.EPIPE, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.sockType = tc.sockType
			f.sendErr = tc.err
			f.put(saAddr, sockaddrIn4("203.0.113.9", 443))
			f.put(bufAddr, payload)
			l, _ := newTestLoop(t, f, guardPolicy(backend.TierLandlock, nil, model))
			l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, uint64(len(payload)), tc.flags, saAddr, 16))
			got, _ := f.lastResp()
			if len(f.sends) != 1 || got.Error != -int32(tc.err.(unix.Errno)) {
				t.Fatalf("response = %+v, sends %d: want the relayed %v", got, len(f.sends), tc.err)
			}
			switch {
			case !tc.want && len(f.signalled) != 0:
				t.Errorf("signals = %+v, want none", f.signalled)
			case tc.want && len(f.signalled) != 1:
				t.Fatalf("signals = %+v, want one SIGPIPE on the trapping task", f.signalled)
			case tc.want:
				s := f.signalled[0]
				if s.sig != unix.SIGPIPE || s.afterResponses != f.respCount() {
					t.Errorf("signal = %+v after %d answers, want SIGPIPE once EPIPE is answered", s, f.respCount())
				}
				if n := len(f.pidfdOpenedFor); n == 0 || f.pidfdOpenedFor[n-1] != 4242 {
					t.Errorf("pidfds opened for %v, want the trapping tid 4242 last", f.pidfdOpenedFor)
				}
			}
			if b := f.fdBalance(); b != 0 {
				t.Errorf("%d descriptors left open", b)
			}
		})
	}
}
