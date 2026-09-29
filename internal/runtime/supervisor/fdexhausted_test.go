// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"bytes"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// lockedBuffer is a bytes.Buffer safe for the logger's writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (w *lockedBuffer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *lockedBuffer) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

// TestDescriptorExhaustionIsLoggedAtWarn is §7's "pidfd_getfd fails" row for EMFILE: every allowed connect is
// refused while this process has no descriptor for the duplicate, and the line alone read as a race (fd-raced)
// with the cause at Debug, so at the default level nothing said the supervisor was out of descriptors. It is
// now fd-exhausted and logged at Warn, once per fdWarnEvery however many connects it refuses; a genuine race
// (EBADF) stays fd-raced and quiet.
func TestDescriptorExhaustionIsLoggedAtWarn(t *testing.T) {
	const addr = 0x2000
	sa := sockaddrIn4("93.184.216.34", 443)
	rules := []agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34")}
	for _, tc := range []struct {
		errno    error
		wantWarn int
	}{{unix.EMFILE, 1}, {unix.EBADF, 0}} {
		f := newFake()
		f.put(addr, sa)
		f.sockType = unix.SOCK_STREAM
		f.dupErr = tc.errno
		l, _ := newTestLoop(t, f, testPolicy(rules, nil, []netip.AddrPort{netip.MustParseAddrPort("127.0.0.53:53")}))
		var buf lockedBuffer
		l.log = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelWarn}))
		for i := 0; i < 3; i++ {
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		}
		if got := strings.Count(buf.String(), "out of file descriptors"); got != tc.wantWarn {
			t.Errorf("%v: %d Warn lines for three refused connects, want %d:\n%s", tc.errno, got, tc.wantWarn, buf.String())
		}
	}
}
