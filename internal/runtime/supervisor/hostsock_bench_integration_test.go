// SPDX-License-Identifier: Apache-2.0

//go:build integration && (amd64 || arm64)

package supervisor

import (
	"os"
	"strconv"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Targets under a contract with no net: section (modeNoNet's), timed by the harness: modeBenchNoNetDgram sends
// targetDgramLoop's addressed UDP datagrams, a DNS client's queries, and modeBenchNoNetConnect makes targetConnectLoop's
// TCP connects. Under host_sockets: true each is continued to the kernel, the reach every such contract had before ADR
// 0070; in the unix-only state each is performed on the supervisor's duplicate (R7b).
const (
	modeBenchNoNetDgram   = "bench-nonet-dgram"
	modeBenchNoNetConnect = "bench-nonet-connect"
)

// targetConnectLoop makes helperLoops TCP connects to the allowed port on 127.0.0.1, each on a fresh socket closed
// after it, and times the whole loop. A connect's result is not checked: the loop's lines say what each was.
func targetConnectLoop() (int, int64) {
	n, err := strconv.Atoi(os.Getenv(helperLoops))
	if err != nil || n <= 0 {
		return 0, 0
	}
	to := &unix.SockaddrInet4{Port: splitPorts(os.Getenv(helperPorts))[0], Addr: [4]byte{127, 0, 0, 1}}
	start := time.Now()
	for range n {
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			return 0, 0
		}
		_ = unix.Connect(fd, to)
		_ = unix.Close(fd)
	}
	return n, time.Since(start).Nanoseconds()
}

// BenchmarkUnixOnlyRelay is ADR 0070 (8): what the unix-only state adds to an IP connect and to an addressed datagram
// (a DNS lookup's query) of a run with no net: section, over a real seccomp listener, as the agent sees it
// (target-ns/op). "continued" is host_sockets: true, where the supervisor answers CONTINUE and the kernel performs the
// call, the cost every such run paid before; "relayed" is the default, where the supervisor performs the call on its
// duplicate of the socket from the copy it decided, so a sibling thread cannot redirect it (ADR 0041 D6).
// docs/OPERATIONS.md quotes the figures. Like BenchmarkRelayDatagram it needs no privilege, and the timer runs only
// across the target's loop.
func BenchmarkUnixOnlyRelay(b *testing.B) {
	for _, bc := range []struct {
		name, mode  string
		hostSockets bool
	}{
		{"datagram/continued", modeBenchNoNetDgram, true},
		{"datagram/relayed", modeBenchNoNetDgram, false},
		{"connect/continued", modeBenchNoNetConnect, true},
		{"connect/relayed", modeBenchNoNetConnect, false},
	} {
		b.Run(bc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.StopTimer()
			h := startHarnessWith(b, harnessOpts{
				loops: b.N, mode: bc.mode, env: []string{helperDgramTo + "=allowed"}, hostSockets: bc.hostSockets,
				acked: b.StartTimer, reported: b.StopTimer,
			})
			m := h.stop(b)
			if h.report.LoopOps != b.N {
				b.Fatalf("the target reported %d calls, want %d", h.report.LoopOps, b.N)
			}
			if m.Notifications < int64(b.N) {
				b.Fatalf("the loop received %d notifications for %d calls", m.Notifications, b.N)
			}
			b.ReportMetric(float64(h.report.LoopNS)/float64(b.N), "target-ns/op")
		})
	}
}
