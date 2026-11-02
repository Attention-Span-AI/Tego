// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// unsupportedLine is what the run's log says, once, of a kernel without TCP sock_diag.
const unsupportedLine = "looked for in /proc/net/tcp for the rest of the run"

// A kernel without TCP sock_diag answers the exact lookup ENOENT, as it answers a tuple no socket has, or refuses the
// netlink protocol outright. The run's lookup tells that apart from a miss once (the probe), says so once in the
// run's log and goes straight to the tcp tables after that; a miss on a kernel with the modules stays a miss and is
// asked again, and any other error is the lookup's own.
func TestTCPDiagTurnsOffOnceForAKernelWithoutIt(t *testing.T) {
	peer, local := netip.MustParseAddrPort("127.0.0.1:40000"), netip.MustParseAddrPort("127.0.0.1:50000")
	refused := fmt.Errorf("%w: socket: %w", errSockDiagUnsupported, unix.EPROTONOSUPPORT)
	other := fmt.Errorf("sock_diag: %w", unix.EPERM)
	for _, c := range []struct {
		name        string
		lookup      error
		missing     bool
		off         bool  // the second connection skips the lookup
		want        error // what the first connection's lookup answers
		probes      int64 // the probe's calls over both connections
		logged      int
		lookupCalls int64
	}{
		{name: "a miss the probe confirms is the kernel's", lookup: errSockDiagMiss, missing: true, off: true,
			want: errSockDiagUnsupported, probes: 1, logged: 1, lookupCalls: 1},
		{name: "a socket(2) that refuses the protocol", lookup: refused, off: true, want: errSockDiagUnsupported,
			probes: 0, logged: 1, lookupCalls: 1},
		{name: "a miss on a kernel with the modules", lookup: errSockDiagMiss, want: errSockDiagMiss, probes: 2,
			lookupCalls: 2},
		{name: "another error", lookup: other, want: unix.EPERM, lookupCalls: 2},
		{name: "a hit", lookupCalls: 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			var logged syncBuffer
			d := newTCPDiag(slog.New(slog.NewTextHandler(&logged, nil)))
			var lookups, probes atomic.Int64
			d.lookup = func(p, l netip.AddrPort) (uint64, error) {
				lookups.Add(1)
				if p != peer || l != local {
					t.Errorf("lookup of %s -> %s, want %s -> %s", p, l, peer, local)
				}
				if c.lookup != nil {
					return 0, c.lookup
				}
				return 77, nil
			}
			d.missing = func() bool { probes.Add(1); return c.missing }
			for i := range 2 {
				ino, err := d.inode(peer, local)
				switch {
				case c.want == nil && (err != nil || ino != 77):
					t.Fatalf("connection %d: inode %d, err %v, want 77", i, ino, err)
				case c.want != nil && !errors.Is(err, c.want):
					t.Fatalf("connection %d: err %v, want %v", i, err, c.want)
				}
			}
			if got := lookups.Load(); got != c.lookupCalls {
				t.Errorf("%d lookups over two connections, want %d", got, c.lookupCalls)
			}
			if got := probes.Load(); got != c.probes {
				t.Errorf("%d probes over two connections, want %d", got, c.probes)
			}
			if got := strings.Count(logged.String(), unsupportedLine); got != c.logged {
				t.Errorf("logged %d times, want %d:\n%s", got, c.logged, logged.String())
			}
			if d.off.Load() != c.off {
				t.Errorf("off %v, want %v", d.off.Load(), c.off)
			}
		})
	}
}

// Many connections that meet a kernel without TCP sock_diag at once still log it once, and every one of them is
// answered errSockDiagUnsupported, so each goes to the tcp tables.
func TestTCPDiagLogsOnceUnderConcurrentConnections(t *testing.T) {
	var logged syncBuffer
	d := newTCPDiag(slog.New(slog.NewTextHandler(&logged, nil)))
	d.lookup = func(netip.AddrPort, netip.AddrPort) (uint64, error) { return 0, errSockDiagMiss }
	d.missing = func() bool { return true }
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Go(func() {
			p := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(40000+i))
			_, err := d.inode(p, netip.MustParseAddrPort("127.0.0.1:50000"))
			errs <- err
		})
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if !errors.Is(err, errSockDiagUnsupported) {
			t.Errorf("err %v, want errSockDiagUnsupported", err)
		}
	}
	if got := strings.Count(logged.String(), unsupportedLine); got != 1 {
		t.Errorf("logged %d times, want once:\n%s", got, logged.String())
	}
}

// The probe's answer: ENOENT, as an NLMSG_ERROR or as an NLMSG_DONE's status, is a kernel without TCP sock_diag;
// an empty dump's NLMSG_DONE, another errno, or a message too short or whose length lies, is not.
func TestProbeAnsweredENOENT(t *testing.T) {
	msg := func(typ uint16, errno unix.Errno, length int) []byte {
		m := make([]byte, nlmsgHdrLen+4)
		ne := binary.NativeEndian
		ne.PutUint32(m[0:], uint32(length))
		ne.PutUint16(m[4:], typ)
		ne.PutUint32(m[nlmsgHdrLen:], uint32(-int32(errno)))
		return m
	}
	full := nlmsgHdrLen + 4
	for _, c := range []struct {
		name string
		msg  []byte
		want bool
	}{
		{"an error reply of ENOENT", msg(nlmsgErrorType, unix.ENOENT, full), true},
		{"a done of ENOENT", msg(unix.NLMSG_DONE, unix.ENOENT, full), true},
		{"an empty dump's done", msg(unix.NLMSG_DONE, 0, full), false},
		{"an error reply of EPERM", msg(nlmsgErrorType, unix.EPERM, full), false},
		{"another type", msg(unix.SOCK_DIAG_BY_FAMILY, unix.ENOENT, full), false},
		{"a length past the datagram", msg(nlmsgErrorType, unix.ENOENT, full+1), false},
		{"a length under the header and status", msg(nlmsgErrorType, unix.ENOENT, nlmsgHdrLen), false},
		{"a short datagram", msg(nlmsgErrorType, unix.ENOENT, full)[:nlmsgHdrLen], false},
	} {
		if got := probeAnsweredENOENT(c.msg); got != c.want {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
		}
	}
}

// On this kernel, with a live connection whose peer socket exists: where the exact lookup finds it, the probe must not
// say the modules are missing, or a run there would give up the exact lookup on its first closed socket; where the
// lookup misses it (a kernel without inet_diag or tcp_diag, as a KVM guest that loaded neither is), the probe must say
// so, and the run's lookup turns off.
func TestTCPDiagProbeAgreesWithTheExactLookup(t *testing.T) {
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	c, s, peer, local := livePair(t, ln)
	defer func() { _ = c.Close(); _ = s.Close() }()
	if _, err := sockDiagInode(peer, local); err != nil {
		if !errors.Is(err, errSockDiagMiss) && !errors.Is(err, errSockDiagUnsupported) {
			t.Skipf("this kernel refuses the exact lookup (%v): the probe's agreement cannot be checked here", err)
		}
		if errors.Is(err, errSockDiagMiss) && !tcpDiagMissing() {
			t.Fatalf("the exact lookup missed a live connection's peer (%v), and the probe says the kernel has TCP sock_diag", err)
		}
		d := newTCPDiag(nil)
		if _, err := d.inode(peer, local); !errors.Is(err, errSockDiagUnsupported) || !d.off.Load() {
			t.Fatalf("without TCP sock_diag: err %v, off %v, want errSockDiagUnsupported and the lookup off", err, d.off.Load())
		}
		t.Logf("this kernel has no TCP sock_diag (%v); the probe said so and the run's lookup turned off", err)
		return
	}
	if tcpDiagMissing() {
		t.Fatal("the exact lookup answered, and the probe says the kernel has no TCP sock_diag")
	}
	d := newTCPDiag(nil)
	if _, err := d.inode(netip.MustParseAddrPort("127.0.0.1:1"), local); !errors.Is(err, errSockDiagMiss) || d.off.Load() {
		t.Fatalf("a tuple no socket has: err %v, off %v, want a miss and the lookup kept", err, d.off.Load())
	}
}

// Once off, the admitter goes straight to the tcp tables: a live connection from this process is still admitted,
// and the exact lookup is not asked again for the next one.
func TestProcAdmitterGoesStraightToTheTablesWithoutTCPDiag(t *testing.T) {
	id, err := liveCgroupID()
	if err != nil {
		t.Skipf("this machine cannot place a process in a cgroup2 hierarchy: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(Loopback, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()
	d := newTCPDiag(nil)
	var lookups atomic.Int64
	d.lookup = func(netip.AddrPort, netip.AddrPort) (uint64, error) {
		lookups.Add(1)
		return 0, fmt.Errorf("%w: socket: %w", errSockDiagUnsupported, unix.EPROTONOSUPPORT)
	}
	a := newProcAdmitterOn(d)
	for i := range 3 {
		c, s, peer, local := livePair(t, ln)
		if _, err := a.admit(peer, local, id); err != nil {
			t.Fatalf("connection %d: the peer of a live connection from this process was refused: %v", i, err)
		}
		_ = c.Close()
		_ = s.Close()
	}
	if got := lookups.Load(); got != 1 {
		t.Errorf("%d exact lookups over three connections, want 1", got)
	}
}

// The run's listeners share one lookup, so a kernel without TCP sock_diag is found, and logged, once a run.
func TestManagerListenersShareOneTCPDiag(t *testing.T) {
	m, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "openai", Host: "api.openai.com"},
	}, Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	ls := m.Listeners()
	if len(ls) != 2 || ls[0].opts.tcpDiag == nil || ls[0].opts.tcpDiag != ls[1].opts.tcpDiag {
		t.Fatalf("%d listeners, lookups %p and %p, want two sharing one", len(ls), ls[0].opts.tcpDiag, ls[1].opts.tcpDiag)
	}
}
