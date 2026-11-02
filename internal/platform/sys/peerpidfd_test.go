// SPDX-License-Identifier: Apache-2.0

package sys

import (
	"errors"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

// TestPeerPidfdFDNamesThePeer: SO_PEERPIDFD's owner form owns a close-on-exec, process-scoped pidfd of the process
// that made the connection, this one, which PollPidfdFD finds alive; below Linux 6.5 the kernel answers ENOPROTOOPT,
// which comes back unchanged for the caller's fallback (internal/platform/peer). A closed connection is an error.
func TestPeerPidfdFDNamesThePeer(t *testing.T) {
	a, b, err := Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	f, err := a.Release("peerpidfd")
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.FileConn(f)
	_ = f.Close()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	raw, err := c.(*net.UnixConn).SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	p, err := PeerPidfdFD(raw)
	if errors.Is(err, unix.ENOPROTOOPT) {
		t.Skip("no SO_PEERPIDFD on this kernel (below Linux 6.5)")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	wantCloexec(t, numOf(p), "PeerPidfdFD")
	if err := checkKind(numOf(p), KindPidfd); err != nil {
		t.Fatalf("PeerPidfdFD's number is not a pidfd: %v", err)
	}
	if exited, err := PollPidfdFD(p, 0); err != nil || exited {
		t.Errorf("PollPidfdFD of this live process = %v, %v", exited, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PeerPidfdFD(raw); err == nil {
		t.Error("PeerPidfdFD of a closed connection succeeded")
	}
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := PollPidfdFD(p, 0); !errors.Is(err, ErrClosed) {
		t.Errorf("PollPidfdFD of a closed owner = %v, want ErrClosed", err)
	}
}
