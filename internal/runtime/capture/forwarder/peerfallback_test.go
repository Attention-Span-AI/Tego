// SPDX-License-Identifier: Apache-2.0

package forwarder

import (
	"errors"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"testing"

	"github.com/attention-span-ai/tego/internal/runtime/source"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// loopbackPair is one accepted loopback connection opened by this process: the dialling end's address is the
// peer, the accepting end's the local, as the listener sees them.
func loopbackPair(t *testing.T) (peer, local netip.AddrPort) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close() })
	s, err := ln.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return netip.MustParseAddrPort(c.LocalAddr().String()), netip.MustParseAddrPort(s.LocalAddr().String())
}

// The /proc walk procAdmitter falls back to when the run's cgroup.procs cannot be listed
// admits a peer whose socket a process of the run holds, names that process, and refuses the same socket for a
// run nobody is in (R19a). The tcp table, /proc/<pid>/fd and the cgroup walk are all real.
func TestFallbackAdmitterAdmitsAMemberOfTheRun(t *testing.T) {
	run, err := liveCgroupID()
	if err != nil {
		t.Skipf("no cgroup2 membership to test against: %v", err)
	}
	peer, local := loopbackPair(t)

	pid, err := procPeerAdmitter(peer, local, run)
	if err != nil {
		t.Fatalf("the run's own connection was refused: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("admitted as pid %d, want the holder %d", pid, os.Getpid())
	}
	if _, err := procPeerAdmitter(peer, local, foreignCgroupID); !errors.Is(err, ErrPeer) {
		t.Errorf("a run nobody is in admitted the connection: err = %v", err)
	}
}

// Membership of the run is not enough; the member has to hold this socket. A socket no
// process holds is refused even when the run has members, so a holdsSocket that matched any descriptor would
// fail here rather than admit every local peer.
func TestFallbackAdmitterRefusesASocketTheRunDoesNotHold(t *testing.T) {
	run, err := liveCgroupID()
	if err != nil {
		t.Skipf("no cgroup2 membership to test against: %v", err)
	}
	peer, local := loopbackPair(t)
	inode, err := peerSocketInode(peer, local)
	if err != nil {
		t.Fatal(err)
	}
	if pid, err := socketHeldByCgroup(inode, run); err != nil || pid != os.Getpid() {
		t.Fatalf("socketHeldByCgroup(held) = %d, %v; want %d", pid, err, os.Getpid())
	}
	const unheld = uint64(1) << 40 // no socket inode on this machine is this large
	if pid, err := socketHeldByCgroup(unheld, run); !errors.Is(err, ErrPeer) {
		t.Errorf("a socket no process holds was admitted as pid %d (err %v)", pid, err)
	}
	if holdsSocket(os.Getpid(), "socket:[0]") {
		t.Error("holdsSocket matched a socket this process does not hold")
	}
	if holdsSocket(-1, "socket:[0]") {
		t.Error("holdsSocket answered yes for a process that cannot be read")
	}
}

// The run's gap report carries every listener's gaps, not only the first's.
func TestManagerGapsGathersEveryListener(t *testing.T) {
	m, err := NewManager([]agent.ModelEndpoint{
		{Provider: "anthropic", Host: "api.anthropic.com"},
		{Provider: "openai", Host: "api.openai.com"},
	}, Options{})
	if err != nil {
		t.Fatalf("new manager: %v", err)
	}
	t.Cleanup(func() { _ = m.Stop() })
	ls := m.Listeners()
	ls[0].note(GapMalformed, 2)
	ls[1].note(GapH2, 3)
	got := m.Gaps()
	slices.SortFunc(got, func(a, b source.Gap) int { return strings.Compare(a.Binary, b.Binary) })
	want := []source.Gap{
		{What: record.GapCapture, Why: GapMalformed, Binary: "api.anthropic.com", Count: 2},
		{What: record.GapCapture, Why: GapH2, Binary: "api.openai.com", Count: 3},
	}
	if !slices.Equal(got, want) {
		t.Errorf("gaps = %+v, want %+v", got, want)
	}
}
