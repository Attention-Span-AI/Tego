// SPDX-License-Identifier: Apache-2.0

package cgroup

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// kernelCredits is a one-shot approval map with the kernel's semantics: UpdateNoExist refuses a live key (EEXIST),
// and Delete removes whatever row the key names, whoever wrote it. take is the hook taking a credit (the CAS and
// delete of tego_connect_approved, tego_unix_approved). collisions counts the EEXIST refusals.
type kernelCredits struct {
	mu         sync.Mutex
	rows       map[any]any
	collisions int
	writes     int
}

func (m *kernelCredits) Update(key, value any, flags ebpf.MapUpdateFlags) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.rows == nil {
		m.rows = map[any]any{}
	}
	if _, live := m.rows[key]; live && flags == ebpf.UpdateNoExist {
		m.collisions++
		return ebpf.ErrKeyExist
	}
	m.rows[key] = value
	m.writes++
	return nil
}

func (m *kernelCredits) Delete(key any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, live := m.rows[key]; !live {
		return ebpf.ErrKeyNotExist
	}
	delete(m.rows, key)
	return nil
}

// take consumes every live credit, as the run's hook does for the operation a relay performs.
func (m *kernelCredits) take() {
	m.mu.Lock()
	defer m.mu.Unlock()
	clear(m.rows)
}

// creditKernel is the fake kernel with the two approval maps (creditStore).
type creditKernel struct {
	*fakeKernel
	connects, unixes *kernelCredits
}

func (k *creditKernel) creditMap(name string) creditMap {
	switch name {
	case bpf.MapConnectApprovals:
		return k.connects
	case bpf.MapUnixApprovals:
		return k.unixes
	}
	return nil
}

func creditHandle() (*Handle, *creditKernel) {
	k := &creditKernel{fakeKernel: newFakeKernel(), connects: &kernelCredits{}, unixes: &kernelCredits{}}
	return &Handle{kern: k, prepared: true, slot: 3, gen: 5}, k
}

// TestGrantsOfOneRowTakeTheirCreditsInTurn is creditRows: the grants of
// one approval row are serialized by the row's own map key, so two approved operations that would write one row never
// collide (the second's UpdateNoExist failing EEXIST, an approval refused) and no revoke deletes another's credit,
// whatever the operations' own spellings differ in: two datagrams of one socket to one destination, a UDP socket's
// connect and datagram to one destination, two scopes (zones) of one IPv6 link-local address, which the kernel's key
// drops, and two abstract names of one unix socket, whose row is the socket's. Operations of different rows are not
// held up. The serializing key used to be the supervisor's, built apart from the map's, and drifted from it twice: by
// the unix name, then by the IPv6 zone.
func TestGrantsOfOneRowTakeTheirCreditsInTurn(t *testing.T) {
	udp, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(udp)
	cookie, err := socketCookie(udp)
	if err != nil {
		t.Fatal(err)
	}
	dst := netip.MustParseAddrPort("192.0.2.4:53")
	datagram := func(cookie uint64, domain int, dst netip.AddrPort) func(h *Handle, done <-chan struct{}) (Revoke, error) {
		return func(h *Handle, done <-chan struct{}) (Revoke, error) {
			return h.GrantDatagram(done, cookie, domain, dst)
		}
	}
	unixName := func(cookie uint64, name string) func(h *Handle, done <-chan struct{}) (Revoke, error) {
		return func(h *Handle, done <-chan struct{}) (Revoke, error) { return h.GrantUnix(done, cookie, []byte(name)) }
	}
	for _, tc := range []struct {
		name          string
		first, second func(h *Handle, done <-chan struct{}) (Revoke, error)
		oneRow        bool
	}{
		{"two datagrams of one socket to one destination", datagram(cookie, unix.AF_INET, dst), datagram(cookie, unix.AF_INET, dst), true},
		{"a UDP socket's connect and datagram to one destination", func(h *Handle, done <-chan struct{}) (Revoke, error) {
			return h.GrantConnect(done, udp, dst, agent.ProtoUDP)
		}, datagram(cookie, unix.AF_INET, dst), true},
		{"two zones of one link-local address", datagram(cookie, unix.AF_INET6, netip.MustParseAddrPort("[fe80::1%2]:53")),
			datagram(cookie, unix.AF_INET6, netip.MustParseAddrPort("[fe80::1%3]:53")), true},
		{"two abstract names of one unix socket", unixName(cookie, "\x00bus"), unixName(cookie, "\x00log"), true},
		{"two sockets", datagram(cookie, unix.AF_INET, dst), datagram(cookie+1, unix.AF_INET, dst), false},
		{"two destinations", datagram(cookie, unix.AF_INET, dst), datagram(cookie, unix.AF_INET, netip.MustParseAddrPort("192.0.2.5:53")), false},
		{"two ports", datagram(cookie, unix.AF_INET, dst), datagram(cookie, unix.AF_INET, netip.MustParseAddrPort("192.0.2.4:54")), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, k := creditHandle()
			first, err := tc.first(h, nil)
			if err != nil {
				t.Fatalf("first grant: %v", err)
			}
			granted := make(chan error, 1)
			var second Revoke
			go func() {
				var err error
				second, err = tc.second(h, nil)
				granted <- err
			}()
			select {
			case err := <-granted:
				if tc.oneRow {
					t.Fatalf("the second grant of one row returned while the first was held: %v", err)
				}
				if err != nil {
					t.Fatalf("a grant of another row: %v", err)
				}
			case <-time.After(100 * time.Millisecond):
				if !tc.oneRow {
					t.Fatal("a grant of another row waited for the first")
				}
			}
			if untaken, err := first(); err != nil || !untaken {
				t.Fatalf("first revoke: untaken=%v %v; want an untaken credit withdrawn", untaken, err)
			}
			if tc.oneRow {
				if err := <-granted; err != nil {
					t.Fatalf("the second grant after the first's revoke: %v", err)
				}
			}
			k.connects.take() // the second's relay: the hook takes its credit
			k.unixes.take()
			if untaken, err := second(); err != nil || untaken {
				t.Fatalf("second revoke: untaken=%v %v; want a taken credit", untaken, err)
			}
			if c := k.connects.collisions + k.unixes.collisions; c != 0 {
				t.Errorf("%d EEXIST collisions; want the grants serialized", c)
			}
			if n := len(k.connects.rows) + len(k.unixes.rows); n != 0 {
				t.Errorf("%d rows left after both revokes", n)
			}
		})
	}
}

// TestAGrantWaitsBoundedAndForANotPreparedHandleGrantsNothing: a grant waits for another of its row at most the given
// wait and never past its caller's done (ErrGrantBusy, nothing written), and one whose handle was detached while it
// waited writes nothing (ErrNotPrepared), since its key names a run that is over.
func TestAGrantWaitsBoundedAndForANotPreparedHandleGrantsNothing(t *testing.T) {
	var rows creditRows
	release, err := rows.hold(nil, "row", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if _, err := rows.hold(nil, "row", 50*time.Millisecond); !errors.Is(err, ErrGrantBusy) {
		t.Fatalf("a held row's second hold: %v; want ErrGrantBusy", err)
	}
	if d := time.Since(start); d < 50*time.Millisecond || d > 900*time.Millisecond {
		t.Errorf("the bounded wait took %v", d)
	}
	done := make(chan struct{})
	close(done)
	if _, err := rows.hold(done, "row", time.Minute); !errors.Is(err, ErrGrantBusy) {
		t.Fatalf("a hold whose done closed: %v; want ErrGrantBusy", err)
	}
	release()
	release() // idempotent
	again, err := rows.hold(nil, "row", time.Second)
	if err != nil {
		t.Fatalf("a released row: %v", err)
	}
	again()

	h, k := creditHandle()
	dst := netip.MustParseAddrPort("192.0.2.4:53")
	first, err := h.GrantDatagram(nil, 9, unix.AF_INET, dst)
	if err != nil {
		t.Fatal(err)
	}
	granted := make(chan error, 1)
	go func() {
		_, err := h.GrantDatagram(nil, 9, unix.AF_INET, dst)
		granted <- err
	}()
	time.Sleep(50 * time.Millisecond)
	h.netMu.Lock()
	h.detached = true
	h.netMu.Unlock()
	if _, err := first(); err != nil {
		t.Fatal(err)
	}
	if err := <-granted; !errors.Is(err, ErrNotPrepared) {
		t.Fatalf("a grant that waited past Detach: %v; want ErrNotPrepared", err)
	}
	if k.connects.writes != 1 {
		t.Errorf("%d credits written; want the first alone", k.connects.writes)
	}
}
