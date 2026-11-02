// SPDX-License-Identifier: Apache-2.0

//go:build integration && tegobpf

package cgroup

import (
	"errors"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	ebpfbindings "github.com/attention-span-ai/tego/internal/bpf"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/backend"
)

// TestUnixApprovalOnRealKernel is supervisor R11c's kernel half on 6.7+: an abstract name no unix: entry lists is
// refused by connect_unix until the supervisor grants the agent's socket that one name after a person approved it
// (Handle.GrantUnix), and the grant admits exactly one connect of exactly that socket to exactly that name, within
// its lifetime, for this run's gen; Detach removes every grant of the slot. Below 6.7 TestPlaneUnixApprovalOnRealKernel
// holds the plane's socket_connect to the same cells.
//
// The run's sockets are made before Arm, as the launcher starts its stage before its arming point (ADR 0021 (2)).
// The table's fs entries give this run a fanotify group, Arm marks their mount for it, and from then until Detach this
// process may start no process (ADR 0021 (3)). The helpers were once started after Arm: each re-executes this binary,
// and on a host whose one filesystem holds both the fixture and the binary (the GitHub runner's root filesystem,
// /tmp and $RUNNER_TEMP alike) the helper's execve raised a permission event of the group, which no listener here
// answers. os/exec's forking thread keeps its scheduler slot until that execve returns, so the next garbage
// collection's stop-the-world waited on it for good and stopped every goroutine, the -test.timeout alarm included:
// GitHub's root suite on kernel 7.0 printed nothing after "=== RUN" until its 6000 s bound killed the binary (§6 E39).
// The KVM guests mount a tmpfs /tmp and run the binary from the initramfs, so their exec was never on the marked
// mount, and their runs passed on every kernel.
func TestUnixApprovalOnRealKernel(t *testing.T) {
	u := newUnixFixture(t, "cgask")
	h, dir, _ := realRun(t, "unixask", u.table())
	if _, ok := h.kern.(*bpfKernel).progs[ebpfbindings.ProgConnectUnix]; !ok {
		t.Skip("this kernel predates cgroup/connect_unix (6.7); TestPlaneUnixApprovalOnRealKernel holds the plane's " +
			"socket_connect to these cells")
	}
	socks := newUnixApprovalSockets(t, dir)
	if err := h.Arm(); err != nil {
		t.Fatal(err)
	}
	unixApprovalCells(t, h, u, socks, unix.EPERM)
}

// TestPlaneUnixApprovalOnRealKernel is TestUnixApprovalOnRealKernel's cells for a run whose unix names the plane's
// socket_connect decides (below 6.7, or on 6.7+ with connect_unix withheld as planeUnixRun does), refused EACCES. A
// run in a plane mode has no fanotify group, so its sockets may be made after planeUnixRun has armed it.
func TestPlaneUnixApprovalOnRealKernel(t *testing.T) {
	h, dir, u := planeUnixRun(t, "planeask")
	unixApprovalCells(t, h, u, newUnixApprovalSockets(t, dir), unix.EACCES)
}

// unixApprovalSockets are the run's sockets the grant's cells connect: AF_UNIX stream sockets that helpers made inside
// the run's cgroup, each held here through a pidfd_getfd duplicate, as the supervisor holds the agent's (controlSocket).
type unixApprovalSockets struct {
	granted int // the socket a grant names: refused before it, admitted once by it
	sibling int // another socket of the run, which that grant does not cover
	late    int // granted, and connected only past the grant's lifetime
	stale   int // whose row names another gen of the slot
	purged  int // granted, and left for Detach to purge
}

// newUnixApprovalSockets makes the cells' sockets in the run's cgroup dir names, one helper process each. A run with a
// fanotify group makes them before Arm (TestUnixApprovalOnRealKernel).
func newUnixApprovalSockets(t *testing.T, dir *os.File) unixApprovalSockets {
	t.Helper()
	var s unixApprovalSockets
	for _, fd := range []*int{&s.granted, &s.sibling, &s.late, &s.stale, &s.purged} {
		*fd = controlSocket(t, dir, "unix-stream")
	}
	return s
}

// unixApprovalCells are the one-connect grant's cells for the attached, armed run h, on its sockets s, over u's
// unlisted abstract listener, with refused the errno the deciding program answers.
func unixApprovalCells(t *testing.T, h *Handle, u *unixFixture, s unixApprovalSockets, refused syscall.Errno) {
	t.Helper()
	m := h.kern.(*bpfKernel).maps[ebpfbindings.MapUnixApprovals]
	if m == nil {
		t.Fatalf("%s is not loaded", ebpfbindings.MapUnixApprovals)
	}
	name := []byte(u.absUnlisted[1:])
	target := &unix.SockaddrUnix{Name: u.absUnlisted}
	other := &unix.SockaddrUnix{Name: "@tego-it-other-" + u.tag}

	fd := s.granted
	if err := unix.Connect(fd, target); !errors.Is(err, refused) {
		t.Fatalf("an unlisted abstract name before any approval: %v, want %v", err, refused)
	}
	revoke, err := grantUnixFD(t, h, fd, name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = revoke() }()
	if err := unix.Connect(s.sibling, target); !errors.Is(err, refused) {
		t.Fatalf("another socket of the run inherited the grant: %v", err)
	}
	if err := unix.Connect(fd, other); !errors.Is(err, refused) {
		t.Fatalf("the grant widened to another name: %v", err)
	}
	cookie, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	key := ebpfbindings.UnixApprovalKey{RunIdx: h.slot, Gen: h.gen, Cookie: cookie}
	var credit ebpfbindings.UnixCredit
	if err := m.Lookup(&key, &credit); err != nil || credit.Credit != 1 {
		t.Fatalf("a refused connect spent the grant: %+v %v", credit, err)
	}
	if err := unix.Connect(fd, target); err != nil {
		t.Fatalf("the approved connect: %v", err)
	}
	if err := m.Lookup(&key, &credit); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("the consumed grant remains: %+v %v", credit, err)
	}
	if untaken, err := revoke(); err != nil || untaken {
		t.Fatalf("revoking a consumed grant: untaken=%v %v; want taken", untaken, err)
	}

	// Past its lifetime a grant admits nothing.
	late := s.late
	revokeLate, err := grantUnixFD(t, h, late, name)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = revokeLate() }()
	time.Sleep(connectApprovalLifetime + 100*time.Millisecond)
	if err := unix.Connect(late, target); !errors.Is(err, refused) {
		t.Fatalf("an expired grant admitted the connect: %v", err)
	}

	// The slot-reuse stale row: a grant of another gen of this slot, as a run that died before its revoke and before
	// the reaper leaves it, is absent to this run.
	stale := s.stale
	staleCookie, err := socketCookie(stale)
	if err != nil {
		t.Fatal(err)
	}
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	sk, sv, err := ebpfbindings.UnixApproval(h.slot, h.gen+1, staleCookie, name, uint64(ts.Nano())+uint64(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Update(&sk, &sv, ebpf.UpdateNoExist); err != nil {
		t.Fatal(err)
	}
	if err := unix.Connect(stale, target); !errors.Is(err, refused) {
		t.Fatalf("a grant of another gen of the slot admitted the connect: %v", err)
	}

	// Detach removes every grant of the slot, of every gen.
	if _, err := grantUnixFD(t, h, s.purged, name); err != nil {
		t.Fatal(err)
	}
	slot := h.slot
	if err := h.Detach(); err != nil {
		t.Fatalf("Detach: %v", err)
	}
	var k ebpfbindings.UnixApprovalKey
	for it := m.Iterate(); it.Next(&k, &credit); {
		if k.RunIdx == slot {
			t.Fatalf("a unix approval of slot %d survived Detach: %+v", slot, k)
		}
	}
}

// TestUnixApprovalRowsPurgedOnRealMaps is §5 R12 for the one-connect grants: purgeSlot, which the reaper and a
// Prepare that reclaims the slot run, removes a grant a dead launcher left at the slot.
func TestUnixApprovalRowsPurgedOnRealMaps(t *testing.T) {
	rt := &agent.RuleTable{Tier: backend.TierCgroup, Record: agent.RecordFull,
		Net: []agent.NetRule{{Raw: "unix:@tego-it-purge", Proto: agent.ProtoUnix, UnixPath: "tego-it-purge", Abstract: true,
			Verdict: agent.VerdictAllow, Static: true}}}
	h, _, _ := realRun(t, "unixaskpurge", rt)
	kern := h.kern.(*bpfKernel)
	m := kern.maps[ebpfbindings.MapUnixApprovals]
	if m == nil {
		t.Fatalf("%s is not loaded", ebpfbindings.MapUnixApprovals)
	}
	k, v, err := ebpfbindings.UnixApproval(h.Slot(), 1, 0xdead, []byte("stale-from-a-dead-run"), 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Update(&k, &v, 0); err != nil {
		t.Fatalf("write a stale grant: %v", err)
	}
	if err := kern.purgeSlot(h.Slot()); err != nil {
		t.Fatalf("purgeSlot: %v", err)
	}
	if err := m.Lookup(&k, &v); !errors.Is(err, ebpf.ErrKeyNotExist) {
		t.Fatalf("a unix approval of slot %d survived purgeSlot: %v", h.Slot(), err)
	}
}

// grantUnixFD grants as the supervisor's askUnix does: by the cookie of the socket fd, which it reads from its
// duplicate of the agent's socket (GrantUnix takes no descriptor number, ADR 0023 F8).
func grantUnixFD(t *testing.T, h *Handle, fd int, name []byte) (Revoke, error) {
	t.Helper()
	cookie, err := socketCookie(fd)
	if err != nil {
		t.Fatal(err)
	}
	return h.GrantUnix(nil, cookie, name)
}
