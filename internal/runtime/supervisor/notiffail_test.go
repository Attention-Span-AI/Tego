// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
)

// TestNotifSendAndIDValidFailuresStillAnswer: a NOTIF_SEND or ID_VALID failure that is not ENOENT says
// nothing about the target. Both marked the notification gone, and gone is never answered (R19), so a
// transient failure — EINTR from notify_lock's interruptible wait, before sys retried it — left the task
// trapped in its syscall until the listener closed. A failed call is now retried once, and an ID_VALID that
// keeps failing answers the notification fail-closed rather than dropping it.
func TestNotifSendAndIDValidFailuresStillAnswer(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrIn4("203.0.113.9", 443)
	allowed := func() *Policy {
		return testPolicy([]agent.NetRule{netRule("svc:443", "svc", 443, "203.0.113.9")}, nil, nil)
	}
	t.Run("NOTIF_SEND fails once", func(t *testing.T) {
		f := newFake()
		f.put(addr, sa)
		f.sendFails = []error{unix.EINTR}
		l, _ := newTestLoop(t, f, allowed())
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, ok := f.lastResp(); !ok || got.Error != 0 || len(f.connects) != 1 {
			t.Fatalf("response %+v (answered %v), connects %d; want the relayed connect's result answered", got, ok, len(f.connects))
		}
	})
	t.Run("ID_VALID fails once", func(t *testing.T) {
		f := newFake()
		f.put(addr, sa)
		f.idValidFails = []error{unix.EINTR}
		l, _ := newTestLoop(t, f, allowed())
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		if got, ok := f.lastResp(); !ok || got.Error != 0 || len(f.connects) != 1 {
			t.Fatalf("response %+v (answered %v), connects %d; want the relayed connect's result answered", got, ok, len(f.connects))
		}
	})
	t.Run("ID_VALID keeps failing: a decision kind is refused", func(t *testing.T) {
		f := newFake()
		f.put(addr, sa)
		f.idValidFailAll = unix.EBADF
		l, _ := newTestLoop(t, f, allowed())
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		got, ok := f.lastResp()
		if !ok || got.Error != -int32(refusalErrno) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
			t.Fatalf("response %+v (answered %v); want R10's errno, never no answer", got, ok)
		}
		if len(f.connects) != 0 {
			t.Errorf("connects %d; want none: nothing read was trusted", len(f.connects))
		}
	})
}
