// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// sysVIPCSyscalls are the eleven System V IPC syscalls the filter notifies.
var sysVIPCSyscalls = []string{"shmget", "shmat", "shmctl", "semget", "semop", "semtimedop", "semctl",
	"msgget", "msgsnd", "msgrcv", "msgctl"}

// TestSysVIPCIsRefused is supervisor.md R34 (the refusal): a segment and a queue made outside the run were attached and read inside it at tiers 1 and 2,
// and the ledger had no line about it. Every System V IPC syscall is now refused with EPERM and recorded refused
// reason=read-denied rule=sysv-ipc, with the syscall as the op.
func TestSysVIPCIsRefused(t *testing.T) {
	for _, sc := range sysVIPCSyscalls {
		t.Run(sc, func(t *testing.T) {
			f := newFake()
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nrFor(t, sc), 4242))
			got, ok := f.lastResp()
			if !ok || got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want EPERM and no CONTINUE", got)
			}
			ev := sink.one(t)
			if ev.Kind != record.KindRefused || ev.Reason != record.ReasonReadDenied || ev.Rule != ruleSysVIPC {
				t.Errorf("event = %s reason=%s rule=%s, want refused/read-denied/sysv-ipc", ev.Kind, ev.Reason, ev.Rule)
			}
			var p record.RefusedPayload
			if err := ev.DecodePayload(&p); err != nil || p.Op != sc {
				t.Errorf("refused payload = %+v (%v), want op %q", p, err, sc)
			}
			if err := ev.Validate(); err != nil {
				t.Errorf("refused event does not validate: %v", err)
			}
		})
	}
}

// TestSysVIPCUseIsVisibleWhenContinued is supervisor.md R34 (the continue path): a contract that declares ipc: true, and an observe run, has System V
// IPC continued, and the ledger still says so: one gap what=record why=sysv-ipc-<syscall> per binary and
// syscall, so a learn pass over an observe run sees that the agent needs ipc: true.
func TestSysVIPCUseIsVisibleWhenContinued(t *testing.T) {
	for _, tc := range []struct {
		name string
		pol  func() *Policy
	}{
		{"ipc: true", func() *Policy { return contractPolicy(&agent.Contract{IPC: true}, nil, nil) }},
		{"observe", func() *Policy {
			pol := testPolicy(nil, nil, nil)
			pol.Observe = true
			return pol
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.links["/proc/4242/exe"] = "/usr/lib/postgresql/bin/postgres"
			l, sink := newTestLoop(t, f, tc.pol())
			for _, sc := range []string{"shmget", "shmat", "shmget"} {
				l.handle(notifFor(nrFor(t, sc), 4242))
				if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
					t.Fatalf("%s: response = %+v, want CONTINUE", sc, got)
				}
			}
			evs := sink.all()
			if len(evs) != 2 {
				t.Fatalf("%d events, want one gap per binary and syscall (2): %+v", len(evs), evs)
			}
			for i, want := range []string{"sysv-ipc-shmget", "sysv-ipc-shmat"} {
				var p record.GapPayload
				if err := evs[i].DecodePayload(&p); err != nil {
					t.Fatal(err)
				}
				if evs[i].Kind != record.KindGap || p.What != record.GapRecord || p.Why != want || p.Binary != "/usr/lib/postgresql/bin/postgres" {
					t.Errorf("event %d = %s %+v, want gap what=record why=%s", i, evs[i].Kind, p, want)
				}
			}
		})
	}
}

// TestKeyringOptInDoesNotOpenSysVIPC is supervisor.md R34 (the two opt-ins are separate): the two opt-ins are separate; keyring: true leaves System V IPC refused.
func TestKeyringOptInDoesNotOpenSysVIPC(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, contractPolicy(&agent.Contract{Keyring: true}, nil, nil))
	l.handle(notifFor(nrFor(t, "shmat"), 4242))
	if got, _ := f.lastResp(); got.Error != -int32(unix.EPERM) {
		t.Fatalf("response = %+v, want EPERM", got)
	}
}
