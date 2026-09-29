// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestNamespaceArmRefusesAsLandlockTopology: an unshare or clone asking for a new mount or user namespace,
// and every setns, is refused EPERM, with a landlock-topology refused line naming the namespace flags (or
// setns's fd), as a mount is. The filter notifies only those flags; the handler names what it was given.
//
// Spec: docs/p0/supervisor.md R31.
func TestNamespaceArmRefusesAsLandlockTopology(t *testing.T) {
	for _, tc := range []struct {
		syscall, target string
		args            []uint64
	}{
		{"unshare", "CLONE_NEWNS", []uint64{unix.CLONE_NEWNS}},
		{"unshare", "CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWPID|CLONE_NEWNET",
			[]uint64{unix.CLONE_NEWNS | unix.CLONE_NEWUSER | unix.CLONE_NEWPID | unix.CLONE_NEWNET}},
		{"clone", "CLONE_NEWUSER", []uint64{unix.CLONE_NEWUSER | uint64(unix.SIGCHLD), 0, 0, 0, 0}},
		{"setns", "fd 7", []uint64{7, unix.CLONE_NEWNS}},
	} {
		t.Run(tc.syscall+" "+tc.target, func(t *testing.T) {
			f := newFake()
			f.links["/proc/4242/exe"] = "/usr/bin/unshare"
			l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
			l.handle(notifFor(nrFor(t, tc.syscall), 4242, tc.args...))
			got, ok := f.lastResp()
			if !ok || got.Error != -int32(unix.EPERM) || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 {
				t.Fatalf("response = %+v, want EPERM and no CONTINUE", got)
			}
			var gaps, refused int
			for _, ev := range sink.all() {
				switch ev.Kind {
				case record.KindGap:
					gaps++
				case record.KindRefused:
					refused++
					var p record.RefusedPayload
					if err := ev.DecodePayload(&p); err != nil || p.Op != tc.syscall || p.Target != tc.target {
						t.Errorf("refused payload = %+v (%v), want op %s target %s", p, err, tc.syscall, tc.target)
					}
					if ev.Reason != record.ReasonLandlockTopology || ev.Rule != ruleUnmatched {
						t.Errorf("refused reason/rule = %s/%s", ev.Reason, ev.Rule)
					}
				}
			}
			if gaps != 1 || refused != 1 {
				t.Errorf("gaps = %d, refused = %d; want one of each", gaps, refused)
			}
		})
	}
	// An observe run has no domain to stand in for: the call is continued and nothing is recorded.
	f := newFake()
	pol := testPolicy(nil, nil, nil)
	pol.Observe = true
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(nrFor(t, "unshare"), 4242, unix.CLONE_NEWUSER))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Errorf("observe: response = %+v, want CONTINUE", got)
	}
	if evs := sink.all(); len(evs) != 0 {
		t.Errorf("observe: %d events, want none", len(evs))
	}
}
