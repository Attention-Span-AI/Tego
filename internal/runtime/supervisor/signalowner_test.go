// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"encoding/binary"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestSignalScopeReadsTheIoctlOwner: below Landlock ABI 6, ioctl(FIOSETOWN) and ioctl(SIOCSPGRP) set a
// socket's signal owner as F_SETOWN does (sock_ioctl → f_setown), and with O_ASYNC a byte to the peer would
// signal that owner. The owner is an int in the caller's memory: a pid when positive, a process group when
// negative, none when 0. One outside the run, or one that cannot be read, is refused EPERM with a
// signal-scope line; another ioctl request is not this arm's and is continued.
//
// Spec: docs/p0/supervisor.md R33.
func TestSignalScopeReadsTheIoctlOwner(t *testing.T) {
	const (
		agent    = 100 // the caller, in the run
		child    = 101 // in the run
		launcher = 50  // outside the run
		ownerAt  = 0x1000
	)
	owner := func(v int32) []byte {
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(v))
		return b
	}
	for _, tc := range []struct {
		name  string
		req   uint64
		owner []byte // nil: nothing mapped at the pointer
		allow bool
	}{
		{"FIOSETOWN to a pid in the run", ioctlFIOSETOWN, owner(child), true},
		{"FIOSETOWN to the launcher", ioctlFIOSETOWN, owner(launcher), false},
		{"FIOSETOWN to a group all in the run", ioctlFIOSETOWN, owner(-child), true},
		{"FIOSETOWN to the launcher's group", ioctlFIOSETOWN, owner(-launcher), false},
		// Group 102's leader is in the run and a process outside it is a member: decided as the group.
		{"FIOSETOWN to a mixed group led from the run", ioctlFIOSETOWN, owner(-102), false},
		{"FIOSETOWN cleared", ioctlFIOSETOWN, owner(0), true},
		{"FIOSETOWN with an unreadable owner", ioctlFIOSETOWN, nil, false},
		{"SIOCSPGRP to a pid in the run", ioctlSIOCSPGRP, owner(child), true},
		{"SIOCSPGRP to the launcher's group", ioctlSIOCSPGRP, owner(-launcher), false},
		{"SIOCSPGRP with an unreadable owner", ioctlSIOCSPGRP, nil, false},
		{"another request (FIONREAD)", 0x541b, owner(launcher), true},
		// The kernel takes cmd as an unsigned int and the filter matches its low 32 bits: junk in the high
		// half is still FIOSETOWN/SIOCSPGRP to both, so the handler must decide it too.
		{"FIOSETOWN with high bits set, to the launcher", 0x1_0000_8901, owner(launcher), false},
		{"SIOCSPGRP with high bits set, to the launcher's group", 0xdead_0000_8902, owner(-launcher), false},
		{"FIOSETOWN with high bits set, to a pid in the run", 0xffff_ffff_0000_8901, owner(child), true},
		{"FIONREAD with high bits set", 0x1_0000_541b, owner(launcher), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.cgroups = map[int]string{agent: "/run.scope", child: "/run.scope/sub", launcher: "/other.scope"}
			f.pgrps = map[int]int{agent: launcher, child: child, launcher: launcher, 102: 102, 60: 102}
			f.cgroups[102], f.cgroups[60] = "/run.scope", "/other.scope"
			if tc.owner != nil {
				f.put(ownerAt, tc.owner)
			}
			pol := testPolicy(nil, nil, nil)
			pol.Cgroup = "/run.scope"
			l, sink := newTestLoop(t, f, pol)
			l.handle(notifFor(ioctlNR(), agent, 3, tc.req, ownerAt))
			got, ok := f.lastResp()
			if !ok {
				t.Fatal("no response")
			}
			if cont := got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0; cont != tc.allow {
				t.Fatalf("response %+v: continued=%v, want %v", got, cont, tc.allow)
			}
			evs := sink.all()
			if tc.allow {
				if len(evs) != 0 {
					t.Errorf("a continued ioctl was recorded: %d events", len(evs))
				}
				return
			}
			if got.Error != -int32(unix.EPERM) {
				t.Errorf("refused with %d, want EPERM", got.Error)
			}
			if len(evs) != 1 || evs[0].Kind != record.KindRefused || evs[0].Rule != ruleSignalScope {
				t.Fatalf("events %+v, want one refused signal-scope line", evs)
			}
			var p record.RefusedPayload
			if err := evs[0].DecodePayload(&p); err != nil || p.Op != "ioctl" {
				t.Errorf("payload %+v (%v), want op ioctl", p, err)
			}
			if tc.owner != nil && p.Target == (sigTarget{}).String() {
				t.Errorf("target %q: the line names the empty pre-read target, not the owner read from memory", p.Target)
			}
		})
	}
}

// TestSignalTargetIgnoresTheHighHalfOfEveryScalarTheFilterMatches holds signalTarget to the filter's view
// of each argument it matches: signalScopeTest loads fcntl's cmd and ioctl's request with a 4-byte load, and
// the kernel takes both as 32-bit ints, so a caller that sets junk above bit 31 is still notified and still
// reaches F_SETOWN / FIOSETOWN in the kernel. The handler must decide such a call, never answer it as one
// the arm does not own (a CONTINUE with no owner read).
//
// Spec: docs/p0/supervisor.md R33.
func TestSignalTargetIgnoresTheHighHalfOfEveryScalarTheFilterMatches(t *testing.T) {
	const junk = 0xdead_beef_0000_0000
	for _, tc := range []struct {
		op   string
		args [6]uint64
	}{
		{"ioctl", [6]uint64{3, junk | ioctlFIOSETOWN}},
		{"ioctl", [6]uint64{3, junk | ioctlSIOCSPGRP}},
		{"fcntl", [6]uint64{3, junk | uint64(unix.F_SETOWN), 50}},
		{"fcntl", [6]uint64{3, junk | uint64(unix.F_SETOWN_EX), 0x1000}},
	} {
		if _, ok := signalTarget(tc.op, tc.args); !ok {
			t.Errorf("signalTarget(%s, %#x) is not decided, but the filter notifies it and the kernel runs it as the low 32 bits", tc.op, tc.args[1])
		}
	}
}
