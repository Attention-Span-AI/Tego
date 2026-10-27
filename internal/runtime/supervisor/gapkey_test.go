// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestAGapWhoseBinaryCannotBeReadIsOncePerProcess: the gap
// lines a run writes once per binary (an observe run's pending-frame refusal, an observed keyring or System V IPC
// syscall, a landlock-topology refusal) take the binary from /proc/<pid>/exe, which the kernel refuses for a
// non-dumpable target (the same ptrace check that answers its pidfd_getfd EPERM). Keyed by the empty binary, every
// such process of the run shared one line and the second one's calls went unrecorded. Each process whose binary cannot
// be read now gets its own line, naming no binary and carrying its pid; its threads and repeats share it.
func TestAGapWhoseBinaryCannotBeReadIsOncePerProcess(t *testing.T) {
	const target = 0x10000
	for _, tc := range []struct {
		name    string
		observe bool
		call    func(t *testing.T, tid int) *notif
		what    string
		why     string
	}{
		{"sendfile, observed", true, func(t *testing.T, tid int) *notif {
			return notifFor(nrFor(t, "sendfile"), tid, 5, 6, 0, 1<<20)
		}, record.GapRecord, ruleFDUnreadable + "-sendfile"},
		{"keyctl, observed", true, func(t *testing.T, tid int) *notif { return notifFor(nrFor(t, "keyctl"), tid) },
			record.GapRecord, gapWhyKeyring + "keyctl"},
		{"shmat, observed", true, func(t *testing.T, tid int) *notif { return notifFor(nrFor(t, "shmat"), tid) },
			record.GapRecord, gapWhySysVIPC + "shmat"},
		{"mount, refused", false, func(t *testing.T, tid int) *notif {
			return notifFor(nrFor(t, "mount"), tid, 0, target, 0, uint64(unix.MS_BIND), 0)
		}, record.GapEnforce, string(record.ReasonLandlockTopology)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.dupErr = unix.EPERM // non-dumpable: no descriptor and no exe link can be read
			f.put(target, cstr("/newroot"))
			f.tgid = map[int]int{42: 42, 44: 42, 43: 43}
			pol := observePolicy()
			if !tc.observe {
				pol = testPolicy(nil, nil, nil)
			}
			l, sink := newTestLoop(t, f, pol)
			for _, tid := range []int{42, 44, 43, 43} {
				l.handle(tc.call(t, tid))
			}
			gaps := map[int]int{}
			for _, ev := range sink.all() {
				if ev.Kind != record.KindGap {
					continue
				}
				var p record.GapPayload
				if err := ev.DecodePayload(&p); err != nil || p.What != tc.what || p.Why != tc.why || p.Binary != "" {
					t.Errorf("gap %+v (%v), want what=%s why=%s naming no binary", p, err, tc.what, tc.why)
				}
				if err := ev.Validate(); err != nil {
					t.Errorf("gap does not validate: %v", err)
				}
				gaps[ev.PID]++
			}
			if len(gaps) != 2 || gaps[42] != 1 || gaps[43] != 1 {
				t.Errorf("gap lines by pid %v, want one for each of the two processes (42 and 43)", gaps)
			}
		})
	}
}
