// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
	"golang.org/x/sys/unix"
)

// TestConnectFromASecondaryThreadIsNotRefused is the bug this file exists for.
//
// A seccomp notification's Pid is a thread id: the kernel fills it with task_pid_vnr(current). The
// duplicate path passed it straight to pidfd_open, which without PIDFD_THREAD requires a thread-group
// leader, so every notification raised by a worker thread got ENOENT. A failed duplicate is a refusal,
// so a threaded agent — a Python ThreadPoolExecutor, a Node worker, a Go program on any thread but the
// first — had every connect refused with EACCES against a contract that named the host, and the ledger
// blamed an fd race that never happened. Verified against this kernel: pidfd_open on a non-leader tid
// returns ENOENT, and the same call with PIDFD_THREAD succeeds.
func TestConnectFromASecondaryThreadIsNotRefused(t *testing.T) {
	const tgid, worker = 4242, 4250

	newLoop := func(leadersOnly bool) (*Loop, *fakeKernel, *testSink) {
		f := newFake()
		f.leadersOnly = leadersOnly
		f.tgid[worker] = tgid // the notification comes from a thread that is not its group's leader
		l, sink := newTestLoop(t, f, testPolicy(
			[]agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "10.1.2.3")}, nil, nil))
		return l, f, sink
	}

	cases := []struct {
		name        string
		leadersOnly bool
		wantOpens   []int
	}{
		// Linux 6.9 and later: PIDFD_THREAD names the trapping task, so one open is enough.
		{"the thread form works", false, []int{worker}},
		// Below 6.9 the flag does not exist, so the thread id fails and the group leader answers.
		{"falls back to the thread group", true, []int{worker, tgid}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			l, f, sink := newLoop(tc.leadersOnly)
			const addr = 0x40000
			f.put(addr, sockaddrIn4("10.1.2.3", 443))
			l.handle(notifFor(connectNR(), worker, 3, addr, 16))

			evs := sink.all()
			if len(evs) != 1 {
				t.Fatalf("%d events, want one net event", len(evs))
			}
			if evs[0].Verdict == record.VerdictRefused {
				t.Fatalf("a connect from a worker thread was refused: rule=%q reason=%q",
					evs[0].Rule, evs[0].Reason)
			}
			if got := f.pidfdOpenedFor; len(got) != len(tc.wantOpens) {
				t.Fatalf("pidfd_open called for %v, want %v", got, tc.wantOpens)
			} else {
				for i := range got {
					if got[i] != tc.wantOpens[i] {
						t.Errorf("pidfd_open call %d was for %d, want %d", i, got[i], tc.wantOpens[i])
					}
				}
			}
		})
	}
}

// TestPidfdOpenGivesUpWhenTheTaskIsGone keeps the fallback from masking a target that really has
// exited: a leader whose own id fails is not retried under another name.
func TestPidfdOpenGivesUpWhenTheTaskIsGone(t *testing.T) {
	f := newFake()
	f.dupErr = unix.ESRCH
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	if _, err := l.openTargetPidFD(notifFor(connectNR(), 4242, 3)); err == nil {
		t.Fatal("a target that is gone must not yield a pidfd")
	}
	if n := len(f.pidfdOpenedFor); n > 2 {
		t.Errorf("pidfd_open was called %d times for one gone target", n)
	}
}

// TestTgidFallbackRefusesAThreadWithItsOwnFDTable pins that the below-6.9 fallback never duplicates from the
// leader for a thread whose descriptor table is not the leader's. pidfd_getfd against the leader succeeds
// whenever the leader has a file under the same number, so without the check the connect was decided and
// relayed on a socket the thread never named. Such a thread, or a kernel whose kcmp cannot say (no
// CONFIG_KCMP), is refused and nothing is connected. The line says fd-unreadable, not fd-raced: either is a lasting
// property of the thread or the kernel, so every connect of that thread is refused alike, and no race happened.
func TestTgidFallbackRefusesAThreadWithItsOwnFDTable(t *testing.T) {
	const tgid, worker = 4242, 4250
	for _, tc := range []struct {
		name    string
		prepare func(f *fakeKernel)
	}{
		{"unshared CLONE_FILES", func(f *fakeKernel) { f.ownFiles = map[int]bool{worker: true} }},
		{"kcmp unavailable", func(f *fakeKernel) { f.kcmpErr = unix.ENOSYS }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.leadersOnly = true
			f.tgid[worker] = tgid
			tc.prepare(f)
			l, sink := newTestLoop(t, f, testPolicy(
				[]agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "10.1.2.3")}, nil, nil))
			const addr = 0x40000
			f.put(addr, sockaddrIn4("10.1.2.3", 443))
			l.handle(notifFor(connectNR(), worker, 3, addr, 16))

			if len(f.connects) != 0 {
				t.Fatalf("connected %d times on the leader's descriptor", len(f.connects))
			}
			got, ok := f.lastResp()
			if !ok || got.Error != -int32(refusalErrno) {
				t.Errorf("response = %+v, want the refusal errno", got)
			}
			ev := sink.one(t)
			if ev.Verdict != record.VerdictRefused || ev.Rule != ruleFDUnreadable {
				t.Errorf("event = {verdict=%s rule=%s}, want refused %s", ev.Verdict, ev.Rule, ruleFDUnreadable)
			}
			if open := f.fdBalance(); open != 0 {
				t.Errorf("%d descriptors left open: the leader's pidfd leaked", open)
			}
		})
	}
}
