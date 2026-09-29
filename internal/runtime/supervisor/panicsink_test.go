// SPDX-License-Identifier: Apache-2.0

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// panickingSink is a Sink whose every Emit panics: a bug on the shared emit path (event, tgidOf, Sink.Emit)
// that a handler hit first and the recovery path then hit again.
type panickingSink struct{}

func (panickingSink) Emit(*record.Event) { panic("a bug on the emit path") }

// TestPanicInTheRecoveryPathIsContained is R25 (e): the recovery path re-runs the emit path to record its gap line,
// so a panic whose cause is on that path panicked again inside the deferred recover, escaped handle and the worker,
// and took the process down, the run's ledger writer with it. handle now returns, the task is answered
// fail-closed, and the loop answers the next notification.
func TestPanicInTheRecoveryPathIsContained(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.sink = panickingSink{}
	const nr = 4242
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
		name: "boom",
		fn:   func(l *Loop, n *notif) { l.emitGap(n, record.GapRecord, "first") },
	}
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("a panic escaped handle: %v", r)
			}
		}()
		l.handle(notifFor(nr, 42))
	}()
	got, ok := f.lastResp()
	if !ok {
		t.Fatal("the task was left unanswered")
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != -int32(unix.EACCES) {
		t.Errorf("response %+v, want the fail-closed EACCES", got)
	}
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{name: "fine", fn: func(l *Loop, n *notif) {
		l.respond(n, respContinue())
	}}
	l.handle(notifFor(nr, 43))
	if got, _ := f.lastResp(); got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
		t.Errorf("the next notification was answered %+v, want continued", got)
	}
}

// TestPanicInFinishIsContained is R25 (e) for finish's answer: handle defers finish before its recover, so
// finish runs once the recover has returned, with nothing around it. After a handler panic whose fail-closed
// answer panicked too (contained in recovered), finish retried that same answer path, and its second panic
// escaped handle and the worker and ended the process. The answer panics on every call here: the table has no
// policy, so respond's observe check dereferences nil before the answer is marked sent.
func TestPanicInFinishIsContained(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	const nr = 4242
	for _, tc := range []struct {
		name string
		fn   func(l *Loop, n *notif)
	}{
		{"handler panics", func(*Loop, *notif) { panic("a handler bug") }},
		{"handler returns unanswered", func(*Loop, *notif) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{name: "boom", fn: tc.fn}
			saved := l.table.Load()
			l.table.Store(&compiled{})
			func() {
				defer l.table.Store(saved)
				defer func() {
					if r := recover(); r != nil {
						t.Fatalf("a panic escaped handle: %v", r)
					}
				}()
				l.handle(notifFor(nr, 42))
			}()
			l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{name: "fine", fn: func(l *Loop, n *notif) {
				l.respond(n, respContinue())
			}}
			l.handle(notifFor(nr, 43))
			if got, ok := f.lastResp(); !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 {
				t.Errorf("the next notification was answered %+v, want continued", got)
			}
		})
	}
}
