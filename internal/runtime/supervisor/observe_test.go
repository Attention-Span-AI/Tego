// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"testing"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// observePolicy is testPolicy for an --observe run: the contract is the same, only the mode differs.
func observePolicy() *Policy {
	pol := testPolicy([]agent.NetRule{netRule("api.example.com:443", "api.example.com", 443, "93.184.216.34")},
		[]agent.FSRule{{Path: "/work/proj", Kind: agent.FSWrite}, {Path: "/etc", Kind: agent.FSImplicit}}, nil)
	pol.Observe = true
	return pol
}

// wantContinue fails unless the one response the loop sent is CONTINUE.
func wantContinue(t *testing.T, f *fakeKernel) {
	t.Helper()
	got, ok := f.lastResp()
	if !ok || f.respCount() != 1 {
		t.Fatalf("responses = %d, want exactly one (I11)", f.respCount())
	}
	if got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE == 0 || got.Error != 0 {
		t.Fatalf("response = %+v, want CONTINUE: an observe run never refuses (R30)", got)
	}
}

// wantObserved fails unless ev is a valid action event recorded observed against rule, with no reason.
func wantObserved(t *testing.T, ev *record.Event, kind record.Kind, rule string) {
	t.Helper()
	if ev.Kind != kind || ev.Verdict != record.VerdictObserved || ev.Reason != "" || ev.Rule != rule {
		t.Errorf("event = %s %s rule %q reason %q, want %s observed rule %q with no reason (R30)",
			ev.Kind, ev.Verdict, ev.Rule, ev.Reason, kind, rule)
	}
	if err := ev.Validate(); err != nil {
		t.Errorf("event does not validate: %v", err)
	}
}

// TestObserveContinuesAConnectItWouldRefuse is R30 for the one kind this package is authoritative for: an
// undeclared destination is let through to the kernel, which performs the connect itself, and the line
// says which entry matched (none) without calling it a refusal.
func TestObserveContinuesAConnectItWouldRefuse(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrIn4("203.0.113.9", 443)
	f := newFake()
	f.put(addr, sa)
	l, sink := newTestLoop(t, f, observePolicy())
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	wantContinue(t, f)
	if len(f.connects) != 0 {
		t.Errorf("the loop performed the connect itself; a continued one is the kernel's to perform")
	}
	ev := sink.one(t)
	wantObserved(t, ev, record.KindNet, ruleUnmatched)
	var p record.NetPayload
	if err := ev.DecodePayload(&p); err != nil || p.Dst != "203.0.113.9:443" {
		t.Errorf("payload %+v (%v), want the destination the target named", p, err)
	}
	if f.fdBalance() != 0 {
		t.Errorf("%d descriptors left open (E28)", f.fdBalance())
	}
}

// TestObserveRelaysADeclaredConnect keeps I3 under observe: a destination the contract admits is still
// performed on the duplicate and answered with its real result, errors included. Only a refusal this loop
// chose becomes CONTINUE; a relayed errno is the syscall's own answer and must reach the target unchanged.
func TestObserveRelaysADeclaredConnect(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrIn4("93.184.216.34", 443)
	for _, tc := range []struct {
		name      string
		err       error
		wantErrno int32
	}{
		{"success", nil, 0},
		{"real error", unix.ECONNREFUSED, -int32(unix.ECONNREFUSED)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.put(addr, sa)
			f.connectErr = tc.err
			l, sink := newTestLoop(t, f, observePolicy())
			l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
			got, ok := f.lastResp()
			if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != tc.wantErrno {
				t.Fatalf("response = %+v, want the relayed result errno %d (I3)", got, tc.wantErrno)
			}
			if len(f.connects) != 1 {
				t.Errorf("connects on the duplicate = %d, want 1", len(f.connects))
			}
			wantObserved(t, sink.one(t), record.KindNet, "net[api.example.com:443]")
		})
	}
}

// TestObserveNeverFailsClosed is R5's fail-closed split under observe: an address this loop could not read
// refuses in an enforcing run, and continues here, still recorded with the marker that says why nothing
// could be matched.
func TestObserveNeverFailsClosed(t *testing.T) {
	f := newFake() // nothing mapped: every read faults
	l, sink := newTestLoop(t, f, observePolicy())
	l.handle(notifFor(connectNR(), 4242, 5, 0x9000, 16))
	wantContinue(t, f)
	wantObserved(t, sink.one(t), record.KindNet, ruleArgsUnreadable)
}

// TestObserveAnswersAnUnansweredDecisionWithContinue covers the last-resort answer finish gives a handler
// that returned without responding (I11): refusal in an enforcing run, CONTINUE here.
func TestObserveAnswersAnUnansweredDecisionWithContinue(t *testing.T) {
	f := newFake()
	l, _ := newTestLoop(t, f, observePolicy())
	n := notifFor(connectNR(), 4242, 5, 0x9000, 16)
	n.entry = entry{name: "connect"}
	l.finish(n)
	wantContinue(t, f)
}

// TestObserveRecordsExecAndFSObserved covers the record-only kinds: an exec no entry grants and a write
// outside every write entry keep their rule, lose the refusal and its reason, and are continued as always.
func TestObserveRecordsExecAndFSObserved(t *testing.T) {
	t.Run("exec", func(t *testing.T) {
		const pathAddr, argvAddr = 0x10000, 0x20000
		f := newFake()
		f.put(pathAddr, cstr("/usr/bin/curl"))
		execFixture(f, argvAddr, []string{"curl", "https://example.com"})
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(nrFor(t, "execve"), 42, pathAddr, argvAddr, 0))
		wantContinue(t, f)
		wantObserved(t, sink.one(t), record.KindExec, ruleUnmatched)
	})
	t.Run("fs", func(t *testing.T) {
		const pathAddr = 0x10000
		f := newFake()
		f.put(pathAddr, cstr("/etc/passwd"))
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(nrFor(t, "openat"), 42, argCWD, pathAddr, 0x241))
		wantContinue(t, f)
		wantObserved(t, sink.one(t), record.KindFS, "fs.implicit[/etc]")
	})
}

// TestObserveOffByDefault pins the other side: the same policy without Observe still refuses, so the flag
// and nothing else is what turns the loop record-only.
func TestObserveOffByDefault(t *testing.T) {
	const addr = 0x40000
	sa := sockaddrIn4("203.0.113.9", 443)
	f := newFake()
	f.put(addr, sa)
	pol := observePolicy()
	pol.Observe = false
	l, sink := newTestLoop(t, f, pol)
	l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
	if got, _ := f.lastResp(); got.Error != -int32(unix.EACCES) {
		t.Fatalf("response = %+v, want EACCES", got)
	}
	if ev := sink.one(t); ev.Verdict != record.VerdictRefused || ev.Reason != record.ReasonNetNotAllowed {
		t.Errorf("verdict/reason = %s/%s, want refused/net-not-allowed", ev.Verdict, ev.Reason)
	}
}

// TestObserveContinuesEveryFailClosedAnswer is I2's observe half for the fail-closed answers
// TestObserveNeverFailsClosed does not reach: a duplicate that could not be taken (fd-raced), an allowed
// connect past the relay ceiling (relay-limit) and a decision handler that panicked (R25). Each refuses
// in an enforcing run and is answered CONTINUE here. A refusal built as resp{errno: ...} rather than
// through respErrno would not be marked a refusal, and an observe run would refuse it silently.
func TestObserveContinuesEveryFailClosedAnswer(t *testing.T) {
	const addr = 0x40000
	declared := sockaddrIn4("93.184.216.34", 443)
	t.Run("fd-raced", func(t *testing.T) {
		f := newFake()
		f.put(addr, declared)
		f.dupErr = unix.EBADF
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(declared))))
		wantContinue(t, f)
		wantObserved(t, sink.one(t), record.KindNet, ruleFDRaced)
	})
	t.Run("relay-limit", func(t *testing.T) {
		f := newFake()
		f.put(addr, declared)
		l, sink := newTestLoop(t, f, observePolicy())
		l.relays.Store(l.relayCeiling()) // every relay slot is held by an outstanding syscall
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(declared))))
		wantContinue(t, f)
		if len(f.connects) != 0 {
			t.Errorf("connects = %d, want none: a relay past the ceiling is never started", len(f.connects))
		}
		wantObserved(t, sink.one(t), record.KindNet, ruleRelayLimit)
		if f.fdBalance() != 0 {
			t.Errorf("%d descriptors left open (E28)", f.fdBalance())
		}
	})
	// The pending-frame refusals that name no destination (refuseOp): continued, and never a refused line, which the
	// ledger would post to last-refusal.json and the agent's reason channel. The gap line in its
	// place is TestTheRunCannotCorkASocket's and TestAnObserveRunRecordsAPendingFrameRefusalItContinued's.
	for _, tc := range []struct {
		name string
		n    func(t *testing.T) *notif
		dup  unix.Errno
	}{
		{"setsockopt UDP_CORK", func(t *testing.T) *notif {
			return notifFor(nrFor(t, "setsockopt"), 4242, 3, unix.SOL_UDP, unix.UDP_CORK, 0x7000, 4)
		}, 0},
		{"sendfile whose descriptor is unreadable", func(t *testing.T) *notif { return notifFor(nrFor(t, "sendfile"), 4242, 5, 6, 0, 1<<20) }, unix.EPERM},
		{"splice whose descriptor is unreadable", func(t *testing.T) *notif {
			return notifFor(nrFor(t, "splice"), 4242, 6, 0, 5, 0, 1<<20, 0)
		}, unix.EPERM},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			f.dupErr = tc.dup
			l, sink := newTestLoop(t, f, observePolicy())
			l.handle(tc.n(t))
			wantContinue(t, f)
			for _, ev := range sink.all() {
				if ev.Kind == record.KindRefused {
					t.Errorf("a refused line in an observe run, which refused nothing: rule %s", ev.Rule)
				}
			}
		})
	}
	// Every other refused-kind answer: emit drops a refused line in an observe run, whose respond continued the call, so a
	// handler that writes one without asking observing() never puts a refusal that did not happen in the ledger. A
	// socket(2) of a family outside the allowlist is one; an observe run's filter never notifies it.
	t.Run("a refused line no observe filter asks for", func(t *testing.T) {
		f := newFake()
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(nrFor(t, "socket"), 4242, unix.AF_PACKET, unix.SOCK_RAW, 0))
		wantContinue(t, f)
		if lines := sink.all(); len(lines) != 0 {
			t.Errorf("%d lines (first %s), want none: nothing was refused", len(lines), lines[0].Kind)
		}
	})
	t.Run("panicked decision handler", func(t *testing.T) {
		f := newFake()
		l, sink := newTestLoop(t, f, observePolicy())
		const nr = 4245
		l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
			name: "boom", fn: func(*Loop, *notif) { panic("a bounds bug in a reader") },
		}
		l.handle(notifFor(nr, 42))
		wantContinue(t, f)
		ev := sink.one(t)
		var p record.GapPayload
		if err := ev.DecodePayload(&p); err != nil || ev.Kind != record.KindGap || p.Why != "handler-panic" {
			t.Errorf("event = %s %+v (%v), want the handler-panic gap, which an observe run leaves as it is", ev.Kind, p, err)
		}
	})
}

// TestObserveStillRelaysWhatItPerforms is I2's other observe half: R4's AF_UNSPEC disassociation and an
// allowed Fast-Open send are performed on the duplicate and answered with their real result, exactly as
// in an enforcing run (I3). Continued instead, the kernel would re-read a sockaddr a sibling thread can
// rewrite between the decision and that read, and the line would name a destination the kernel never
// used.
func TestObserveStillRelaysWhatItPerforms(t *testing.T) {
	const addr, bufAddr = 0x40000, 0x50000
	t.Run("connect AF_UNSPEC", func(t *testing.T) {
		f := newFake()
		sa := unspecSockaddr("203.0.113.9", 443)
		f.put(addr, sa)
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(connectNR(), 4242, 5, addr, uint64(len(sa))))
		got, ok := f.lastResp()
		if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Error != 0 {
			t.Fatalf("response = %+v, want the relayed result (I3)", got)
		}
		if len(f.connects) != 1 || string(f.connects[0]) != string(sa) {
			t.Errorf("connects = %q, want the target's own AF_UNSPEC bytes once", f.connects)
		}
		wantObserved(t, sink.one(t), record.KindNet, ruleUnspec)
	})
	t.Run("sendto MSG_FASTOPEN to a declared host", func(t *testing.T) {
		f := newFake()
		f.sockType = unix.SOCK_STREAM
		sa := sockaddrIn4("93.184.216.34", 443)
		f.put(addr, sa)
		f.put(bufAddr, []byte("ping"))
		l, sink := newTestLoop(t, f, observePolicy())
		l.handle(notifFor(sendToNR(), 4242, 5, bufAddr, 4, uint64(unix.MSG_FASTOPEN), addr, uint64(len(sa))))
		got, ok := f.lastResp()
		if !ok || got.Flags&unix.SECCOMP_USER_NOTIF_FLAG_CONTINUE != 0 || got.Val != 4 {
			t.Fatalf("response = %+v, want the relayed byte count (I3)", got)
		}
		if len(f.sends) != 1 || string(f.sends[0].payload) != "ping" {
			t.Errorf("sends = %+v, want the target's bytes once on the duplicate", f.sends)
		}
		wantObserved(t, sink.one(t), record.KindNet, "net[api.example.com:443]")
	})
}
