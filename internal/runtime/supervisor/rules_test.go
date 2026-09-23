// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestResolverExceptionNeedsConfiguredResolver is E32: an empty Policy.Resolver list (no /etc/resolv.conf
// entries at run start) makes R14's "port 53 is always allow" exception match nothing, so a destination on
// port 53 falls through to ordinary R7 host:port matching instead of becoming an implicit allow. Every
// existing connect test that exercises the resolver exception (TestConnectDecisions, the golden fixtures)
// configures at least one resolver address; none drives the case the spec calls out by name: "not a crash,
// not a default-allow" when nothing is configured yet.
func TestResolverExceptionNeedsConfiguredResolver(t *testing.T) {
	f := newFake()
	f.put(0x40000, sockaddrIn4("127.0.0.53", 53))
	// No net.allow entries and no resolver addresses: nothing should ever admit this destination.
	l, sink := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.handle(notifFor(connectNR(), 4242, 5, 0x40000, 16))

	got, ok := f.lastResp()
	if !ok || got.Error != -int32(unix.EACCES) {
		t.Fatalf("response = %+v, want EACCES: an empty resolver list must not become a default allow (E32)", got)
	}
	ev := sink.one(t)
	if ev.Verdict != record.VerdictRefused || ev.Rule != ruleUnmatched {
		t.Errorf("verdict/rule = %s/%s, want refused/%s: R14's exception matches nothing when Resolver is empty (E32)",
			ev.Verdict, ev.Rule, ruleUnmatched)
	}
}

// emitOrderSink records, for the one event it is handed, whether the fake listener had already recorded a
// response at the moment Emit ran.
type emitOrderSink struct {
	f             *fakeKernel
	respondedYet  *bool
	emitWasCalled *bool
}

func (s emitOrderSink) Emit(*record.Event) {
	*s.emitWasCalled = true
	*s.respondedYet = s.f.respCount() >= 1
}

// TestEmitAfterRespond is R23/I5: the order is always decide -> respond (NOTIF_SEND) -> emit, and Sink.Emit
// is fire-and-forget (P0-DESIGN §2.4) precisely because nothing here ever waits on it. That guarantee only
// holds if the response has already gone out by the time Emit runs; if a handler ever emitted first, a slow
// consumer downstream of Sink would delay the very response this package promises never to delay. No
// existing test observes the two calls' relative order (each only checks that a response happened and that
// an event happened), so a regression that swapped them would pass every other test in this package.
func TestEmitAfterRespond(t *testing.T) {
	tests := []struct {
		name  string
		rules []agent.NetRule
		setup func(f *fakeKernel)
		n     func(t *testing.T) *notif
	}{
		{
			name:  "refused connect",
			setup: func(f *fakeKernel) { f.put(0x40000, sockaddrIn4("203.0.113.9", 443)) },
			n:     func(t *testing.T) *notif { return notifFor(connectNR(), 4242, 5, 0x40000, 16) },
		},
		{
			name:  "allowed connect",
			rules: []agent.NetRule{netRule("api:443", "api", 443, "93.184.216.34")},
			setup: func(f *fakeKernel) { f.put(0x40000, sockaddrIn4("93.184.216.34", 443)) },
			n:     func(t *testing.T) *notif { return notifFor(connectNR(), 4242, 5, 0x40000, 16) },
		},
		{
			name:  "record-only write-open",
			setup: func(f *fakeKernel) { f.put(0x10000, cstr("/tmp/x")) },
			n: func(t *testing.T) *notif {
				return notifFor(nrFor(t, "openat"), 4242, argCWD, 0x10000, 0x241)
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			tc.setup(f)
			var respondedYet, emitted bool
			sink := emitOrderSink{f: f, respondedYet: &respondedYet, emitWasCalled: &emitted}
			l, err := New(testListener(), testPolicy(tc.rules, nil, nil), sink, Options{kernel: f, Workers: 1})
			if err != nil {
				t.Fatal(err)
			}
			l.handle(tc.n(t))
			if !emitted {
				t.Fatal("Sink.Emit was never called; the fixture should have produced exactly one event")
			}
			if f.respCount() != 1 {
				t.Fatalf("responses = %d, want exactly one", f.respCount())
			}
			if !respondedYet {
				t.Error("Sink.Emit ran before NOTIF_SEND: the order must be decide -> respond -> emit (R23, I5)")
			}
		})
	}
}

// TestWorkerPoolBoundsConcurrency: Options.Workers goroutines each run a synchronous
// receive->dispatch->respond loop, so at most Workers notifications are ever mid-handler at once, and a
// (Workers+1)th queued notification only starts once a busy worker frees up. E23 is the Workers=1 edge:
// full serialization. Nothing in this package's suite currently drives Loop.Run with a handler slow enough
// to observe concurrency at all, so an accidental switch to "one goroutine per notification" (which would
// still pass every response-shape and event test in this package) would not be caught anywhere.
func TestWorkerPoolBoundsConcurrency(t *testing.T) {
	tests := []struct {
		name    string
		workers int
		count   int
	}{
		{name: "Workers=1 fully serializes (E23)", workers: 1, count: 3},
		{name: "Workers=2 bounds concurrency at two", workers: 2, count: 3},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake()
			const nr = 5000
			for i := 0; i < tc.count; i++ {
				f.queue(sysNotif{ID: uint64(i + 1), Pid: 42, Data: sysData(nr)})
			}
			var running, peak atomic.Int64
			release := make(chan struct{})
			l, err := New(testListener(), testPolicy(nil, nil, nil), &testSink{}, Options{kernel: f, Workers: tc.workers})
			if err != nil {
				t.Fatal(err)
			}
			l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: nr}] = entry{
				name: "block",
				fn: func(l *Loop, n *notif) {
					cur := running.Add(1)
					for {
						p := peak.Load()
						if cur <= p || peak.CompareAndSwap(p, cur) {
							break
						}
					}
					<-release // held open until the test releases it, so concurrency is observable
					running.Add(-1)
					l.respond(n, respContinue())
				},
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- l.Run(ctx) }()

			// >= rather than ==: a pool that (wrongly) let more than Workers handlers run at once would
			// still cross this threshold, and the very next check is what names that failure specifically
			// instead of letting the test time out on an equality that can never hold.
			waitFor(t, func() bool { return running.Load() >= int64(tc.workers) })
			if got := running.Load(); got > int64(tc.workers) {
				t.Fatalf("running = %d, want at most Workers=%d in flight at once (R21)", got, tc.workers)
			}
			// One token per queued notification: each blocked handler reads exactly one, and a worker that
			// frees up immediately picks up the next queued notification and blocks again, so sending all
			// tc.count tokens up front safely drains the whole queue without any extra synchronization.
			for i := 0; i < tc.count; i++ {
				release <- struct{}{}
			}
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Fatalf("Run: %v", err)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("Run did not return")
			}
			if peak.Load() > int64(tc.workers) {
				t.Errorf("peak concurrent handlers = %d, want at most Workers=%d (R21)", peak.Load(), tc.workers)
			}
			if peak.Load() != int64(tc.workers) {
				t.Errorf("peak concurrent handlers = %d, want exactly Workers=%d: the pool must actually reach its bound", peak.Load(), tc.workers)
			}
			if f.respCount() != tc.count {
				t.Errorf("responses = %d, want %d", f.respCount(), tc.count)
			}
		})
	}
}

// TestMetricsCountsUnansweredAndPanicked: metrics.notifications increments once per notification
// received off the listener, including one that turns out already gone (R19 abandon, no response at all)
// and one whose handler panics (R25, recovered into a fail-closed response). Every existing metrics test
// either drives Loop.handle directly and increments the counter itself (bypassing the real increment site
// in the worker loop) or only exercises the happy path through Run, so the "still counted" half of R24 —
// the reason run_end.supervisor.notifications can be compared against a kernel-side count at all — has no
// test that would notice if a future change moved the increment to only fire on a successful response.
func TestMetricsCountsUnansweredAndPanicked(t *testing.T) {
	f := newFake()
	f.stale[1] = true // R19: this notification's target is already gone when it is decided
	f.queue(sysNotif{ID: 1, Pid: 42, Data: sysData(connectNR(), 5, 0x40000, 16)})
	const panicNR = 5001
	f.queue(sysNotif{ID: 2, Pid: 43, Data: sysData(panicNR)})

	l, _ := newTestLoop(t, f, testPolicy(nil, nil, nil))
	l.dispatch[dispatchKey{arch: nativeAuditArch(), nr: panicNR}] = entry{
		name: "boom",
		fn:   func(*Loop, *notif) { panic("simulated handler bug") },
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()

	waitFor(t, func() bool { return f.respCount() == 1 })
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not return")
	}

	if got := l.Metrics().Notifications; got != 2 {
		t.Errorf("notifications = %d, want 2: the R19 abandon and the R25 panic were both received off the listener (R24)", got)
	}
	if f.respCount() != 1 {
		t.Errorf("responses = %d, want exactly 1: only the panicked notification's fail-closed answer was ever sent", f.respCount())
	}
}

// TestPolicyLookupIsPerNotification: every read this package makes resolves against notif.pid fresh
// on each notification rather than a pid fixed once for the Loop's life. That is what a nested run needs —
// its notifications arrive at the ancestor's Loop (R20's EBUSY routing) carrying a different pid and a
// different /proc/<pid>/cwd than the ancestor's own — and it is what tells two threads of the same run's own
// PATH search apart (R28). This drives two connects with different pids and different cwds through one
// Loop and checks each resolves against its own process, not the first one seen.
func TestPolicyLookupIsPerNotification(t *testing.T) {
	f := newFake()
	f.links["/proc/100/cwd"] = "/work/a"
	f.links["/proc/200/cwd"] = "/work/b"
	sa := sockaddrUn("pg.sock")
	f.put(0x40000, sa)
	rules := []agent.NetRule{
		unixRuleOf("unix:/work/a/pg.sock", "/work/a/pg.sock", false),
		unixRuleOf("unix:/work/b/pg.sock", "/work/b/pg.sock", false),
	}
	l, sink := newTestLoop(t, f, testPolicy(rules, nil, nil))
	l.handle(notifFor(connectNR(), 100, 5, 0x40000, uint64(len(sa))))
	l.handle(notifFor(connectNR(), 200, 5, 0x40000, uint64(len(sa))))

	evs := sink.all()
	if len(evs) != 2 {
		t.Fatalf("events = %d, want 2", len(evs))
	}
	if evs[0].Verdict != record.VerdictAllow || evs[0].Rule != "net[unix:/work/a/pg.sock]" {
		t.Errorf("pid 100: rule/verdict = %s/%s, want allow/net[unix:/work/a/pg.sock]", evs[0].Rule, evs[0].Verdict)
	}
	if evs[1].Verdict != record.VerdictAllow || evs[1].Rule != "net[unix:/work/b/pg.sock]" {
		t.Errorf("pid 200: rule/verdict = %s/%s, want allow/net[unix:/work/b/pg.sock]: a cached first pid "+
			"would resolve this against /work/a instead (R20)", evs[1].Rule, evs[1].Verdict)
	}
}
