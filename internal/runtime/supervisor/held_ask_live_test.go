// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// liveBlockOf is a live Set holding one block of kind on value, placed from a terminal.
func liveBlockOf(kind liveblock.Kind, value string) *liveblock.Set {
	return liveblock.CompileEntries([]liveblock.Entry{{Kind: kind, Value: value, By: "uid:1 pid:2 cli", At: time.Now()}}, 2, liveblock.Resolved{})
}

// heldLiveRefusal judges the one line and the answer of a held open a live block refused after it was asked about:
// EACCES, refused read-denied under the block's rule, decided by that rule (never the gate, never a person).
func heldLiveRefusal(t *testing.T, f *fakeKernel, lines []*record.Event, rule string) {
	t.Helper()
	res, _ := f.lastResp()
	if res.Error != -int32(unix.EACCES) {
		t.Fatalf("answer %+v: want EACCES", res)
	}
	if len(lines) != 1 || lines[0].Kind != record.KindFS || lines[0].Verdict != record.VerdictRefused ||
		lines[0].Reason != record.ReasonReadDenied || lines[0].Rule != rule || lines[0].Authority == record.AuthorityHuman ||
		lines[0].Authority == record.AuthorityGate {
		t.Fatalf("lines %+v: want one fs line refused read-denied by %s", lines, rule)
	}
}

// TestHeldAskApprovedAfterALiveBlockIsRefused: a read asked about before a live read block of its file
// landed, and approved after (Allow once on the dashboard's card, 250 ms after Confirm: never allow), is refused when
// the answer comes back, under the block's rule, and nothing is opened or delivered; before, the approval completed it
// and the agent read the file the page called never readable. It holds for a hold of this loop's own pin (an
// fs.ask_read entry, the demo's) and for a gate-held ask on the deputy's pinned object, for a read and a path block. A
// write block, which leaves reads alone, leaves the approval standing.
func TestHeldAskApprovedAfterALiveBlockIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		kind    liveblock.Kind
		refuses bool
	}{
		{"a read block", liveblock.KindRead, true},
		{"a path block", liveblock.KindPath, true},
		{"a write block", liveblock.KindWrite, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Run("fs.ask_read hold", func(t *testing.T) {
				x := newAskReadFixture(t)
				var cur atomic.Pointer[liveblock.Set]
				x.live = cur.Load
				l, sink, asked := x.loop(t, func(ask.Request) ask.Decision {
					cur.Store(liveBlockOf(tc.kind, x.vault)) // lands while the person decides
					return ask.Decision{Approved: true, By: "uid:1 pid:2"}
				})
				n := x.open(t, l, x.secret, unix.O_RDONLY|unix.O_CLOEXEC)
				if len(*asked) != 1 {
					t.Fatalf("asked %d times, want once", len(*asked))
				}
				if !tc.refuses {
					if evs := sink.all(); len(x.k.completed) != 1 || len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
						t.Fatalf("completed %v, lines %+v: a write block leaves an approved read standing", x.k.completed, evs)
					}
					return
				}
				if len(x.k.completed) != 0 || len(x.k.delivered) != 0 || !n.answered {
					t.Fatalf("completed %v, delivered %q, answered %v: want nothing opened under the block", x.k.completed, x.k.delivered, n.answered)
				}
				heldLiveRefusal(t, x.f, sink.all(), liveblock.Rule(tc.kind, x.vault))
			})
			t.Run("gate-held ask", func(t *testing.T) {
				x := newHeldAskFixture(t)
				var cur atomic.Pointer[liveblock.Set]
				x.live = cur.Load
				l, sink, asked := x.loop(t, func(ask.Request) ask.Decision {
					cur.Store(liveBlockOf(tc.kind, x.target))
					return ask.Decision{Approved: true, By: "uid:1 pid:2"}
				})
				n := x.open(t, l, x.target, unix.O_RDONLY|unix.O_CLOEXEC)
				if len(*asked) != 1 {
					t.Fatalf("asked %d times, want once", len(*asked))
				}
				if !tc.refuses {
					if len(x.dep.opened) != 1 || len(x.k.heldDelivered) != 1 {
						t.Fatalf("deputy opens %v, delivered %q: a write block leaves an approved read standing", x.dep.opened, x.k.heldDelivered)
					}
					return
				}
				if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 || !n.answered {
					t.Fatalf("deputy opens %v, delivered %q, answered %v: want nothing opened under the block", x.dep.opened, x.k.heldDelivered, n.answered)
				}
				heldLiveRefusal(t, x.f, sink.all(), liveblock.Rule(tc.kind, x.target))
			})
		})
	}
}

// TestPendingAskWithdrawnWhenALiveBlockLands: a live block that lands while a held open waits for its person takes
// the request back at once, so the dashboard's card and `tego ask` drop it, and the open is refused under the block;
// nobody is left asked about an open no answer could complete. Through the real broker for an fs.ask_read hold (its
// answer line says ask-unavailable by cancelled, its list is empty), and for a gate-held ask on the deputy's pin.
func TestPendingAskWithdrawnWhenALiveBlockLands(t *testing.T) {
	t.Run("fs.ask_read hold, the real broker", func(t *testing.T) {
		x := newAskReadFixture(t)
		var cur atomic.Pointer[liveblock.Set]
		var mu sync.Mutex
		var lines []ask.Event
		runDir := t.TempDir()
		broker, err := ask.New(runDir, ask.Options{UID: uint32(os.Getuid()), Timeout: time.Minute,
			Authorize: func(ask.Peer) error { return nil },
			Emit: func(e ask.Event) error {
				mu.Lock()
				defer mu.Unlock()
				lines = append(lines, e)
				return nil
			}})
		if err != nil {
			t.Fatal(err)
		}
		defer broker.Close()
		sink := &testSink{}
		l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, LiveBlocks: cur.Load, Ask: broker.Request})
		if err != nil {
			t.Fatal(err)
		}
		defer l.closeAskScopes()
		x.addr += 0x2000
		x.f.put(0x10000+x.addr, cstr(x.secret))
		n := notifFor(nrFor(t, "openat"), 42, argCWD, 0x10000+x.addr, unix.O_RDONLY)
		done := make(chan struct{})
		go func() { l.handle(n); close(done) }()
		var items []ask.Summary
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && len(items) == 0; time.Sleep(5 * time.Millisecond) {
			if items, err = ask.ListFor(context.Background(), runDir, os.Getpid()); err != nil {
				t.Fatal(err)
			}
		}
		if len(items) != 1 || items[0].Op != ask.OpRead {
			t.Fatalf("pending %+v: want the held read", items)
		}
		cur.Store(liveBlockOf(liveblock.KindRead, x.vault))
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("the held read was still asked about 5 s after a read block of its file landed")
		}
		if items, err = ask.ListFor(context.Background(), runDir, os.Getpid()); err != nil || len(items) != 0 {
			t.Fatalf("pending after the block: %+v %v, want none", items, err)
		}
		mu.Lock()
		got := append([]ask.Event(nil), lines...)
		mu.Unlock()
		if len(got) != 2 || got[1].Kind != "answer" || got[1].Decision.Approved || got[1].Decision.Reason != ask.ReasonUnavailable ||
			got[1].Decision.By != "cancelled" {
			t.Fatalf("broker lines %+v: want the ask and its answer ask-unavailable by cancelled", got)
		}
		if len(x.k.completed) != 0 {
			t.Fatalf("completed %v: want nothing opened", x.k.completed)
		}
		heldLiveRefusal(t, x.f, sink.all(), liveblock.Rule(liveblock.KindRead, x.vault))
	})
	t.Run("gate-held ask", func(t *testing.T) {
		x := newHeldAskFixture(t)
		var cur atomic.Pointer[liveblock.Set]
		withdrawn := false
		sink := &testSink{}
		l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, openDeputy: x.dep, LiveBlocks: cur.Load,
			Ask: func(ctx context.Context, req ask.Request) (ask.Decision, error) {
				cur.Store(liveBlockOf(liveblock.KindRead, x.target))
				select {
				case <-ctx.Done(): // the broker's own answer to a request its owner took back
					withdrawn = true
					return ask.Decision{AskID: req.AskID, Reason: ask.ReasonUnavailable, By: "cancelled"}, nil
				case <-time.After(5 * time.Second): // the person, still shown the card, answers Allow once
					return ask.Decision{Approved: true, By: "uid:1 pid:2"}, nil
				}
			}})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(l.closeAskScopes)
		x.open(t, l, x.target, unix.O_RDONLY)
		if !withdrawn {
			t.Fatal("the request was never taken back after a read block of its file landed")
		}
		if len(x.dep.opened) != 0 || len(x.k.heldDelivered) != 0 {
			t.Fatalf("deputy opens %v, delivered %q: want nothing opened", x.dep.opened, x.k.heldDelivered)
		}
		heldLiveRefusal(t, x.f, sink.all(), liveblock.Rule(liveblock.KindRead, x.target))
	})
}
