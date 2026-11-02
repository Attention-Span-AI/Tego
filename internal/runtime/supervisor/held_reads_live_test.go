// SPDX-License-Identifier: Apache-2.0

//go:build amd64 || arm64

package supervisor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/attention-span-ai/tego/internal/liveblock"
	"github.com/attention-span-ai/tego/internal/runtime/ask"
	"github.com/attention-span-ai/tego/pkg/spec/agent"
	"github.com/attention-span-ai/tego/pkg/spec/record"
)

// TestHeldReadLiftedFenceNamesTheEntry: a read an Adjustable run's read fence entry reaches, allowed because the entry
// is lifted (no refusal in the live Set), is recorded under the entry's rule, live.fence[read:<value>], not as
// unmatched (ADR 0125 decision 9); a read outside the fence keeps its own rule.
func TestHeldReadLiftedFenceNamesTheEntry(t *testing.T) {
	x, _ := heldReadsFixture(t, agent.RecordFull)
	exports := filepath.Join(x.dir, "exports")
	if err := os.Mkdir(exports, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(exports, "q3.csv"), []byte("revenue"), 0o600); err != nil {
		t.Fatal(err)
	}
	x.pol.Rules.Live = &agent.LiveTable{Mode: agent.LiveAdjustable,
		Entries: []agent.LiveEntry{{Kind: agent.LiveKindRead, Value: exports, Source: agent.LiveSourceDeny}}}
	l, sink, _ := x.loop(t, func(ask.Request) ask.Decision { return ask.Decision{} })
	for _, tc := range []struct{ path, rule string }{
		{filepath.Join(exports, "q3.csv"), "live.fence[read:" + exports + "]"},
		{filepath.Join(x.dir, "src", "a.txt"), ""},
	} {
		before := len(sink.all())
		x.openAs(t, l, tc.path, unix.O_RDONLY, 0)
		evs := sink.all()[before:]
		if len(evs) != 1 || evs[0].Verdict != record.VerdictAllow {
			t.Fatalf("%s: lines %+v, want one allow", tc.path, evs)
		}
		if tc.rule != "" && evs[0].Rule != tc.rule || tc.rule == "" && strings.HasPrefix(evs[0].Rule, "live.") {
			t.Fatalf("%s: rule %q, want %q", tc.path, evs[0].Rule, tc.rule)
		}
	}
}

// TestHeldReadLiveRefusalOnThePinnedObject is ADR 0125 decision 2's read fence entry, and a live read block, held to
// the object the deputy opened: the copied name resolves to an allowed file, so the name check lets the open on, but
// the deputy's walk reaches a file beneath the refused entry (a sibling swapped the name between the two), and the
// open is refused read-denied under the entry's rule. The same open of an allowed object is delivered.
func TestHeldReadLiveRefusalOnThePinnedObject(t *testing.T) {
	for _, tc := range []struct {
		name  string
		entry func(dir string) liveblock.Entry
		rule  func(dir string) string
	}{
		{"a read fence entry not lifted",
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindRead, Value: dir, By: "contract", At: time.Now(), Fence: true}
			},
			func(dir string) string { return "live.fence[read:" + dir + "]" }},
		{"a live read block",
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindRead, Value: dir, By: "uid:1 pid:2 cli", At: time.Now()}
			},
			func(dir string) string { return "live.block[read:" + dir + "]" }},
		{"a live path block",
			func(dir string) liveblock.Entry {
				return liveblock.Entry{Kind: liveblock.KindPath, Value: dir, By: "uid:1 pid:2 cli", At: time.Now()}
			},
			func(dir string) string { return "live.block[path:" + dir + "]" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			x, _ := heldReadsFixture(t, agent.RecordSummary)
			exports := filepath.Join(x.dir, "exports")
			secret := filepath.Join(exports, "q3.csv")
			if err := os.Mkdir(exports, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(secret, []byte("revenue"), 0o600); err != nil {
				t.Fatal(err)
			}
			set := liveblock.CompileEntries([]liveblock.Entry{tc.entry(exports)}, 1, liveblock.Resolved{})
			sink := &testSink{}
			l, err := New(testListener(), x.pol, sink, Options{kernel: x.k, openDeputy: x.dep,
				LiveBlocks: func() *liveblock.Set { return set },
				Ask:        func(context.Context, ask.Request) (ask.Decision, error) { return ask.Decision{}, nil }})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(l.closeAskScopes)
			benign := filepath.Join(x.dir, "src", "a.txt")

			// The name the loop copies is the benign file; the deputy's walk lands on the secret.
			x.dep.swapTo = secret
			before, delivered := len(sink.all()), len(x.k.heldDelivered)
			x.openAs(t, l, benign, unix.O_RDONLY, 0)
			res, _ := x.f.lastResp()
			evs := sink.all()[before:]
			if x.dep.pins == 0 {
				t.Fatal("the open was not held")
			}
			if len(x.k.heldDelivered) != delivered || res.Error != -int32(unix.EACCES) {
				t.Fatalf("answer %+v, delivered %d: want EACCES, nothing delivered", res, len(x.k.heldDelivered)-delivered)
			}
			if len(evs) != 1 || evs[0].Verdict != record.VerdictRefused || evs[0].Reason != record.ReasonReadDenied ||
				evs[0].Rule != tc.rule(exports) {
				t.Fatalf("lines %+v, want one read-denied refusal by %s", evs, tc.rule(exports))
			}

			// The same open whose walk reaches the benign file is delivered.
			x.dep.swapTo = ""
			delivered = len(x.k.heldDelivered)
			x.openAs(t, l, benign, unix.O_RDONLY, 0)
			if len(x.k.heldDelivered) != delivered+1 {
				t.Fatal("an open of an allowed object was not delivered")
			}
		})
	}
}
